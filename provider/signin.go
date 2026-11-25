package provider

// Sign-in pages: the public start page, status polling and refusal screens.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// Status API values.
const (
	statusWaiting  = "waiting"
	statusChecking = "checking"
	statusComplete = "complete"
	statusFailed   = "failed"
)

// statusResponse is the stable JSON shape of GET /plex/status. It never
// holds a token, PIN code, claim, email or UUID.
type statusResponse struct {
	Status    string         `json:"status"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Redirect  string         `json:"redirect,omitempty"`
	Code      ReasonCode     `json:"code,omitempty"`
	Ref       string         `json:"ref,omitempty"`
	Account   *statusAccount `json:"account,omitempty"`
}

// statusAccount is the Plex account shown on the sign-in page.
type statusAccount struct {
	Title    string `json:"title,omitempty"`
	Username string `json:"username,omitempty"`
	Thumb    string `json:"thumb,omitempty"`
}

// accountOf returns the public fields shown for a Plex account on the sign-in
// page, or nil when nothing is known about it.
func accountOf(user plexUser) *statusAccount {
	if user.UUID == "" && user.Username == "" && user.Title == "" {
		return nil
	}
	return &statusAccount{Title: publicName(user.Title), Username: publicName(user.Username), Thumb: safeAvatar(user.Thumb)}
}

// statusJSON encodes a sign-in status response.
func statusJSON(httpStatus int, body statusResponse) *pluginv1.HandleHTTPResponse {
	data, err := json.Marshal(body)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, `{"status":"failed"}`)
	}
	return jsonResponse(httpStatus, string(data))
}

// lookupFlow returns a copy of the flow for flowID when claim is the secret
// of the browser that opened it. On failure it returns the reason code and
// HTTP status to answer with.
func (p *Provider) lookupFlow(flowID, claim string) (pendingFlow, ReasonCode, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	flow := p.flows[flowID]
	if flow == nil {
		return pendingFlow{}, ReasonExpired, http.StatusNotFound
	}
	if time.Now().After(flow.expiresAt) {
		flow.token = ""
		if validClaim(flow, claim) {
			return *flow, ReasonExpired, http.StatusOK
		}
		return pendingFlow{}, ReasonExpired, http.StatusOK
	}
	if !validClaim(flow, claim) {
		return pendingFlow{}, ReasonClaimed, http.StatusForbidden
	}
	return *flow, ReasonNone, http.StatusOK
}

// validClaim reports whether claim is the secret of the browser that opened
// the flow. Only its SHA-256 is stored, compared in constant time.
func validClaim(flow *pendingFlow, claim string) bool {
	hash := sha256.Sum256([]byte(claim))
	return claim != "" && flow.claimed && subtle.ConstantTimeCompare(flow.browserHash, hash[:]) == 1
}

// signinFailure gives a flow error its own reference without attaching any
// identity unless the browser presented the owning claim.
func (p *Provider) signinFailure(ctx context.Context, code ReasonCode, user plexUser) statusResponse {
	ref := newRef()
	p.recordActivity(ctx, newActivity(ref, Decision{Reason: code}, user))
	return statusResponse{Status: statusFailed, Code: code, Ref: ref, Account: accountOf(user)}
}

// status answers GET /plex/status: it polls Plex for the PIN and, once Plex
// approves it, decides whether the account may sign in.
func (p *Provider) status(ctx context.Context, flowID, claim string) *pluginv1.HandleHTTPResponse {
	flow, reason, code := p.lookupFlow(flowID, claim)
	if reason != ReasonNone {
		return statusJSON(code, p.signinFailure(ctx, reason, flow.user))
	}
	if flow.complete || flow.failed != ReasonNone {
		return p.answer(flowID, flow)
	}
	expires := flow.expiresAt.UTC()
	waiting := func(status string) *pluginv1.HandleHTTPResponse {
		return statusJSON(http.StatusOK, statusResponse{Status: status, ExpiresAt: &expires})
	}
	unavailable := func(status string) *pluginv1.HandleHTTPResponse {
		return statusJSON(http.StatusOK, statusResponse{Status: status, ExpiresAt: &expires, Code: ReasonPlexUnavailable})
	}

	pin, err := p.pollPINFromPlex(ctx, flow.pinID, flow.pinCode)
	if err != nil {
		logger.Warn("poll Plex PIN", "error", err)
		return unavailable(statusWaiting)
	}
	if pin.AuthToken == "" {
		return waiting(statusWaiting)
	}

	// Plex approved. The decision below is detached from the browser request
	// so a closed tab does not leave a half-made decision behind.
	decideCtx := context.WithoutCancel(ctx)
	user, err := p.fetchUser(decideCtx, pin.AuthToken)
	if errors.Is(err, errPlexUnauthorized) {
		return p.finish(decideCtx, flowID, Decision{Reason: ReasonRejected}, plexUser{}, "")
	}
	if err != nil {
		logger.Warn("fetch Plex account", "error", err)
		return unavailable(statusChecking)
	}
	// Retain the known identity so an expired flow can show it to its browser,
	// even if the access lookup did not finish.
	p.mu.Lock()
	if current := p.flows[flowID]; current != nil && !current.complete && current.failed == ReasonNone {
		current.user = *user
	}
	p.mu.Unlock()
	settings, connection, err := p.accessState(decideCtx)
	if err != nil {
		logger.Warn("load access settings", "error", err)
		return unavailable(statusChecking)
	}
	var resources []plexResource
	if connection.ServerMachineID != "" && user.UUID != "" && !user.Restricted && !user.Guest {
		resources, err = p.fetchResources(decideCtx, pin.AuthToken)
		if errors.Is(err, errPlexUnauthorized) {
			return p.finish(decideCtx, flowID, Decision{Reason: ReasonRejected}, *user, "")
		}
		if err != nil {
			logger.Warn("fetch Plex resources", "error", err)
			return unavailable(statusChecking)
		}
	}
	decision := Decide(settings, connection.ServerMachineID, connection.OwnerUUID, *user, resources)
	if decision.Allowed && decision.Rule == RuleManual {
		p.learnManual(decideCtx, *user)
	}
	return p.finish(decideCtx, flowID, decision, *user, pin.AuthToken)
}

// finish records the final decision for a flow and answers with it. Only an
// allowed decision keeps the Plex token and creates the one-time exchange
// secret, for ExchangeCode.
func (p *Provider) finish(ctx context.Context, flowID string, decision Decision, user plexUser, token string) *pluginv1.HandleHTTPResponse {
	var exchange string
	if decision.Allowed {
		var err error
		if exchange, err = randomID(); err != nil {
			logger.Warn("create exchange secret", "error", err)
			decision = Decision{Reason: ReasonRejected}
		}
	}
	p.mu.Lock()
	flow := p.flows[flowID]
	if flow == nil || time.Now().After(flow.expiresAt) {
		p.mu.Unlock()
		return statusJSON(http.StatusOK, p.signinFailure(ctx, ReasonExpired, user))
	}
	if flow.complete || flow.failed != ReasonNone {
		// Another poll decided first; answer with its result.
		done := *flow
		p.mu.Unlock()
		return p.answer(flowID, done)
	}
	flow.ref = newRef()
	flow.user = user
	if decision.Allowed {
		flow.complete = true
		flow.token = token
		flow.exchange = exchange
	} else {
		flow.failed = decision.Reason
	}
	done := *flow
	p.mu.Unlock()

	p.recordActivity(ctx, newActivity(done.ref, decision, user))
	return p.answer(flowID, done)
}

// answer returns the flow's current status. A completed flow carries the Silo
// callback URL that finishes the sign-in. Callers have already checked that
// the request comes from the browser that claimed the flow.
func (p *Provider) answer(flowID string, flow pendingFlow) *pluginv1.HandleHTTPResponse {
	expires := flow.expiresAt.UTC()
	body := statusResponse{Status: statusFailed, ExpiresAt: &expires, Code: flow.failed, Ref: flow.ref, Account: accountOf(flow.user)}
	if flow.complete {
		body.Status, body.Code = statusComplete, ReasonNone
		body.Redirect = callbackURL(flow.redirectURI, flow.state, flowID+"."+flow.exchange)
	}
	return statusJSON(http.StatusOK, body)
}

// assetsBase is the path from a sign-in or admin page to /assets/. Pages
// live one level below the installation's plugin-content root.
const assetsBase = "../assets/"

// signinError is one error screen: its code and the message keys of its
// actions (03-sign-in-flow.md, Error codes).
type signinError struct {
	Code         ReasonCode
	Primary      string
	Secondary    string
	OtherAccount bool
}

var signinErrors = []signinError{
	{Code: ReasonNotAllowed, Primary: "signin.back", OtherAccount: true},
	{Code: ReasonNotConfigured, Primary: "signin.back"},
	{Code: ReasonIneligible, Primary: "signin.back", OtherAccount: true},
	{Code: ReasonRejected, Primary: "signin.retry", Secondary: "signin.back"},
	{Code: ReasonExpired, Primary: "signin.retry"},
	{Code: ReasonClaimed, Primary: "signin.back"},
}

// signinPage is the data for signin.html.
type signinPage struct {
	Lang         Lang
	T            func(string, ...any) string
	CSP          string
	Assets       string
	Host         string
	Screen       string // start, waiting, success or error
	Code         ReasonCode
	Ref          string
	Account      *statusAccount
	PlexURL      string
	StatusURL    string
	FlowID       string
	StatusToken  string
	ReturnURL    string
	ExpiresAt    string
	AutoContinue bool
	Errors       []signinError
	Script       map[string]string
}

// newSigninPage returns the sign-in page data shared by every screen.
func newSigninPage(lang Lang) signinPage {
	return signinPage{
		Lang:   lang,
		T:      lang.T,
		CSP:    metaContentSecurityPolicy,
		Assets: assetsBase,
		Host:   "Silo",
		Errors: signinErrors,
		Script: map[string]string{
			"expires": lang.T("signin.wait.expires", "%s"),
			"copied":  lang.T("signin.copied"),
			"ref":     lang.T("signin.ref", "%s"),
		},
	}
}

// errorPage records the refusal in the activity log and renders its screen
// with the reference the person can give an administrator.
func (p *Provider) errorPage(ctx context.Context, lang Lang, status int, code ReasonCode, flow pendingFlow) *pluginv1.HandleHTTPResponse {
	page := newSigninPage(lang)
	failure := p.signinFailure(ctx, code, flow.user)
	page.Screen, page.Code, page.Ref, page.Account = "error", code, failure.Ref, failure.Account
	page.Host = signinHost(flow.contentBase)
	return renderPage(status, "signin.html", page)
}

// startPage serves GET /plex/start. The first visit claims the flow for this
// browser and gives it a secret; Plex sends the browser back here with that
// secret (forwardUrl), and the page keeps it in the address bar, so only
// the browser that opened the flow can reopen it.
func (p *Provider) startPage(ctx context.Context, req *pluginv1.HandleHTTPRequest, flowID, claim string) *pluginv1.HandleHTTPResponse {
	lang := English
	p.mu.Lock()
	flow := p.flows[flowID]
	if flow == nil || time.Now().After(flow.expiresAt) {
		var expired pendingFlow
		if flow != nil {
			expired.contentBase = flow.contentBase
			if validClaim(flow, claim) {
				expired.user = flow.user
			}
		}
		p.mu.Unlock()
		return p.errorPage(ctx, lang, http.StatusGone, ReasonExpired, expired)
	}
	secret, returning := claim, false
	if flow.claimed {
		if !validClaim(flow, claim) {
			base := flow.contentBase
			p.mu.Unlock()
			return p.errorPage(ctx, lang, http.StatusConflict, ReasonClaimed, pendingFlow{contentBase: base})
		}
		returning = true
	} else {
		var err error
		if secret, err = randomID(); err != nil {
			p.mu.Unlock()
			logger.Warn("create claim secret", "error", err)
			return p.errorPage(ctx, lang, http.StatusInternalServerError, ReasonRejected, pendingFlow{})
		}
		hash := sha256.Sum256([]byte(secret))
		flow.claimed = true
		flow.browserHash = hash[:]
	}
	snapshot := *flow
	p.mu.Unlock()

	page := newSigninPage(lang)
	if snapshot.failed == ReasonNone {
		query := url.Values{"flow": {flowID}, "claim": {secret}}.Encode()
		page.StatusURL = snapshot.contentBase + "/plex/status"
		page.FlowID = flowID
		page.StatusToken = secret
		page.ReturnURL = snapshot.contentBase + "/plex/start?" + query
		page.PlexURL = plexAuthURL(snapshot.pinCode, page.ReturnURL)
		page.ExpiresAt = snapshot.expiresAt.UTC().Format(time.RFC3339)
	}
	page.Host = signinHost(snapshot.contentBase)
	switch {
	case snapshot.failed != ReasonNone:
		page.Screen, page.Code, page.Ref, page.Account = "error", snapshot.failed, snapshot.ref, accountOf(snapshot.user)
	default:
		page.Screen = "waiting"
		page.AutoContinue = !returning
	}
	return renderPage(http.StatusOK, "signin.html", page)
}

// signinHost returns the Silo host name shown on the sign-in page.
func signinHost(contentBase string) string {
	if u, err := url.Parse(contentBase); err == nil && u.Host != "" {
		return u.Host
	}
	return "Silo"
}

// plexAuthURL is Plex's sign-in page for pinCode. Plex sends the browser
// back to forwardURL when the person approves.
func plexAuthURL(pinCode, forwardURL string) string {
	return "https://app.plex.tv/auth#?" +
		"clientID=" + url.QueryEscape(clientID) +
		"&code=" + url.QueryEscape(pinCode) +
		"&context%5Bdevice%5D%5Bproduct%5D=" + url.QueryEscape(productName) +
		"&forwardUrl=" + url.QueryEscape(forwardURL)
}
