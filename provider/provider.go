package provider

// Provider type and the Silo auth_provider.v1 entry points: sign-in start,
// code exchange, connection test and account re-checks.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	plexAPI        = "https://plex.tv"
	plexClientsAPI = "https://clients.plex.tv"
	clientID       = "silo-plugin-auth-plex"
	productName    = "Plex Sign-In"
	capabilityID   = "plex"
	flowLifetime   = 10 * time.Minute
	maxFlows       = 1000 // pending sign-in flows; bounds memory and plex.tv PIN requests

	// Version is the plugin version: manifest, X-Plex-Version header and build agree.
	Version = "0.1.0"
)

// Provider implements the Silo auth_provider.v1 and http_routes.v1
// capabilities. Pending sign-in and connect flows live in memory and are
// guarded by mu; settings and activity are kept in Silo instance state.
type Provider struct {
	pluginv1.UnimplementedAuthProviderServer
	pluginv1.UnimplementedAuthProviderChecksServer
	pluginv1.UnimplementedHttpRoutesServer

	httpClient *http.Client
	apiBaseURL string
	// resourceHosts lists the Plex hosts tried for the resource lookup, in
	// order. Production starts with plex.tv; tests replace the list.
	resourceHosts  []string
	mu             sync.Mutex
	flows          map[string]*pendingFlow
	pendingCreates int
	finders        map[string]*finderFlow
	state          stateStore
	formSecret     string
}

// pendingFlow is one person's sign-in, from InitAuthorize until Silo exchanges
// its code or it expires after flowLifetime.
type pendingFlow struct {
	pinID       int64
	pinCode     string
	state       string
	redirectURI string
	contentBase string
	expiresAt   time.Time
	browserHash []byte
	claimed     bool
	complete    bool
	failed      ReasonCode // final refusal, kept until expiry so a reload shows it
	ref         string     // activity reference of the final decision
	user        plexUser
	token       string
	exchange    string // one-time secret for Silo's callback, set when allowed
}

// authResult is an approved Plex account and its token.
type authResult struct {
	user  plexUser
	token string
}

// New returns a Provider that talks to plex.tv. Its HTTP client has a timeout
// and never follows redirects.
func New() *Provider {
	return &Provider{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		apiBaseURL:    plexAPI,
		resourceHosts: []string{plexAPI, plexClientsAPI},
		flows:         make(map[string]*pendingFlow),
	}
}

// Configure receives the global config. The branding keys are fixed by the
// manifest and the plugin has no other global settings, so entries are
// ignored.
func (p *Provider) Configure(context.Context, []*pluginv1.ConfigEntry) error {
	return nil
}

// Authenticate refuses password sign-in: Plex accounts sign in only through
// the OAuth flow.
func (p *Provider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return denied(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "Use the Plex sign-in button to authenticate."), nil
}

// InitAuthorize starts a sign-in. It validates Silo's state and HTTPS callback,
// creates a Plex PIN and returns the URL of the plugin's start page, which
// sends the person to Plex.
func (p *Provider) InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	if req == nil || req.GetState() == "" || req.GetRedirectUri() == "" {
		return nil, errors.New("Silo authorization state or callback URL is missing")
	}
	callback, err := url.Parse(req.GetRedirectUri())
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil || callback.RawQuery != "" || callback.Fragment != "" {
		return nil, errors.New("Silo callback URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	installID, err := installIDFromState(req.GetState())
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.pruneFlowsLocked(time.Now())
	full := p.flowLimitReachedLocked()
	if !full {
		p.pendingCreates++ // reserve capacity before the network call
	}
	p.mu.Unlock()
	if full {
		return nil, errors.New("too many Plex sign-in attempts in progress, try again shortly")
	}
	defer func() {
		p.mu.Lock()
		p.pendingCreates--
		p.mu.Unlock()
	}()
	pin, err := p.createPIN(ctx)
	if err != nil {
		return nil, err
	}
	flowID, err := randomID()
	if err != nil {
		return nil, errors.New("could not create a Plex sign-in session")
	}
	expiresAt := time.Now().Add(flowLifetime)

	// Silo's OAuth callback uses the install ID for the public plugin-content route.
	start := *callback
	start.Path = strings.TrimSuffix(start.Path, "/")
	if i := strings.LastIndex(start.Path, "/auth/oauth/"); i >= 0 {
		start.Path = start.Path[:i]
	}
	contentBase := start.Scheme + "://" + start.Host + "/api/v2/plugin-content/plugins/" + url.PathEscape(installID)
	start.Path += "/plugin-content/plugins/" + url.PathEscape(installID) + "/plex/start"
	flow := &pendingFlow{pinID: pin.ID, pinCode: pin.Code, state: req.GetState(), redirectURI: req.GetRedirectUri(), contentBase: contentBase, expiresAt: expiresAt}
	p.mu.Lock()
	p.pruneFlowsLocked(time.Now())
	p.flows[flowID] = flow
	p.mu.Unlock()
	start.RawQuery = url.Values{"flow": {flowID}}.Encode()
	start.Fragment = ""
	return &pluginv1.InitAuthorizeResponse{AuthorizeUrl: start.String()}, nil
}

// ExchangeCode completes a sign-in when Silo's callback presents the code.
// The code is "<flow ID>.<exchange secret>": the flow ID is public (it is in
// the start link), but the secret is only handed to the browser that claimed
// the flow, once the plugin allowed the account. The code works once, and
// only with the original state and callback.
func (p *Provider) ExchangeCode(_ context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	invalid := denied(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "Plex sign-in session is invalid or expired.")
	if req == nil || req.GetCode() == "" || req.GetState() == "" {
		return invalid, nil
	}
	flowID, secret, _ := strings.Cut(req.GetCode(), ".")
	p.mu.Lock()
	defer p.mu.Unlock()
	flow := p.flows[flowID]
	if flow == nil {
		return invalid, nil
	}
	if secret == "" || !flow.complete || flow.exchange == "" || subtle.ConstantTimeCompare([]byte(flow.exchange), []byte(secret)) != 1 {
		// A wrong or missing secret never reveals or consumes the flow, so a
		// guessed flow ID cannot block the real sign-in.
		return invalid, nil
	}
	if subtle.ConstantTimeCompare([]byte(flow.state), []byte(req.GetState())) != 1 || flow.redirectURI != req.GetRedirectUri() || time.Now().After(flow.expiresAt) {
		delete(p.flows, flowID)
		return invalid, nil
	}
	if installID, err := installIDFromState(flow.state); err != nil || installID == "" {
		delete(p.flows, flowID)
		return invalid, nil
	}
	response := identity(&authResult{user: flow.user, token: flow.token})
	delete(p.flows, flowID)
	return response, nil
}

// TestConnection reports whether Plex is reachable and whether sign-in is
// ready, with the same rules as the admin page badge. It reveals no secret.
func (p *Provider) TestConnection(ctx context.Context, _ *pluginv1.AuthTestConnectionRequest) (*pluginv1.AuthTestConnectionResponse, error) {
	var steps []*pluginv1.AuthTestStep
	add := func(id, label string, ok bool, message string) {
		steps = append(steps, &pluginv1.AuthTestStep{Id: id, Label: label, Ok: ok, Message: message})
	}
	if err := p.checkEndpoint(ctx); err != nil {
		add("plex", "Plex sign-in service", false, "Plex is not responding.")
	} else {
		add("plex", "Plex sign-in service", true, "Plex is reachable.")
	}
	settings, connection, err := p.accessState(ctx)
	status := Readiness(settings, connection)
	if err != nil {
		status = Status{State: StateUnavailable}
	}
	label := English.T("admin.title")
	switch status.State {
	case StateReady:
		add("access", label, true, English.T("admin.status.ready"))
	case StateNotSetUp:
		add("access", label, false, English.T("admin.status.not_set_up")+": "+English.T("error.not_configured.text"))
	default:
		add("access", label, false, English.T("admin.status.unavailable")+": "+English.T("admin.notice.error_state"))
	}
	ok := true
	for _, step := range steps {
		ok = ok && step.GetOk()
	}
	return &pluginv1.AuthTestConnectionResponse{Ok: ok, Steps: steps}, nil
}

// CheckAccount re-validates an account with its stored Plex token. Only a
// definitive answer from Plex with a working token revokes access; an
// unusable token or an unreachable Plex never signs anyone out.
func (p *Provider) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	status := func(s pluginv1.CheckAccountStatus) (*pluginv1.CheckAccountResponse, error) {
		return &pluginv1.CheckAccountResponse{Status: s}, nil
	}
	if req == nil || strings.TrimSpace(req.GetExternalSubject()) == "" {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND)
	}
	token := req.GetRefreshState().GetFields()["auth_token"].GetStringValue()
	if token == "" {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	}
	user, err := p.fetchUser(ctx, token)
	if errors.Is(err, errPlexUnauthorized) {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	}
	if err != nil {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	}
	if "plex:"+user.UUID != req.GetExternalSubject() {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	}
	settings, connection, err := p.accessState(ctx)
	if err != nil {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	}
	var resources []plexResource
	if connection.ServerMachineID != "" {
		resources, err = p.fetchResources(ctx, token)
		if errors.Is(err, errPlexUnauthorized) {
			return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
		}
		if err != nil {
			return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		}
	}
	if !Decide(settings, connection.ServerMachineID, connection.OwnerUUID, *user, resources).Allowed {
		return status(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	}
	// An empty token leaves the stored refresh state untouched.
	return &pluginv1.CheckAccountResponse{
		Status:  pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE,
		Account: identity(&authResult{user: *user}),
	}, nil
}

// EndSessionUrl returns no URL: signing out of Silo does not sign out of Plex.
func (p *Provider) EndSessionUrl(context.Context, *pluginv1.AuthEndSessionUrlRequest) (*pluginv1.AuthEndSessionUrlResponse, error) {
	return &pluginv1.AuthEndSessionUrlResponse{}, nil
}

// Handle routes the plugin's HTTP requests: public sign-in pages and assets,
// and the administrator pages.
func parsePublicForm(req *pluginv1.HandleHTTPRequest) (url.Values, int) {
	const maxPublicFormSize = 4 << 10
	if len(req.GetBody()) > maxPublicFormSize {
		return nil, http.StatusRequestEntityTooLarge
	}
	form, err := url.ParseQuery(string(req.GetBody()))
	if err != nil {
		return nil, http.StatusBadRequest
	}
	return form, http.StatusOK
}

// Handle dispatches one HTTP route. The table in routes.go owns the path,
// method, Silo access level and handler of every route.
func (p *Provider) Handle(ctx context.Context, req *pluginv1.HandleHTTPRequest) (*pluginv1.HandleHTTPResponse, error) {
	if req == nil {
		return httpResponse(http.StatusMethodNotAllowed, contentTypeText, "method not allowed"), nil
	}
	return p.dispatch(ctx, req), nil
}

// identity converts a Plex account into the identity sent to Silo. The
// external subject is "plex:" followed by the Plex UUID.
func identity(result *authResult) *pluginv1.AuthenticateResponse {
	username := strings.TrimSpace(result.user.Username)
	displayName := strings.TrimSpace(result.user.Title)
	if displayName == "" {
		displayName = username
	}
	// managed_role stays UNSPECIFIED and groups are not sent: Silo gives a
	// new account the User role and its default group.
	response := &pluginv1.AuthenticateResponse{
		ExternalSubject: "plex:" + result.user.UUID,
		DisplayName:     displayName,
		Username:        username,
		Issuer:          plexAPI,
	}
	if email := strings.TrimSpace(result.user.Email); email != "" {
		response.Email = email
		// Only pass through what Plex says; absent means "did not say", so
		// Silo never auto-matches an account on an unconfirmed email.
		response.EmailVerified = result.user.Confirmed
	}
	response.PictureUrl = safeAvatar(result.user.Thumb)
	if result.token != "" {
		response.RefreshState = tokenState(result.token)
	}
	return response
}

// denied returns a refused authentication with a reason for Silo.
func denied(denial pluginv1.AuthDenial, detail string) *pluginv1.AuthenticateResponse {
	return &pluginv1.AuthenticateResponse{Denial: denial, DenialDetail: detail}
}

// tokenState stores the Plex token as refresh state so CheckAccount can
// re-validate the account later.
func tokenState(token string) *structpb.Struct {
	state, _ := structpb.NewStruct(map[string]any{"auth_token": token})
	return state
}

// encodeJSON marshals value, returning "{}" when it cannot be encoded.
func encodeJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return `{}`
	}
	return string(data)
}

// randomID returns 32 random bytes, URL-safe base64 encoded.
func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// installIDFromState reads the plugin installation ID from Silo's OAuth state.
// The state is signed by Silo; it is only read here, never trusted to
// authorize anything.
func installIDFromState(state string) (string, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("Silo authorization state is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Silo authorization state is invalid")
	}
	var claims struct {
		InstallID string `json:"i"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.InstallID == "" || strings.ContainsAny(claims.InstallID, "/\\") {
		return "", errors.New("Silo installation ID is missing from OAuth state")
	}
	return claims.InstallID, nil
}

// callbackURL returns Silo's OAuth callback with the exchange code and state.
func callbackURL(redirectURI, state, code string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// pruneFlowsLocked drops expired sign-in and connect flows. p.mu must be held.
func (p *Provider) pruneFlowsLocked(now time.Time) {
	for id, flow := range p.finders {
		if now.After(flow.expiresAt) {
			delete(p.finders, id)
		}
	}
	for id, flow := range p.flows {
		if now.After(flow.expiresAt) {
			delete(p.flows, id)
		}
	}
}

// flowLimitReachedLocked reports whether another Plex flow would exceed
// maxFlows. Sign-in and administrator connect flows share the budget, and
// pendingCreates reserves slots for calls already talking to Plex. p.mu must
// be held.
func (p *Provider) flowLimitReachedLocked() bool {
	return len(p.flows)+len(p.finders)+p.pendingCreates >= maxFlows
}
