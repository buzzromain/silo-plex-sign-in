package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPlexPINAuthorizationReturnsStableIdentityToSilo(t *testing.T) {
	var approved atomic.Bool
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/pins":
			if r.Method != http.MethodPost {
				t.Errorf("PIN create method = %s", r.Method)
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("strong") != "true" {
				t.Errorf("PIN create form invalid: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":77,"code":"ABCD"}`))
		case "/api/v2/pins/77":
			if r.URL.Query().Get("code") != "ABCD" {
				t.Errorf("PIN poll missing code")
			}
			w.Header().Set("Content-Type", "application/json")
			if approved.Load() {
				_, _ = w.Write([]byte(`{"id":77,"code":"ABCD","authToken":"plex-account-token"}`))
			} else {
				_, _ = w.Write([]byte(`{"id":77,"code":"ABCD","authToken":""}`))
			}
		case "/api/v2/user":
			if r.Header.Get("X-Plex-Token") != "plex-account-token" {
				t.Errorf("Plex token missing on user lookup")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uuid":"plex-uuid-1","username":"alex"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer plex.Close()

	p := testProvider(plex)
	state := signedSiloState(t, "install-42")
	redirect := "https://media.example.test/api/v2/auth/oauth/install-42/callback"
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: state, RedirectUri: redirect, Linking: true})
	if err != nil {
		t.Fatal(err)
	}
	startURL, err := url.Parse(started.GetAuthorizeUrl())
	if err != nil {
		t.Fatal(err)
	}
	flowID := startURL.Query().Get("flow")
	if flowID == "" || !strings.Contains(startURL.Path, "/plugin-content/plugins/install-42/plex/start") {
		t.Fatalf("unexpected authorize URL: %s", started.GetAuthorizeUrl())
	}

	page, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, map[string]any{"flow": flowID})})
	if err != nil || page.GetStatusCode() != http.StatusOK || !strings.Contains(string(page.GetBody()), "https://app.plex.tv/auth#?clientID=") {
		t.Fatalf("page=%v err=%v", page, err)
	}
	claim := claimFromPage(t, page)
	statusRequest := func() *pluginv1.HandleHTTPRequest {
		return &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {claim}}.Encode())}
	}
	waiting, err := p.Handle(context.Background(), statusRequest())
	if err != nil || !strings.Contains(string(waiting.GetBody()), `"status":"waiting"`) {
		t.Fatalf("waiting=%v err=%v", waiting, err)
	}

	approved.Store(true)
	_, err = p.Handle(context.Background(), statusRequest())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := p.Handle(context.Background(), statusRequest())
	if err != nil || !strings.Contains(string(completed.GetBody()), `"status":"complete"`) {
		t.Fatalf("completed=%v err=%v", completed, err)
	}
	var status struct {
		CallbackURL string `json:"redirect"`
	}
	if err := json.Unmarshal(completed.GetBody(), &status); err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(status.CallbackURL)
	code := callback.Query().Get("code")
	if err != nil || callback.Query().Get("state") != state || !strings.HasPrefix(code, flowID+".") || len(code) <= len(flowID)+1 {
		t.Fatalf("invalid callback: %s", status.CallbackURL)
	}

	// The flow ID is public (it is in the start link); on its own, or with a
	// wrong secret, it must not complete the sign-in nor consume the flow.
	for _, guess := range []string{flowID, flowID + ".", flowID + ".wrong"} {
		forged, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: guess, State: state, RedirectUri: redirect})
		if err != nil || forged.GetExternalSubject() != "" || forged.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS {
			t.Fatalf("code %q without the exchange secret was accepted: %v err=%v", guess, forged, err)
		}
	}

	identity, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: code, State: state, RedirectUri: redirect})
	if err != nil || identity.GetExternalSubject() != "plex:plex-uuid-1" || identity.GetUsername() != "alex" {
		t.Fatalf("identity=%v err=%v", identity, err)
	}
	if token := identity.GetRefreshState().GetFields()["auth_token"].GetStringValue(); token != "plex-account-token" {
		t.Fatalf("refresh token=%q", token)
	}
	replayed, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: code, State: state, RedirectUri: redirect})
	if err != nil || replayed.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS {
		t.Fatalf("callback code was not single use: response=%v err=%v", replayed, err)
	}
}

func TestPlexStatusRequiresClaimingBrowserCookie(t *testing.T) {
	var approved atomic.Bool
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/pins":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":77,"code":"ABCD"}`))
		case "/api/v2/pins/77":
			w.Header().Set("Content-Type", "application/json")
			if approved.Load() {
				_, _ = w.Write([]byte(`{"id":77,"code":"ABCD","authToken":"token"}`))
			} else {
				_, _ = w.Write([]byte(`{"id":77,"code":"ABCD","authToken":""}`))
			}
		case "/api/v2/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uuid":"plex-uuid","username":"alex"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer plex.Close()
	p := testProvider(plex)
	state := signedSiloState(t, "install-42")
	redirect := "https://media.example.test/api/v2/auth/oauth/install-42/callback"
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: state, RedirectUri: redirect})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(started.GetAuthorizeUrl())
	if err != nil {
		t.Fatal(err)
	}
	flowID := parsed.Query().Get("flow")
	query := mustStruct(t, map[string]any{"flow": flowID})

	withoutClaim, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}}.Encode())})
	if err != nil || withoutClaim.GetStatusCode() != http.StatusForbidden {
		t.Fatalf("unclaimed poll response=%v err=%v", withoutClaim, err)
	}
	page, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: query})
	if err != nil || page.GetStatusCode() != http.StatusOK {
		t.Fatalf("start page=%v err=%v", page, err)
	}
	claim := claimFromPage(t, page)
	if _, ok := page.GetHeaders()["Set-Cookie"]; ok {
		t.Fatal("plugin routes cannot set cookies through Silo; claim must not rely on Set-Cookie")
	}
	stolenBrowser, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {"wrong-secret"}}.Encode())})
	if err != nil || stolenBrowser.GetStatusCode() != http.StatusForbidden {
		t.Fatalf("wrong claim poll response=%v err=%v", stolenBrowser, err)
	}
	approved.Store(true)
	request := func() *pluginv1.HandleHTTPRequest {
		return &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {claim}}.Encode())}
	}
	_, err = p.Handle(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := p.Handle(context.Background(), request())
	if err != nil || !strings.Contains(string(completed.GetBody()), `"status":"complete"`) {
		t.Fatalf("claiming browser did not complete authorization: response=%v err=%v", completed, err)
	}
	thirdParty, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}}.Encode())})
	if err != nil || thirdParty.GetStatusCode() != http.StatusForbidden || strings.Contains(string(thirdParty.GetBody()), "redirect") {
		t.Fatalf("unbound browser received callback: response=%v err=%v", thirdParty, err)
	}
}

func TestPlexCallbackRejectsWrongStateRedirectAndExpiry(t *testing.T) {
	p := New()
	state := signedSiloState(t, "install-1")
	redirect := "https://media.example.test/callback"
	p.flows["valid"] = &pendingFlow{state: state, redirectURI: redirect, expiresAt: time.Now().Add(flowLifetime), complete: true, user: plexUser{UUID: "u1"}, token: "secret", exchange: "x"}
	p.flows["expired"] = &pendingFlow{state: state, redirectURI: redirect, expiresAt: time.Now().Add(-time.Second), complete: true, exchange: "x"}
	for _, req := range []*pluginv1.ExchangeCodeRequest{
		{Code: "valid.x", State: "wrong", RedirectUri: redirect},
		{Code: "valid.x", State: state, RedirectUri: "https://attacker.example/callback"},
		{Code: "expired.x", State: state, RedirectUri: redirect},
	} {
		response, err := p.ExchangeCode(context.Background(), req)
		if err != nil || response.GetExternalSubject() != "" || response.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS {
			t.Fatalf("response=%v err=%v", response, err)
		}
	}
}

func TestPlexAuthorizeRejectsUntrustedRedirectURI(t *testing.T) {
	p := New()
	_, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: signedSiloState(t, "install-1"), RedirectUri: "http://attacker.example/callback"})
	if err == nil {
		t.Fatal("expected non-HTTPS redirect to be rejected")
	}
}

func TestPasswordSignInIsDisabled(t *testing.T) {
	p := New()
	response, err := p.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: "user", Password: "password"})
	if err != nil || response.GetExternalSubject() != "" || response.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE {
		t.Fatalf("response=%v err=%v", response, err)
	}
}

func signedSiloState(t *testing.T, installID string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"i": installID})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(payload) + ".test-signature"
}

func mustStruct(t *testing.T, values map[string]any) *structpb.Struct {
	t.Helper()
	result, err := structpb.NewStruct(values)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testProvider(server *httptest.Server) *Provider {
	p := New()
	store := newFakeStore()
	store.values[settingsKey], _ = json.Marshal(Settings{Version: settingsVersion, Manual: []ManualEntry{{Input: "alex"}}})
	p.state = store
	p.apiBaseURL = server.URL
	p.httpClient = server.Client()
	p.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return p
}

// withAccess replaces p's state with the given settings and server.
func withAccess(t *testing.T, p *Provider, settings Settings, serverID string) *fakeStore {
	t.Helper()
	store := newFakeStore()
	settings.Version = settingsVersion
	store.put(t, settingsKey, settings)
	if serverID != "" {
		store.put(t, connectionKey, plexConnection{Version: 1, ServerMachineID: serverID})
	}
	p.state = store
	return store
}

// claimFromPage extracts the browser claim from the POST-only status token.
// The claim is not put in the status endpoint URL.
func claimFromPage(t *testing.T, page *pluginv1.HandleHTTPResponse) string {
	t.Helper()
	body := html.UnescapeString(string(page.GetBody()))
	_, rest, ok := strings.Cut(body, `data-status-token="`)
	if !ok {
		t.Fatalf("start page has no status token: %s", body)
	}
	claim, _, _ := strings.Cut(rest, `"`)
	if claim == "" {
		t.Fatalf("start page has an empty status token: %s", body)
	}
	return claim
}
