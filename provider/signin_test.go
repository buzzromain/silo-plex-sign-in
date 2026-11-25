package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// fakePlex serves the PIN, user and resources endpoints. The PIN is
// approved once approved is set; status codes can be forced.
type fakePlex struct {
	approved   atomic.Bool
	userJSON   string
	userStatus atomic.Int32
	pinStatus  atomic.Int32
	resources  string
}

func (f *fakePlex) server(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/pins":
			_, _ = w.Write([]byte(`{"id":9,"code":"PINCODE9"}`))
		case "/api/v2/pins/9":
			if st := f.pinStatus.Load(); st != 0 {
				w.WriteHeader(int(st))
				return
			}
			token := ""
			if f.approved.Load() {
				token = "secret-plex-token"
			}
			_, _ = w.Write([]byte(`{"id":9,"code":"PINCODE9","authToken":"` + token + `"}`))
		case "/api/v2/user":
			if st := f.userStatus.Load(); st != 0 {
				w.WriteHeader(int(st))
				return
			}
			_, _ = w.Write([]byte(f.userJSON))
		case "/api/v2/resources":
			_, _ = w.Write([]byte(f.resources))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

const fullUser = `{"uuid":"u-1","username":"alex","title":"Alex M.","email":"alex@example.test","confirmed":true,"thumb":"https://plex.tv/users/abc123/avatar"}`

// openFlow runs InitAuthorize and opens the start page; it returns the
// flow id and claim.
func openFlow(t *testing.T, p *Provider) (string, string) {
	t.Helper()
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{
		State: signedSiloState(t, "install-42"), RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-42/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	flowID := strings.SplitN(strings.SplitN(started.GetAuthorizeUrl(), "flow=", 2)[1], "&", 2)[0]
	page, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, map[string]any{"flow": flowID})})
	if err != nil {
		t.Fatal(err)
	}
	return flowID, claimFromPage(t, page)
}

func poll(t *testing.T, p *Provider, flowID, claim string) (int, statusResponse, string) {
	t.Helper()
	resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {claim}}.Encode())})
	if err != nil {
		t.Fatal(err)
	}
	var body statusResponse
	if err := json.Unmarshal(resp.GetBody(), &body); err != nil {
		t.Fatalf("status body is not JSON: %s", resp.GetBody())
	}
	return int(resp.GetStatusCode()), body, string(resp.GetBody())
}

func assertNoSecrets(t *testing.T, raw, claim string) {
	t.Helper()
	for _, secret := range []string{"secret-plex-token", "PINCODE9", "alex@example.test", "u-1", claim} {
		if secret != "" && strings.Contains(raw, secret) {
			t.Fatalf("status response leaks %q: %s", secret, raw)
		}
	}
}

func TestStatusStates(t *testing.T) {
	plex := &fakePlex{userJSON: fullUser, resources: `[{"clientIdentifier":"srv","provides":"server"}]`}
	tests := []struct {
		name     string
		settings Settings
		server   string
		setup    func()
		want     statusResponse
	}{
		{"waiting", Settings{Manual: []ManualEntry{{Input: "alex"}}}, "", func() {}, statusResponse{Status: statusWaiting}},
		{"plex down while waiting", Settings{}, "", func() { plex.pinStatus.Store(502) }, statusResponse{Status: statusWaiting, Code: ReasonPlexUnavailable}},
		{"plex down while checking", Settings{}, "", func() { plex.approved.Store(true); plex.userStatus.Store(502) }, statusResponse{Status: statusChecking, Code: ReasonPlexUnavailable}},
		{"complete by server", Settings{}, "srv", func() { plex.approved.Store(true) }, statusResponse{Status: statusComplete}},
		{"complete by list", Settings{Manual: []ManualEntry{{Input: "alex"}}}, "", func() { plex.approved.Store(true) }, statusResponse{Status: statusComplete}},
		{"not allowed", Settings{Manual: []ManualEntry{{Input: "sam"}}}, "", func() { plex.approved.Store(true) }, statusResponse{Status: statusFailed, Code: ReasonNotAllowed}},
		{"not configured", Settings{}, "", func() { plex.approved.Store(true) }, statusResponse{Status: statusFailed, Code: ReasonNotConfigured}},
		{"rejected token", Settings{}, "", func() { plex.approved.Store(true); plex.userStatus.Store(401) }, statusResponse{Status: statusFailed, Code: ReasonRejected}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plex.approved.Store(false)
			plex.userStatus.Store(0)
			plex.pinStatus.Store(0)
			p := testProvider(plex.server(t))
			store := withAccess(t, p, tt.settings, tt.server)
			flowID, claim := openFlow(t, p)
			tt.setup()
			code, body, raw := poll(t, p, flowID, claim)
			if code != http.StatusOK || body.Status != tt.want.Status || body.Code != tt.want.Code || body.ExpiresAt == nil {
				t.Fatalf("code=%d body=%s", code, raw)
			}
			assertNoSecrets(t, raw, claim)
			final := body.Status == statusComplete || body.Status == statusFailed
			if final != (body.Ref != "") {
				t.Fatalf("ref must be set exactly on final states: %s", raw)
			}
			if body.Status == statusComplete && (!strings.HasPrefix(body.Redirect, "https://media.example.test/") || body.Account == nil || body.Account.Title != "Alex M.") {
				t.Fatalf("complete body = %s", raw)
			}
			if body.Code == ReasonNotAllowed && (body.Account == nil || body.Account.Username != "alex") {
				t.Fatalf("refusal must show the Plex account: %s", raw)
			}
			if final {
				entries, _ := p.loadActivity(context.Background())
				if len(entries) != 1 || entries[0].Ref != body.Ref {
					t.Fatalf("activity = %+v", entries)
				}
				if data := string(store.values[activityKey]); strings.Contains(data, "secret-plex-token") || strings.Contains(data, "example.test") || strings.Contains(data, claim) {
					t.Fatalf("activity leaks a secret: %s", data)
				}
				// A second poll answers the same decision without a new entry.
				_, again, _ := poll(t, p, flowID, claim)
				if again.Ref != body.Ref || again.Status != body.Status {
					t.Fatalf("second poll changed the answer: %+v", again)
				}
				if entries, _ := p.loadActivity(context.Background()); len(entries) != 1 {
					t.Fatalf("one entry per decision, got %d", len(entries))
				}
			}
		})
	}
}

func TestStatusIneligibleAccounts(t *testing.T) {
	for _, userJSON := range []string{
		`{"uuid":"","username":"nouuid"}`,
		`{"uuid":"u-2","username":"kid","restricted":true}`,
		`{"uuid":"u-3","username":"guest","guest":true}`,
	} {
		plex := &fakePlex{userJSON: userJSON, resources: `[]`}
		plex.approved.Store(true)
		p := testProvider(plex.server(t))
		withAccess(t, p, Settings{}, "srv")
		flowID, claim := openFlow(t, p)
		if _, body, raw := poll(t, p, flowID, claim); body.Status != statusFailed || body.Code != ReasonIneligible {
			t.Fatalf("%s: %s", userJSON, raw)
		}
	}
}

func TestStatusUnknownExpiredAndClaimed(t *testing.T) {
	plex := &fakePlex{userJSON: fullUser}
	p := testProvider(plex.server(t))
	flowID, claim := openFlow(t, p)

	if code, body, _ := poll(t, p, "nope", claim); code != http.StatusNotFound || body.Status != statusFailed || body.Code != ReasonExpired {
		t.Fatalf("unknown flow: %d %+v", code, body)
	}
	if code, body, _ := poll(t, p, flowID, "wrong"); code != http.StatusForbidden || body.Code != ReasonClaimed {
		t.Fatalf("wrong claim: %d %+v", code, body)
	}
	if code, body, _ := poll(t, p, flowID, ""); code != http.StatusForbidden || body.Code != ReasonClaimed {
		t.Fatalf("no claim: %d %+v", code, body)
	}
	p.mu.Lock()
	p.flows[flowID].expiresAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if _, body, _ := poll(t, p, flowID, claim); body.Status != statusFailed || body.Code != ReasonExpired {
		t.Fatalf("expired: %+v", body)
	}
}

func TestRefusedFlowCannotBeExchanged(t *testing.T) {
	plex := &fakePlex{userJSON: fullUser}
	plex.approved.Store(true)
	p := testProvider(plex.server(t))
	withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "sam"}}}, "")
	flowID, claim := openFlow(t, p)
	poll(t, p, flowID, claim)
	state := signedSiloState(t, "install-42")
	resp, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: flowID, State: state, RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-42/callback"})
	if err != nil || resp.GetExternalSubject() != "" || resp.GetDenial() == pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
		t.Fatalf("refused flow exchanged: %v %v", resp, err)
	}
}

func TestFlowErrorsHaveActivityReferences(t *testing.T) {
	p := testProvider((&fakePlex{userJSON: fullUser}).server(t))
	flowID, _ := openFlow(t, p)
	_, wrong, _ := poll(t, p, flowID, "wrong")
	_, expired, _ := poll(t, p, "unknown", "unknown")
	activity, err := p.loadActivity(context.Background())
	if err != nil || len(activity) != 2 || wrong.Ref == "" || expired.Ref == "" || activity[0].Ref != expired.Ref || activity[1].Ref != wrong.Ref || wrong.Account != nil || expired.Account != nil {
		t.Fatalf("flow failures do not link to activity: %v %#v", err, activity)
	}
}
