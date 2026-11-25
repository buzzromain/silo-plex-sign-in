package provider

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func startFlow(t *testing.T) (*Provider, string, *pluginv1.HandleHTTPResponse) {
	t.Helper()
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/pins" {
			_, _ = w.Write([]byte(`{"id":9,"code":"CODE"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(plex.Close)
	p := testProvider(plex)
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: signedSiloState(t, "install-7"), RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-7/callback"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(started.GetAuthorizeUrl())
	flowID := parsed.Query().Get("flow")
	page, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, map[string]any{"flow": flowID})})
	if err != nil || page.GetStatusCode() != http.StatusOK {
		t.Fatalf("first visit page=%v err=%v", page, err)
	}
	return p, flowID, page
}

func TestPlexIsToldToSendTheBrowserBackToTheSamePage(t *testing.T) {
	_, flowID, page := startFlow(t)
	body := html.UnescapeString(string(page.GetBody()))
	claim := claimFromPage(t, page)

	i := strings.Index(body, "forwardUrl=")
	if i < 0 {
		t.Fatalf("Plex link has no forwardUrl, so mobile webviews cannot come back:\n%s", body)
	}
	rest := body[i+len("forwardUrl="):]
	forward, err := url.QueryUnescape(rest[:strings.IndexAny(rest, `"&`)])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(forward)
	if err != nil || parsed.Path != "/api/v2/plugin-content/plugins/install-7/plex/start" || parsed.Query().Get("flow") != flowID || parsed.Query().Get("claim") != claim {
		t.Fatalf("forwardUrl must return the claiming browser to its flow, got %q", forward)
	}
	if !strings.Contains(body, `data-status-token="`+claim+`"`) || !strings.Contains(body, `data-status-url="https://media.example.test/api/v2/plugin-content/plugins/install-7/plex/status"`) {
		t.Fatal("the status POST token must be sent in the request body, not its URL")
	}
	if !strings.Contains(body, `data-auto-continue="true"`) || !strings.Contains(body, `data-plex-url="https://app.plex.tv/auth`) {
		t.Fatal("first visit must automatically continue to Plex in the same window")
	}
	if !strings.Contains(body, "media.example.test") {
		t.Fatal("waiting page must show the destination Silo host")
	}
}

func TestReturningFromPlexReopensThePageForTheSameBrowser(t *testing.T) {
	p, flowID, first := startFlow(t)
	claim := claimFromPage(t, first)
	back, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, map[string]any{"flow": flowID, "claim": claim})})
	if err != nil || back.GetStatusCode() != http.StatusOK {
		t.Fatalf("returning browser must get the page again, got %v err=%v", back, err)
	}
	body := html.UnescapeString(string(back.GetBody()))
	if !strings.Contains(body, `data-screen="waiting"`) {
		t.Fatal("returning page should go straight to waiting/polling")
	}
	if strings.Contains(body, `data-auto-continue="true"`) {
		t.Fatal("a returning browser must not be redirected to Plex again")
	}
	if claimFromPage(t, back) != claim {
		t.Fatal("the browser secret must stay stable across visits")
	}
}

func TestOtherBrowsersCannotReopenAClaimedFlow(t *testing.T) {
	p, flowID, _ := startFlow(t)
	for name, query := range map[string]map[string]any{
		"no claim":    {"flow": flowID},
		"wrong claim": {"flow": flowID, "claim": "guess"},
	} {
		resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, query)})
		if err != nil || resp.GetStatusCode() != http.StatusConflict {
			t.Errorf("%s: want 409, got %v err=%v", name, resp.GetStatusCode(), err)
		}
		if strings.Contains(string(resp.GetBody()), "plex_sso") || strings.Contains(string(resp.GetBody()), "claim=") {
			t.Errorf("%s: refusal must not leak the secret", name)
		}
	}
}
