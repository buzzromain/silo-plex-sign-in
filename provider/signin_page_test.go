package provider

import (
	"context"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

var (
	inlineHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	inlineStyle   = regexp.MustCompile(`(?i)<style|\sstyle\s*=`)
	inlineScript  = regexp.MustCompile(`(?i)<script(?:\s+[^>]*)?>[^<]+</script>`)
	external      = regexp.MustCompile(`(?i)<(script|link)[^>]+(src|href)="(https?:)?//[^"]*"`)
	externalImg   = regexp.MustCompile(`(?i)<img[^>]+src="(https?:)?//[^"]*"`)
	plexImg       = regexp.MustCompile(`src="https://([a-z0-9-]+\.)?plex\.tv/`)
)

// assertCleanHTML checks the rules every page follows: no inline handlers,
// styles or scripts, and no external script, style or font.
func assertCleanHTML(t *testing.T, body string) {
	t.Helper()
	if m := inlineHandler.FindString(body); m != "" {
		t.Errorf("inline handler %q", m)
	}
	if m := inlineStyle.FindString(body); m != "" {
		t.Errorf("inline style %q", m)
	}
	for _, m := range inlineScript.FindAllString(body, -1) {
		if !strings.Contains(m, `type="application/json"`) {
			t.Errorf("inline script %q", m)
		}
	}
	if m := external.FindString(body); m != "" {
		t.Errorf("external script or stylesheet %q", m)
	}
	for _, m := range externalImg.FindAllString(body, -1) {
		if !plexImg.MatchString(m) {
			t.Errorf("image from outside plex.tv %q", m)
		}
	}
}

func startPageRequest(t *testing.T, p *Provider, flowID, claim, lang string) *pluginv1.HandleHTTPResponse {
	t.Helper()
	query := map[string]any{"flow": flowID}
	if claim != "" {
		query["claim"] = claim
	}
	resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{
		Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, query),
		Headers: map[string]string{"Accept-Language": lang},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestStartPageIsEnglishAndNamesHost(t *testing.T) {
	for _, tt := range []struct {
		header, lang, title, destination string
	}{
		{"", "en", "Sign in with Plex", "Signing in to media.example.test"},
		// The interface is English only, whatever the browser prefers.
		{"de-DE,fr;q=0.8", "en", "Sign in with Plex", "Signing in to media.example.test"},
	} {
		p, flowID, _ := startFlow(t)
		p.mu.Lock()
		p.flows[flowID].claimed = false
		p.mu.Unlock()
		resp := startPageRequest(t, p, flowID, "", tt.header)
		body := html.UnescapeString(string(resp.GetBody()))
		if !strings.Contains(body, `data-screen="waiting"`) || !strings.Contains(body, `data-auto-continue="true"`) || !strings.Contains(body, "app.plex.tv/auth") {
			t.Fatalf("first visit must automatically continue to Plex: %s", body)
		}
		if resp.GetStatusCode() != http.StatusOK || !strings.Contains(body, `<html lang="`+tt.lang+`">`) ||
			!strings.Contains(body, tt.destination) {
			t.Fatalf("%s page must name provider and host:\n%s", tt.lang, body)
		}
		if resp.GetHeaders()["Content-Type"] != contentTypeHTML || resp.GetHeaders()["Cache-Control"] != "no-store" {
			t.Errorf("headers = %v", resp.GetHeaders())
		}
		assertCleanHTML(t, string(resp.GetBody()))
	}
}

func TestStartPageKeepsSecretsInsideItsTwoURLs(t *testing.T) {
	p, flowID, page := startFlow(t)
	body := html.UnescapeString(string(page.GetBody()))
	claim := claimFromPage(t, page)
	// The PIN code appears only in the Plex URL; the status claim is not
	// embedded in the status URL and may appear only in its dedicated field.
	withoutURLs := regexp.MustCompile(`(href|data-plex-url|data-status-url|data-return-url)="[^"]*"`).ReplaceAllString(body, "")
	if strings.Contains(withoutURLs, "code=CODE") {
		t.Fatal("PIN code appears outside the Plex URL")
	}
	statusURL := regexp.MustCompile(`data-status-url="([^"]+)"`).FindStringSubmatch(body)
	if len(statusURL) < 2 {
		t.Fatalf("start page has no status URL: %s", body)
	}
	if strings.Contains(statusURL[1], claim) || strings.Contains(statusURL[1], "claim=") {
		t.Fatal("browser claim must not be included in the status URL")
	}
	claimed := startPageRequest(t, p, flowID, "guess", "")
	if strings.Contains(string(claimed.GetBody()), claim) || strings.Contains(string(claimed.GetBody()), "CODE\"") || strings.Contains(string(claimed.GetBody()), "code=CODE") {
		t.Fatal("error page leaks a secret")
	}
}

func TestStartPageErrorsAreStyledHTML(t *testing.T) {
	p, flowID, _ := startFlow(t)

	claimed := startPageRequest(t, p, flowID, "", "")
	body := string(claimed.GetBody())
	if claimed.GetStatusCode() != http.StatusConflict || claimed.GetHeaders()["Content-Type"] != contentTypeHTML ||
		!strings.Contains(body, `id="error-claimed"`) || !strings.Contains(html.UnescapeString(body), English.T("error.claimed.title")) {
		t.Fatalf("claimed page = %d\n%s", claimed.GetStatusCode(), body)
	}
	if strings.Contains(body, `id="error-claimed" class="error" aria-labelledby="error-claimed-title" role="alert" hidden`) {
		t.Fatal("claimed screen must be visible")
	}
	assertCleanHTML(t, body)

	unknown := startPageRequest(t, p, "no-such-flow", "", "")
	if unknown.GetStatusCode() != http.StatusGone || !strings.Contains(string(unknown.GetBody()), "This sign-in has expired") {
		t.Fatalf("unknown flow = %d\n%s", unknown.GetStatusCode(), unknown.GetBody())
	}

	p.mu.Lock()
	p.flows[flowID].expiresAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	expired := startPageRequest(t, p, flowID, "", "")
	if expired.GetStatusCode() != http.StatusGone || !strings.Contains(html.UnescapeString(string(expired.GetBody())), "This sign-in has expired") {
		t.Fatalf("expired flow = %d", expired.GetStatusCode())
	}
}

func TestEveryErrorScreenRenders(t *testing.T) {
	for _, lang := range []Lang{English} {
		for _, e := range signinErrors {
			page := newSigninPage(lang)
			page.Screen, page.Code, page.Ref = "error", e.Code, "7KQ4M2"
			page.Account = &statusAccount{Title: "Claire L.", Username: "claire.l", Thumb: "https://plex.tv/users/x/avatar"}
			resp := renderPage(http.StatusOK, "signin.html", page)
			body := html.UnescapeString(string(resp.GetBody()))
			for _, want := range []string{
				lang.T("error." + string(e.Code) + ".title"),
				lang.T("signin.ref", "7KQ-4M2"),
				"7KQ-4M2", lang.T(e.Primary),
			} {
				if !strings.Contains(body, want) {
					t.Errorf("%s/%s: missing %q", lang, e.Code, want)
				}
			}
			section := body[strings.Index(body, `id="error-`+string(e.Code)+`"`):]
			section, _, _ = strings.Cut(section, "</section>")
			wantsIdentity := e.Code == ReasonNotAllowed || e.Code == ReasonIneligible
			if wantsIdentity != strings.Contains(section, `data-identity`) {
				t.Errorf("%s/%s: identity shown for the wrong codes", lang, e.Code)
			}
			if !wantsIdentity && (strings.Contains(section, "Claire L.") || strings.Contains(section, "claire.l")) {
				t.Errorf("%s/%s: identity leaked", lang, e.Code)
			}
			if strings.Contains(section, strings.ToUpper(string(e.Code))) || !strings.Contains(section, lang.T("signin.copy")) {
				t.Errorf("%s/%s: expected reference action without technical code", lang, e.Code)
			}
			if e.OtherAccount != strings.Contains(section, `data-other-account`) {
				t.Errorf("%s: other-account link mismatch", e.Code)
			}
			assertCleanHTML(t, string(resp.GetBody()))
		}
	}
}

func TestReloadAfterRefusalShowsTheSameError(t *testing.T) {
	plex := &fakePlex{userJSON: fullUser}
	plex.approved.Store(true)
	p := testProvider(plex.server(t))
	withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "sam"}}}, "")
	flowID, claim := openFlow(t, p)
	_, status, _ := poll(t, p, flowID, claim)
	resp := startPageRequest(t, p, flowID, claim, "")
	body := html.UnescapeString(string(resp.GetBody()))
	if !strings.Contains(body, formatRef(status.Ref)) || !strings.Contains(body, `data-screen="error"`) || !strings.Contains(body, "Alex M.") {
		t.Fatalf("reload must show the refusal with its reference:\n%s", body)
	}
}
