package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func adminHeaders(id string) map[string]string {
	return map[string]string{"X-Silo-User-Id": id, "X-Silo-User-Role": "admin"}
}

func userHeaders(id string) map[string]string {
	return map[string]string{"X-Silo-User-Id": id, "X-Silo-User-Role": "user"}
}

func finderPlex(t *testing.T, approved *bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/pins":
			_, _ = w.Write([]byte(`{"id":3,"code":"FINDCODE"}`))
		case "/api/v2/pins/3":
			if *approved {
				_, _ = w.Write([]byte(`{"id":3,"code":"FINDCODE","authToken":"secret-plex-token"}`))
			} else {
				_, _ = w.Write([]byte(`{"id":3,"code":"FINDCODE","authToken":""}`))
			}
		case "/api/v2/user":
			_, _ = w.Write([]byte(`{"uuid":"owner-uuid-1","username":"owner"}`))
		case "/api/v2/resources":
			_, _ = w.Write([]byte(`[
				{"name":"Friend's box","clientIdentifier":"friend-id-0001","provides":"server","owned":false},
				{"name":"Living room TV","clientIdentifier":"tv-id-0001","provides":"player,client","owned":false},
				{"name":"Home server","clientIdentifier":"home-id-0001","provides":"server","owned":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func finderGet(t *testing.T, p *Provider, path string, headers map[string]string, query map[string]any) *pluginv1.HandleHTTPResponse {
	t.Helper()
	req := &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: path, Headers: headers}
	if query != nil {
		req.Query = mustStruct(t, query)
	}
	resp, err := p.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func finderPost(t *testing.T, p *Provider, path string, headers map[string]string, values map[string]string) *pluginv1.HandleHTTPResponse {
	t.Helper()
	form := url.Values{"token": {p.formToken()}}
	for key, value := range values {
		form.Set(key, value)
	}
	resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: path, Headers: headers, Body: []byte(form.Encode())})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFinderPageIsSideEffectFreeAndRoutesRequireAdmin(t *testing.T) {
	pinCalls := 0
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/pins" {
			pinCalls++
			_, _ = w.Write([]byte(`{"id":3,"code":"FINDCODE"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(plex.Close)
	p := testProvider(plex)
	for name, headers := range map[string]map[string]string{"anonymous": nil, "regular user": userHeaders("5")} {
		if resp := finderGet(t, p, finderPath, headers, nil); resp.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s on %s: want 403, got %d", name, finderPath, resp.GetStatusCode())
		}
		if resp := finderPost(t, p, finderStartPath, headers, nil); resp.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s on %s: want 403, got %d", name, finderStartPath, resp.GetStatusCode())
		}
		if resp := finderPost(t, p, finderStatusPath, headers, map[string]string{"flow": "x"}); resp.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s on %s: want 403, got %d", name, finderStatusPath, resp.GetStatusCode())
		}
	}
	if len(p.finders) != 0 || pinCalls != 0 {
		t.Fatal("refused admin routes must not start a Plex PIN")
	}

	page := finderGet(t, p, finderPath, adminHeaders("1"), nil)
	if page.GetStatusCode() != http.StatusOK || !strings.Contains(string(page.GetBody()), "Connect Plex") {
		t.Fatalf("GET finder page = %d: %s", page.GetStatusCode(), page.GetBody())
	}
	if pinCalls != 0 || len(p.finders) != 0 {
		t.Fatal("GET finder page must be side-effect free; expected no PIN or pending flow")
	}
}

func TestFinderListsServersWithoutLeakingTheToken(t *testing.T) {
	approved := false
	p := testProvider(finderPlex(t, &approved))
	page := finderGet(t, p, finderPath, adminHeaders("1"), nil)
	if page.GetStatusCode() != http.StatusOK || !strings.Contains(string(page.GetBody()), "Connect Plex") {
		t.Fatalf("page=%v", page)
	}
	started := finderPost(t, p, finderStartPath, adminHeaders("1"), nil)
	if started.GetStatusCode() != http.StatusSeeOther || !strings.Contains(started.GetHeaders()["Location"], "find-server?flow=") {
		t.Fatalf("start flow = %v", started)
	}
	flowID := strings.TrimPrefix(started.GetHeaders()["Location"], "../find-server?flow=")
	page = finderGet(t, p, finderPath, adminHeaders("1"), map[string]any{"flow": flowID})
	if page.GetStatusCode() != http.StatusOK || !strings.Contains(string(page.GetBody()), `data-status="find-server/poll"`) || strings.Contains(string(page.GetBody()), "secret-plex-token") {
		t.Fatalf("flow page must provide poll endpoint without leaking token: %s", page.GetBody())
	}
	poll := func(headers map[string]string) *pluginv1.HandleHTTPResponse {
		return finderPost(t, p, finderStatusPath, headers, map[string]string{"flow": flowID, "token": p.formToken()})
	}

	if body := string(poll(adminHeaders("1")).GetBody()); !strings.Contains(body, `"waiting"`) {
		t.Fatalf("before approval: %s", body)
	}
	approved = true
	if resp := poll(adminHeaders("2")); resp.GetStatusCode() != http.StatusGone {
		t.Fatalf("another admin must not read this flow, got %d", resp.GetStatusCode())
	}
	resp := poll(adminHeaders("1"))
	body := string(resp.GetBody())
	if !strings.Contains(body, `"done"`) || !strings.Contains(body, "home-id-0001") {
		t.Fatalf("owned server missing: %s", body)
	}
	if strings.Contains(body, "tv-id-0001") {
		t.Fatalf("players are not servers: %s", body)
	}
	if strings.Contains(body, "friend-id-0001") {
		t.Fatalf("a server only shared with the account must not be offered: %s", body)
	}
	if strings.Contains(body, "secret-plex-token") {
		t.Fatalf("the Plex token must never leave the plugin: %s", body)
	}
	if again := poll(adminHeaders("1")); again.GetStatusCode() != http.StatusOK || !strings.Contains(string(again.GetBody()), `"done"`) {
		t.Fatal("a completed finder flow must remain selectable until the admin chooses a server")
	}
}

func TestFinderSelectStoresServerConnectionWithoutLeakingTheToken(t *testing.T) {
	approved := false
	p := testProvider(finderPlex(t, &approved))

	start := finderPost(t, p, finderStartPath, adminHeaders("1"), nil)
	flowID := strings.TrimPrefix(start.GetHeaders()["Location"], "../find-server?flow=")
	approved = true
	finderPost(t, p, finderStatusPath, adminHeaders("1"), map[string]string{"flow": flowID, "token": p.formToken()})

	form := url.Values{
		"token":     {p.formToken()},
		"flow":      {flowID},
		"server_id": {"home-id-0001"},
	}
	resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{
		Method:  http.MethodPost,
		Path:    finderSelectPath,
		Headers: adminHeaders("1"),
		Body:    []byte(form.Encode()),
	})
	if err != nil || resp.GetStatusCode() != http.StatusSeeOther || !strings.Contains(resp.GetHeaders()["Location"], "notice=connected") {
		t.Fatalf("select response=%v err=%v", resp, err)
	}
	if strings.Contains(string(resp.GetBody()), "secret-plex-token") {
		t.Fatal("the Plex token must never reach the browser")
	}
	connection, err := p.loadConnection(context.Background())
	if err != nil {
		t.Fatalf("connection not stored: %v", err)
	}
	if connection.ServerMachineID != "home-id-0001" || connection.ServerName != "Home server" || connection.OwnerToken != "secret-plex-token" || connection.OwnerUUID != "owner-uuid-1" {
		t.Fatalf("unexpected connection: %+v", connection)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.finders[flowID]; exists {
		t.Fatal("selected finder flow must be removed")
	}
}

func TestFinderReturnReusesTheFlowInTheSameWindow(t *testing.T) {
	approved := false
	p := testProvider(finderPlex(t, &approved))

	first := finderGet(t, p, finderPath, adminHeaders("1"), nil)
	if first.GetStatusCode() != http.StatusOK {
		t.Fatalf("first page status=%d", first.GetStatusCode())
	}
	if len(p.finders) != 0 {
		t.Fatal("GET finder page must not create a flow")
	}
	start := finderPost(t, p, finderStartPath, adminHeaders("1"), nil)
	flowID := strings.TrimPrefix(start.GetHeaders()["Location"], "../find-server?flow=")
	if flowID == "" {
		t.Fatal("start route did not return a flow ID")
	}

	returned := finderGet(t, p, finderPath, adminHeaders("1"), map[string]any{"flow": flowID})
	body := string(returned.GetBody())
	if returned.GetStatusCode() != http.StatusOK || !strings.Contains(body, `data-status="find-server/poll"`) {
		t.Fatalf("return page did not resume the existing flow: %s", body)
	}
	if !strings.Contains(body, `id="plex-connect"`) || !strings.Contains(body, "https://app.plex.tv/auth#?") || !strings.Contains(body, "Check again") {
		t.Fatal("the pending flow must link to the Plex authorization page")
	}
	if strings.Contains(body, `target="_blank"`) {
		t.Fatal("the Plex authorization must stay in the same window")
	}
	p.mu.Lock()
	storedFlows := len(p.finders)
	p.mu.Unlock()
	if storedFlows != 1 {
		t.Fatalf("returning from Plex created another PIN/flow: %d stored", storedFlows)
	}

	otherAdmin := finderGet(t, p, finderPath, adminHeaders("2"), map[string]any{"flow": flowID})
	if otherAdmin.GetStatusCode() != http.StatusGone || strings.Contains(string(otherAdmin.GetBody()), flowID) {
		t.Fatal("another administrator must not resume or see this flow")
	}
}

func TestTestConnectionReportsCurrentAccessState(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer plex.Close()
	p := testProvider(plex)
	withAccess(t, p, Settings{}, "")

	resp, err := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOk() {
		t.Fatalf("an unconfigured plugin locks everyone out, so the test must not pass: %v", resp)
	}
	if resp.GetSteps()[0].GetId() != "plex" || !resp.GetSteps()[0].GetOk() {
		t.Fatalf("Plex reachability comes first: %v", resp.GetSteps())
	}

	if err := p.saveConnection(context.Background(), plexConnection{
		ServerMachineID: "abcdef1234567890",
		ServerName:      "Home server",
		OwnerToken:      "token",
	}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{}); !resp.GetOk() {
		t.Fatalf("a configured server must pass: %v", resp)
	}
}
