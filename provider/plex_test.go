package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlexUserListAcceptsObjectOrArray(t *testing.T) {
	var objectList plexUserList
	if err := json.Unmarshal([]byte(`{"uuid":"one","username":"alex"}`), &objectList); err != nil || len(objectList) != 1 {
		t.Fatalf("object form: %v %+v", err, objectList)
	}
	var arrayList plexUserList
	if err := json.Unmarshal([]byte(`[{"uuid":"one"},{"uuid":"two"}]`), &arrayList); err != nil || len(arrayList) != 2 {
		t.Fatalf("array form: %v %+v", err, arrayList)
	}
}

func plexDirectoryServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Plex-Token") != "owner-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v2/user":
			_, _ = w.Write([]byte(`{"uuid":"owner-1","username":"owner","title":"Owner Person","email":"owner@example.test","thumb":"https://plex.tv/users/owner/avatar"}`))
		case "/api/v2/home/users":
			_, _ = w.Write([]byte(`{"users":[
				{"uuid":"alex-1","username":"alex","title":"Alex Martin","email":"alex@example.test","thumb":"https://plex.tv/users/alex/avatar","home":true},
				{"uuid":"sam-1","username":"sam","title":"Sam Petit","thumb":"/users/sam/avatar"}]}`))
		case "/api/v2/shared_servers/owned/accepted":
			_, _ = w.Write([]byte(`[
				{"machineIdentifier":"other-server","invited":[{"uuid":"ignored-1","username":"ignored","title":"Ignored","email":"ignored@example.test"}]},
				{"machineIdentifier":"home-server","invited":[
					{"uuid":"alex-1","username":"alex","title":"Alex Martin"},
					{"uuid":"sue-1","username":"sue","title":"Sue Shared","email":"sue@example.test","confirmed":true,"thumb":"https://plex.tv/users/sue/avatar"}
				]}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPlexDirectoryMergesOwnerHomeAndSharedUsers(t *testing.T) {
	server := plexDirectoryServer(t)
	defer server.Close()
	p := testProvider(server)

	users, warnings, err := p.fetchPlexDirectory(context.Background(), "owner-token", "home-server")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("directory err=%v warnings=%v", err, warnings)
	}
	if len(users) != 5 {
		t.Fatalf("directory users = %d, want 5: %+v", len(users), users)
	}
	byID := make(map[string]plexDirectoryUser, len(users))
	for _, user := range users {
		byID[user.UUID] = user
	}
	if !byID["owner-1"].Owner {
		t.Fatal("owner not marked")
	}
	if !byID["alex-1"].Home || !byID["alex-1"].Shared {
		t.Fatalf("duplicate Home/shared user lost a source: %+v", byID["alex-1"])
	}
	if !byID["sam-1"].Home || byID["sam-1"].Thumb != "https://plex.tv/users/sam/avatar" {
		t.Fatalf("relative avatar not normalized: %+v", byID["sam-1"])
	}
	if !byID["sue-1"].Shared {
		t.Fatal("shared server user not marked")
	}
	if byID["ignored-1"].Shared || byID["ignored-1"].UUID == "" {
		t.Fatal("users from another server must be suggestions, not shared users")
	}
}

func TestAccessPageShowsServerIdentityAndEnrichedPeople(t *testing.T) {
	server := plexDirectoryServer(t)
	defer server.Close()
	p := testProvider(server)
	store := withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "sue"}, {Input: "unknown-person"}}}, "")
	store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "home-server", ServerName: "Home Cinema", OwnerToken: "owner-token"})

	access := p.renderAdmin(context.Background(), English, adminInput{notice: "admin.notice.connected"}, http.StatusOK)
	body := string(access.GetBody())
	for _, want := range []string{"Home Cinema", "home-server", "Plex server connected"} {
		if !strings.Contains(body, want) {
			t.Errorf("Access missing %q", want)
		}
	}
	people := p.renderAdmin(context.Background(), English, adminInput{tab: "people"}, http.StatusOK)
	body = string(people.GetBody())
	for _, want := range []string{"Owner Person", "Alex Martin", "Sue Shared", "https://plex.tv/users/alex/avatar", "unknown-person", "Pending first sign-in"} {
		if !strings.Contains(body, want) {
			t.Errorf("People missing %q", want)
		}
	}
	for _, secret := range []string{"owner-token", ">alex-1<"} {
		if strings.Contains(body, secret) {
			t.Errorf("People leaks %q", secret)
		}
	}
	if !strings.Contains(body, "alex@example.test") {
		t.Error("People should show the available Plex email")
	}
}

// TestDirectoryEmailMatchRequiresConfirmation keeps an unconfirmed Plex email
// from binding a manual entry to an account, as in matchManual.
func TestDirectoryEmailMatchRequiresConfirmation(t *testing.T) {
	yes, no := true, false
	person := func(confirmed *bool) plexDirectoryUser {
		return plexDirectoryUser{plexUser: plexUser{UUID: "u1", Username: "kim", Email: "kim@example.test", Confirmed: confirmed}}
	}
	if !directoryInputMatches("kim", person(nil)) {
		t.Fatal("username must match")
	}
	if !directoryInputMatches("KIM@example.test", person(&yes)) {
		t.Fatal("confirmed email must match")
	}
	for _, confirmed := range []*bool{nil, &no} {
		if directoryInputMatches("kim@example.test", person(confirmed)) {
			t.Fatalf("unconfirmed email matched (confirmed=%v)", confirmed)
		}
		if _, ok := directoryMatch("kim@example.test", []plexDirectoryUser{person(confirmed)}); ok {
			t.Fatal("directoryMatch bound an unconfirmed email")
		}
	}
}

func TestFetchResourcesFallsBackToSecondHost(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"Living room","clientIdentifier":"tv","provides":"player"}]`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"Home","clientIdentifier":"srv","provides":"server","owned":true}]`))
	}))
	defer second.Close()

	p := New()
	p.httpClient = first.Client()
	p.resourceHosts = []string{first.URL, second.URL}
	resources, err := p.fetchResources(context.Background(), "token")
	if err != nil || len(resources) != 1 || resources[0].ClientIdentifier != "srv" {
		t.Fatalf("second host not used: %+v, %v", resources, err)
	}
}

func TestFetchResourcesStopsWhenPlexRejectsTheToken(t *testing.T) {
	calls := 0
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`[{"name":"Home","clientIdentifier":"srv","provides":"server","owned":true}]`))
	}))
	defer second.Close()

	p := New()
	p.httpClient = first.Client()
	p.resourceHosts = []string{first.URL, second.URL}
	if _, err := p.fetchResources(context.Background(), "token"); err == nil {
		t.Fatal("a rejected token must be reported")
	}
	if calls != 0 {
		t.Fatal("a rejected token must not be retried on another host")
	}
}

func TestCheckEndpointRejectsAMissingRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	p := testProvider(server)
	if err := p.checkEndpoint(context.Background()); err == nil {
		t.Fatal("404 must fail Silo's connection test")
	}
}
