package provider

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func adminRequest(t *testing.T, p *Provider, path string, form url.Values, query map[string]any, headers map[string]string) *pluginv1.HandleHTTPResponse {
	t.Helper()
	req := &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: path, Headers: headers}
	if query != nil {
		req.Query = mustStruct(t, query)
	}
	if form != nil {
		req.Method, req.Body = http.MethodPost, []byte(form.Encode())
	}
	resp, err := p.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPeopleCopyIdentityActionIsIconOnly(t *testing.T) {
	p := New()
	withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "claire", UUID: "plex-user-1", Username: "claire"}}}, "")
	for _, tc := range []struct {
		lang string
		want string
	}{
		{"en", `aria-label="Copy Plex ID"`},
		// A French browser still gets the English-only interface.
		{"fr", `aria-label="Copy Plex ID"`},
	} {
		r := adminRequest(t, p, accessPath, nil, map[string]any{"tab": "people"}, map[string]string{"X-Silo-User-Id": "1", "X-Silo-User-Role": "admin", "accept-language": tc.lang})
		body := html.UnescapeString(string(r.GetBody()))
		if r.GetStatusCode() != http.StatusOK || !strings.Contains(body, tc.want) || !strings.Contains(body, `data-copy="plex:plex-user-1"`) {
			t.Errorf("%s copy action missing accessible label or identity: status=%d", tc.lang, r.GetStatusCode())
		}
		if strings.Contains(body, "Link to an existing Silo account") || strings.Contains(body, `plex:plex-user-1</`) {
			t.Errorf("%s page exposes a link action or renders the identity as text", tc.lang)
		}
	}
}

func TestAdminRoutesRequireAdminAndFormToken(t *testing.T) {
	p := New()
	getRoutes := []string{accessPath, finderPath, activityExportPath}
	postRoutes := []string{peopleAddPath, peopleRemovePath, activityAllowPath, disconnectPath, finderStartPath, finderStatusPath, finderSelectPath}
	for _, path := range getRoutes {
		if r := adminRequest(t, p, path, nil, nil, userHeaders("2")); r.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s: non-admin GET got %d", path, r.GetStatusCode())
		}
	}
	for _, path := range postRoutes {
		bad := url.Values{"token": {"bad"}}
		if r := adminRequest(t, p, path, bad, nil, userHeaders("2")); r.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s: non-admin POST got %d", path, r.GetStatusCode())
		}
		if r := adminRequest(t, p, path, bad, nil, adminHeaders("1")); r.GetStatusCode() != http.StatusForbidden {
			t.Errorf("%s: invalid token got %d", path, r.GetStatusCode())
		}
		bad.Set("input", strings.Repeat("x", maxFormSize+1))
		if r := adminRequest(t, p, path, bad, nil, adminHeaders("1")); r.GetStatusCode() != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: oversized form got %d", path, r.GetStatusCode())
		}
	}
}

func postAdmin(t *testing.T, p *Provider, path string, values map[string]string) *pluginv1.HandleHTTPResponse {
	t.Helper()
	form := url.Values{"token": {p.formToken()}}
	for k, v := range values {
		form.Set(k, v)
	}
	return adminRequest(t, p, path, form, nil, adminHeaders("1"))
}

func wantNotice(t *testing.T, r *pluginv1.HandleHTTPResponse, notice string) {
	t.Helper()
	if r.GetStatusCode() != 303 || !strings.Contains(r.GetHeaders()["Location"], "notice="+notice) {
		t.Fatalf("want notice %q, status=%d location=%q", notice, r.GetStatusCode(), r.GetHeaders()["Location"])
	}
}

func TestDisconnectKeepsManualList(t *testing.T) {
	p := New()
	store := withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "alex"}}}, "home-server")
	ctx := context.Background()
	original := string(store.values[connectionKey])
	if notice := postAdmin(t, p, peopleAddPath, map[string]string{"input": "sam"}); notice.GetStatusCode() != 303 {
		t.Fatalf("adding a person changed the connection: %d", notice.GetStatusCode())
	}
	if string(store.values[connectionKey]) != original {
		t.Fatal("adding a manual person must not change the Plex connection")
	}
	wantNotice(t, postAdmin(t, p, disconnectPath, nil), "disconnected")
	s, c, err := p.accessState(ctx)
	if err != nil || len(s.Manual) != 2 || c.ServerMachineID != "" {
		t.Fatalf("disconnect changed unrelated settings: %+v, %+v, %v", s, c, err)
	}
}

func TestAdminPeopleAddValidateLearnAndRemove(t *testing.T) {
	p := testProvider(plexDirectoryServer(t))
	store := withAccess(t, p, Settings{}, "")
	store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "home-server", OwnerToken: "owner-token"})
	post := func(input string) *pluginv1.HandleHTTPResponse {
		return postAdmin(t, p, peopleAddPath, map[string]string{"input": input})
	}
	for _, input := range []string{"two words", "0123456789abcdef", "123456"} {
		if r := post(input); r.GetStatusCode() != 422 {
			t.Fatalf("invalid input accepted: %d", r.GetStatusCode())
		}
	}
	for _, input := range []string{"sue@example.test", "sue", "owner", "alex", "sam"} {
		if r := post(input); r.GetStatusCode() != 422 || !strings.Contains(string(r.GetBody()), "already has access through your Plex server") {
			t.Fatalf("%s already has server access and must not be added: %d", input, r.GetStatusCode())
		}
	}
	wantNotice(t, post("ignored"), "added")
	s, err := p.loadSettings(context.Background())
	if err != nil || len(s.Manual) != 1 || s.Manual[0].UUID != "ignored-1" || s.Manual[0].Email != "ignored@example.test" {
		t.Fatalf("directory UUID not learned: %+v, %v", s, err)
	}
	if r := post("Ignored"); r.GetStatusCode() != 422 || !strings.Contains(string(r.GetBody()), "Already on the manual list.") {
		t.Fatalf("duplicate not refused: %d", r.GetStatusCode())
	}
	wantNotice(t, postAdmin(t, p, peopleRemovePath, map[string]string{"entry": entryKey(s.Manual[0].Input)}), "removed")
	s, _ = p.loadSettings(context.Background())
	if len(s.Manual) != 0 {
		t.Fatal("entry not removed")
	}
	for i := range maxManualEntries {
		s.Manual = append(s.Manual, ManualEntry{Input: fmt.Sprintf("user-%d", i)})
	}
	store.put(t, settingsKey, s)
	if r := post("overflow"); r.GetStatusCode() != 422 || !strings.Contains(string(r.GetBody()), "200 entries") {
		t.Fatalf("entry limit: %d", r.GetStatusCode())
	}
}

func TestAdminActivity(t *testing.T) {
	p := New()
	store := withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "sam@example.test"}}}, "")
	var r *pluginv1.HandleHTTPResponse
	var body string
	store.put(t, activityKey, []ActivityEntry{{Ref: "7KQ4M2", At: time.Now(), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex"}})
	r = adminRequest(t, p, accessPath, nil, map[string]any{"tab": "activity", "ref": "7KQ-4M2"}, adminHeaders("1"))
	body = string(r.GetBody())
	for _, want := range []string{"7KQ-4M2", `activity-row highlight`, `value="allow"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Activity lacks %s", want)
		}
	}
	if strings.Contains(body, "NOT_ALLOWED") {
		t.Error("technical reason codes must not be shown in the activity UI")
	}
	if !strings.Contains(body, "Allow alex to sign in to Silo?") || !strings.Contains(body, "Plex sharing is unchanged.") {
		t.Error("manual allow action must explain its consequence")
	}
	store.put(t, activityKey, []ActivityEntry{
		{Ref: "7KQ4M2", At: time.Now(), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex"},
		{Ref: "A6Y4W3", At: time.Now(), Outcome: outcomeAllow, Rule: RuleManual, Username: "sam"},
	})
	store.put(t, activityKey, []ActivityEntry{
		{Ref: "7KQ4M2", At: time.Now(), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex"},
		{Ref: "A6Y4W3", At: time.Now(), Outcome: outcomeAllow, Rule: RuleManual, Username: "sam"},
		{Ref: "EXP234", At: time.Now(), Outcome: outcomeRefuse, Reason: ReasonExpired},
	})
	refused := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "activity", "show": "refused"}, adminHeaders("1")).GetBody())
	if !strings.Contains(refused, "7KQ-4M2") || strings.Contains(refused, "A6Y-4W3") || strings.Contains(refused, "EXP-234") {
		t.Error("the Access denied filter must show only access refusals")
	}
	all := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "activity"}, adminHeaders("1")).GetBody())
	if !strings.Contains(all, "Not completed") || !strings.Contains(all, "Expired (10-minute limit)") || !strings.Contains(all, "Keeps attempts from the last 30 days, at most 100 in total (up to 20 not completed).") {
		t.Error("interrupted sign-ins and retention must be explained")
	}
	if !strings.Contains(all, `aria-label="Sign-in activity"`) && !strings.Contains(all, `tag tag-alert`) {
		t.Error("refusal badge missing")
	}
	if strings.Contains(all, `tag-alert" title="Denied">2<`) {
		t.Error("an expired sign-in must not count as a refusal")
	}
	wantNotice(t, postAdmin(t, p, activityAllowPath, map[string]string{"ref": "7KQ4M2"}), "added")
	s, _ := p.loadSettings(context.Background())
	if len(s.Manual) != 2 || s.Manual[1].UUID != "u-1" {
		t.Fatalf("Allow changed unexpected fields: %+v", s)
	}
}

func TestPeopleSortAndLocalizedEmptyStates(t *testing.T) {
	s := Settings{Manual: []ManualEntry{{Input: "Ada"}, {Input: "home", UUID: "2"}}}
	directory := []plexDirectoryUser{
		{plexUser: plexUser{UUID: "3", Username: "Shared"}, Shared: true},
		{plexUser: plexUser{UUID: "2", Username: "Home"}, Home: true},
		{plexUser: plexUser{UUID: "5", Username: "Kid", Restricted: true}, Home: true},
		{plexUser: plexUser{UUID: "1", Username: "Owner"}, Owner: true},
	}
	people, _ := peopleRows(English, s, true, directory)
	names := make([]string, len(people))
	for i, row := range people {
		names[i] = row.Name
	}
	// Home members with their own Plex account sign in through the server and
	// are listed with no Home label; managed profiles (no account) are hidden.
	if strings.Join(names, ",") != "Owner,Home,Shared,Ada" {
		t.Fatalf("unexpected people: %v", names)
	}
	if home := people[1]; strings.Join(home.Tags, ",") != "server,manual" || !home.Redundant || home.Subject != "plex:2" {
		t.Fatalf("Home member with an account: %+v", home)
	}
	for _, row := range people {
		for _, tag := range row.Tags {
			if strings.Contains(strings.ToLower(tag), "home") {
				t.Fatalf("Home must not be a tag: %+v", row)
			}
		}
	}
	manualOnly, suggestions := peopleRows(English, s, false, directory)
	if len(suggestions) != 0 {
		t.Fatal("without a Plex server nobody should be suggested")
	}
	if len(manualOnly) != 2 {
		t.Fatalf("without Plex, only the two manual entries should be shown: %+v", manualOnly)
	}
	for _, row := range manualOnly {
		if len(row.Tags) != 1 || row.Tags[0] != "manual" {
			t.Fatalf("without a Plex server every row is manual: %+v", row)
		}
	}
	for _, tt := range []struct{ tab, key string }{{"access", "admin.access.title"}, {"people", "admin.people.empty"}, {"activity", "admin.activity.empty"}} {
		p := New()
		withAccess(t, p, Settings{}, "")
		r := adminRequest(t, p, accessPath, nil, map[string]any{"tab": tt.tab}, map[string]string{"X-Silo-User-Id": "1", "X-Silo-User-Role": "admin", "accept-language": "fr-CA"})
		body := string(r.GetBody())
		if r.GetStatusCode() != 200 || !strings.Contains(body, `lang="en"`) || !strings.Contains(html.UnescapeString(body), English.T(tt.key)) {
			t.Fatalf("empty %s: %d", tt.tab, r.GetStatusCode())
		}
		assertCleanHTML(t, body)
	}
}

func TestPeopleRowsShowStoredManualEmailWithoutDirectory(t *testing.T) {
	s := Settings{Manual: []ManualEntry{{
		Input: "ada", UUID: "u-1", Username: "ada", Email: "ada@example.test",
	}}}
	rows, _ := peopleRows(English, s, false, nil)
	if len(rows) != 1 || rows[0].Email != "ada@example.test" {
		t.Fatalf("stored email must be shown when Plex is not reached: %+v", rows)
	}
	byInput := Settings{Manual: []ManualEntry{{Input: "ada@example.test"}}}
	if rows, _ := peopleRows(English, byInput, false, nil); len(rows) != 1 || rows[0].Email != "ada@example.test" {
		t.Fatalf("an address typed as the entry must still be shown: %+v", rows)
	}
}

func TestActivityExportIsCSVAndEscapesFormulas(t *testing.T) {
	p := New()
	store := withAccess(t, p, Settings{}, "")
	now := time.Now().UTC()
	store.put(t, activityKey, []ActivityEntry{
		{Ref: "AAA111", At: now, Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex", Title: "=SUM(1,1)"},
		{Ref: "BBB222", At: now.Add(-time.Hour), Outcome: outcomeAllow, Rule: RuleManual, UUID: "u-2", Username: "sam", Title: "Sam"},
	})

	resp := adminRequest(t, p, activityExportPath, nil, nil, adminHeaders("1"))
	body := string(resp.GetBody())
	if resp.GetStatusCode() != http.StatusOK || !strings.Contains(resp.GetHeaders()["Content-Type"], "text/csv") {
		t.Fatalf("export = %d %q", resp.GetStatusCode(), resp.GetHeaders()["Content-Type"])
	}
	if cd := resp.GetHeaders()["Content-Disposition"]; !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Fatalf("export must download a file: %q", cd)
	}
	if !strings.HasPrefix(body, "ref,at,outcome,rule,reason,plex_account_id,username,title\n") {
		t.Fatalf("unexpected header: %q", body)
	}
	if !strings.Contains(body, "AAA111,") || !strings.Contains(body, `"'=SUM(1,1)"`) {
		t.Fatalf("formula-looking value must be escaped: %q", body)
	}
	for _, leaked := range []string{"token", "pin", "email_key", "name_key"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("export leaks %q: %q", leaked, body)
		}
	}

	post := adminRequest(t, p, activityExportPath, url.Values{"token": {p.formToken()}}, nil, adminHeaders("1"))
	if post.GetStatusCode() != http.StatusMethodNotAllowed {
		t.Fatalf("export must be read-only, got %d", post.GetStatusCode())
	}
}

func TestActivityMarksRefusalListedByEmailOrUsername(t *testing.T) {
	confirmed := true
	for _, tt := range []struct {
		name   string
		user   plexUser
		manual ManualEntry
	}{
		{"email typed as the entry", plexUser{UUID: "u-1", Username: "sam@example.test", Confirmed: &confirmed}, ManualEntry{Input: "sam@example.test"}},
		{"username typed as the entry", plexUser{UUID: "u-2", Username: "sam"}, ManualEntry{Input: "SAM"}},
		{"email learned on the entry", plexUser{UUID: "u-3", Username: "samuel", Email: "sam@example.test", Confirmed: &confirmed}, ManualEntry{Input: "sam", Email: "sam@example.test"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entry := newActivity("REF123", Decision{Reason: ReasonNotAllowed}, tt.user)
			rows := activityRows(English, Settings{Manual: []ManualEntry{tt.manual}}, []ActivityEntry{entry}, "", time.Now())
			if len(rows) != 1 || rows[0].Allow || !rows[0].Listed {
				t.Fatalf("an already listed person must not be offered the action again: %+v", rows)
			}
		})
	}
}

func TestActivityBadgeClearsOnceRefusedPersonIsListed(t *testing.T) {
	confirmed := true
	refusal := newActivity("A1B2C3", Decision{Reason: ReasonNotAllowed}, plexUser{UUID: "u-1", Username: "sam@example.test", Confirmed: &confirmed})
	render := func(manual []ManualEntry) string {
		p := New()
		store := withAccess(t, p, Settings{Manual: manual}, "")
		store.put(t, activityKey, []ActivityEntry{refusal})
		return string(p.renderAdmin(context.Background(), English, adminInput{tab: "activity"}, http.StatusOK).GetBody())
	}
	if body := render([]ManualEntry{{Input: "sam@example.test"}}); strings.Contains(body, "tag-alert") {
		t.Error("a refusal the manual list now covers must not stay in the badge")
	}
	if body := render(nil); !strings.Contains(body, "tag-alert") {
		t.Error("an unresolved refusal must still be counted")
	}
}

func TestAccessConnectsPlexAndPeopleHoldsTheList(t *testing.T) {
	p := New()
	withAccess(t, p, Settings{}, "")
	body := string(adminRequest(t, p, accessPath, nil, nil, adminHeaders("1")).GetBody())
	for _, want := range []string{`?tab=access" aria-current="page">Plex<`, "Who can sign in", "Selected Plex server", "Manual list", "Connect Plex", "Not configured", "No one can sign in yet. Connect a server or add users."} {
		if !strings.Contains(body, want) {
			t.Errorf("Access lacks %q", want)
		}
	}
	if strings.Contains(body, `type="radio"`) {
		t.Error("sources are not mutually exclusive modes")
	}
	people := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "people"}, adminHeaders("1")).GetBody())
	for _, want := range []string{"Add to manual list", ">Users<"} {
		if !strings.Contains(people, want) {
			t.Errorf("People lacks %q", want)
		}
	}
	if strings.Contains(people, "Estimate access for a Plex account") {
		t.Error("People still shows the access estimate section")
	}
	if strings.Contains(body, "Access configured") || strings.Contains(body, "live check") {
		t.Error("the not-set-up state must not show the configured hint")
	}
	withAccess(t, p, Settings{}, "plex-server-1")
	body = string(adminRequest(t, p, accessPath, nil, nil, adminHeaders("1")).GetBody())
	for _, want := range []string{"Access configured", "Plex availability isn’t checked.", "Disconnect server"} {
		if !strings.Contains(body, want) {
			t.Errorf("configured Access lacks %q", want)
		}
	}
	if strings.Contains(body, "Checked ") {
		t.Error("the connection date must not read as a health check")
	}
	if !strings.Contains(body, "if Plex reports access to the selected server, or if it’s on the manual list.") || !strings.Contains(body, "This plugin never changes it.") {
		t.Error("connected server must explain the rule")
	}
}

func TestDisconnectKeepsManualAccess(t *testing.T) {
	p := New()
	withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "alex"}}}, "srv")
	if notice := postAdmin(t, p, disconnectPath, nil); notice.GetStatusCode() != 303 {
		t.Fatalf("disconnect = %d", notice.GetStatusCode())
	}
	settings, connection, err := p.accessState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := Decide(settings, connection.ServerMachineID, connection.OwnerUUID, connection.OwnerID, plexUser{UUID: "u-1", Username: "alex"}, nil); !got.Allowed || got.Rule != RuleManual {
		t.Fatalf("manual source must survive disconnect: %+v", got)
	}
	if got := Decide(settings, connection.ServerMachineID, connection.OwnerUUID, connection.OwnerID, plexUser{UUID: "u-2", Username: "friend"}, nil); got.Allowed {
		t.Fatal("server users must stop being allowed after disconnect")
	}
}

func TestPeopleFilterOnlyForLongLists(t *testing.T) {
	build := func(n int) string {
		settings := Settings{}
		for i := range n {
			settings.Manual = append(settings.Manual, ManualEntry{Input: fmt.Sprintf("user-%d", i)})
		}
		p := New()
		withAccess(t, p, settings, "")
		return string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "people"}, adminHeaders("1")).GetBody())
	}
	if strings.Contains(build(8), `id="people-filter"`) {
		t.Error("a short list does not need a filter")
	}
	if !strings.Contains(build(9), `id="people-filter"`) {
		t.Error("a long list needs a filter")
	}
}

func TestAdminAddRefusedWhilePlexCannotConfirm(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer plex.Close()
	p := testProvider(plex)
	store := withAccess(t, p, Settings{}, "")
	store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "home-server", OwnerToken: "owner-token"})
	r := postAdmin(t, p, peopleAddPath, map[string]string{"input": "newcomer"})
	if r.GetStatusCode() != 422 || !strings.Contains(string(r.GetBody()), "Plex isn’t responding") {
		t.Fatalf("an unchecked add must be refused: %d", r.GetStatusCode())
	}
	if s, _ := p.loadSettings(context.Background()); len(s.Manual) != 0 {
		t.Fatalf("nothing should be stored: %+v", s.Manual)
	}

	withAccess(t, p, Settings{}, "")
	wantNotice(t, postAdmin(t, p, peopleAddPath, map[string]string{"input": "newcomer"}), "added")
}

func TestPeopleFlagsManualEntryAlreadyAllowedByServer(t *testing.T) {
	s := Settings{Manual: []ManualEntry{{Input: "sue", UUID: "3"}}}
	directory := []plexDirectoryUser{{plexUser: plexUser{UUID: "3", Username: "sue"}, Shared: true}}
	people, _ := peopleRows(English, s, true, directory)
	if len(people) != 1 || !people[0].Redundant {
		t.Fatalf("redundant manual entry not flagged: %+v", people)
	}
	people, _ = peopleRows(English, s, false, directory)
	if len(people) != 1 || people[0].Redundant {
		t.Fatalf("without a server the entry is not redundant: %+v", people)
	}
}

// TestAdminUXStates covers the copy and states added by the admin UX audit.
func TestAdminUXStates(t *testing.T) {
	p := New()
	store := withAccess(t, p, Settings{Manual: []ManualEntry{{Input: "sam"}}}, "")
	store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "a1b2c3d4e5f6f9", UpdatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	body := string(adminRequest(t, p, accessPath, nil, nil, adminHeaders("1")).GetBody())
	for _, want := range []string{"Unnamed server", "a1b2c3…f9", "Connected 1 h ago", "1 on the list · No Plex server access required", `href="access?tab=people">Manage list<`, "Disconnect Unnamed server?", "The manual list is kept."} {
		if !strings.Contains(body, want) {
			t.Errorf("Plex tab lacks %q", want)
		}
	}

	store.put(t, activityKey, []ActivityEntry{
		{Ref: "7KQ4M2", At: time.Now(), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex"},
	})
	found := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "activity", "ref": "7kq-4m2"}, adminHeaders("1")).GetBody())
	if !strings.Contains(found, `id="ref-match"`) || strings.Contains(found, "No attempt matches this reference.") || !strings.Contains(found, `value="7KQ-4M2"`) {
		t.Error("a lowercase reference must be found and highlighted")
	}
	missing := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "activity", "ref": "ZZZ-ZZZ"}, adminHeaders("1")).GetBody())
	if !strings.Contains(missing, "No attempt matches this reference.") {
		t.Error("an unknown reference must say so")
	}
	if !strings.Contains(found, "1 unresolved denials in the last 7 days") {
		t.Error("the Activity badge needs an accessible label")
	}

	wantNotice(t, postAdmin(t, p, activityAllowPath, map[string]string{"ref": "7KQ4M2"}), "added")
	wantNotice(t, postAdmin(t, p, activityAllowPath, map[string]string{"ref": "7KQ4M2"}), "already_listed")
	wantNotice(t, postAdmin(t, p, activityAllowPath, map[string]string{"ref": "GONE22"}), "ref_missing")
}

func TestPeopleWarnsWhenPlexDirectoryIsPartial(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer plex.Close()
	p := testProvider(plex)
	store := withAccess(t, p, Settings{}, "")
	store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "home-server", OwnerToken: "owner-token"})
	body := string(adminRequest(t, p, accessPath, nil, map[string]any{"tab": "people"}, adminHeaders("1")).GetBody())
	if !strings.Contains(body, "users allowed by the server may be missing") {
		t.Error("a partial Plex directory must be announced")
	}
}

func TestActivityRowsExplainIdentityAndFollowUp(t *testing.T) {
	now := time.Now()
	s := Settings{Manual: []ManualEntry{{Input: "alex", UUID: "u-1"}}}
	rows := activityRows(English, s, []ActivityEntry{
		{Ref: "AAAAAA", At: now, Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-1", Username: "alex"},
		{Ref: "BBBBBB", At: now, Outcome: outcomeRefuse, Reason: ReasonExpired},
		{Ref: "CCCCCC", At: now, Outcome: outcomeRefuse, Reason: ReasonIneligible, UUID: "u-2", Username: "kid"},
	}, "", now)
	if !rows[0].Listed || rows[0].Allow {
		t.Error("a refused person now on the manual list must say so, not offer Allow again")
	}
	if !rows[1].Person.Anonymous || rows[1].Person.Name != "No Plex account identified" {
		t.Errorf("an attempt without a Plex account must not look like a person: %+v", rows[1].Person)
	}
	if rows[2].Person.Anonymous || !strings.Contains(rows[2].Detail, "A full Plex account is required") {
		t.Errorf("ineligible reason must say what to do: %q", rows[2].Detail)
	}
}
