package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// plexAccountServer fakes plex.tv: /user and /resources for one account token.
func plexAccountServer(t *testing.T, userJSON, resourcesJSON string, userStatus, resourcesStatus *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/user":
			if st := int(userStatus.Load()); st != 0 && st != 200 {
				w.WriteHeader(st)
				return
			}
			_, _ = w.Write([]byte(userJSON))
		case "/api/v2/resources":
			if st := int(resourcesStatus.Load()); st != 0 && st != 200 {
				w.WriteHeader(st)
				return
			}
			_, _ = w.Write([]byte(resourcesJSON))
		default:
			http.NotFound(w, r)
		}
	}))
}

func refreshState(t *testing.T, token string) *pluginv1.CheckAccountRequest {
	t.Helper()
	return &pluginv1.CheckAccountRequest{ExternalSubject: "plex:u-1", RefreshState: mustStruct(t, map[string]any{"auth_token": token})}
}

func TestCheckAccountRevokesOnlyOnDefinitiveAnswer(t *testing.T) {
	var userStatus, resStatus atomic.Int32
	plex := plexAccountServer(t, `{"uuid":"u-1","username":"alex"}`, `[{"clientIdentifier":"srv","provides":"server"}]`, &userStatus, &resStatus)
	defer plex.Close()
	p := testProvider(plex)
	withAccess(t, p, Settings{}, "srv")
	check := func() pluginv1.CheckAccountStatus {
		resp, err := p.CheckAccount(context.Background(), refreshState(t, "tok"))
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetStatus()
	}

	if got := check(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		t.Fatalf("shared user must stay active, got %v", got)
	}

	withAccess(t, p, Settings{}, "another-server")
	if got := check(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED {
		t.Fatalf("lost server access must revoke, got %v", got)
	}

	withAccess(t, p, Settings{}, "srv")
	resStatus.Store(http.StatusInternalServerError)
	if got := check(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("Plex outage must never revoke, got %v", got)
	}

	resStatus.Store(0)
	userStatus.Store(http.StatusUnauthorized)
	if got := check(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED {
		t.Fatalf("expired token must not revoke, got %v", got)
	}

	userStatus.Store(0)
	resp, _ := p.CheckAccount(context.Background(), &pluginv1.CheckAccountRequest{ExternalSubject: "plex:u-1"})
	if resp.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED {
		t.Fatalf("no stored token must be unsupported, got %v", resp.GetStatus())
	}
	other, _ := p.CheckAccount(context.Background(), &pluginv1.CheckAccountRequest{ExternalSubject: "plex:someone-else", RefreshState: mustStruct(t, map[string]any{"auth_token": "tok"})})
	if other.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED {
		t.Fatalf("a token that belongs to another account must not vouch for this one, got %v", other.GetStatus())
	}
}

func TestCheckAccountDoesNotOverwriteRefreshToken(t *testing.T) {
	var userStatus, resStatus atomic.Int32
	plex := plexAccountServer(t, `{"uuid":"u-1","username":"alex"}`, `[]`, &userStatus, &resStatus)
	defer plex.Close()
	p := testProvider(plex)
	resp, err := p.CheckAccount(context.Background(), refreshState(t, "tok"))
	if err != nil || resp.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	if resp.GetAccount().GetRefreshState() != nil {
		t.Fatal("CheckAccount must leave the stored token unset, not clear it")
	}
}

func TestIdentityEmailVerificationFollowsPlex(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name      string
		confirmed *bool
		wantSet   bool
		wantValue bool
	}{
		{"confirmed", &yes, true, true},
		{"unconfirmed is a real answer", &no, true, false},
		{"missing means plex did not say", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := identity(&authResult{user: plexUser{UUID: "u", Username: "alex", Email: "a@example.test", Confirmed: tc.confirmed}})
			if resp.GetEmail() != "a@example.test" {
				t.Fatalf("email = %q", resp.GetEmail())
			}
			if resp.EmailVerified != nil != tc.wantSet || (tc.wantSet && *resp.EmailVerified != tc.wantValue) {
				t.Fatalf("email_verified = %v", resp.EmailVerified)
			}
		})
	}
	if resp := identity(&authResult{user: plexUser{UUID: "u", Username: "alex"}}); resp.GetEmail() != "" || resp.EmailVerified != nil {
		t.Fatalf("no email must stay empty: %v", resp)
	}
}

func TestIdentityNeverManagesRolesAndKeepsPicture(t *testing.T) {
	user := plexUser{UUID: "u", Username: "alex", Thumb: "https://plex.tv/users/abc/avatar"}
	if resp := identity(&authResult{user: user}); resp.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Fatalf("the plugin must never manage Silo roles: %v", resp.GetManagedRole())
	}
	if resp := identity(&authResult{user: user}); resp.GetPictureUrl() != user.Thumb {
		t.Fatalf("picture = %q", resp.GetPictureUrl())
	}
	insecure := plexUser{UUID: "u", Thumb: "http://plex.tv/a"}
	if resp := identity(&authResult{user: insecure}); resp.GetPictureUrl() != "" || strings.Contains(resp.String(), "http://plex.tv") {
		t.Fatal("non-https avatars must be dropped")
	}
}

func TestSignInRefusesAccountWithoutServerAccess(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/pins":
			_, _ = w.Write([]byte(`{"id":5,"code":"CODE"}`))
		case "/api/v2/pins/5":
			_, _ = w.Write([]byte(`{"id":5,"code":"CODE","authToken":"tok"}`))
		case "/api/v2/user":
			_, _ = w.Write([]byte(`{"uuid":"u-9","username":"stranger"}`))
		case "/api/v2/resources":
			_, _ = w.Write([]byte(`[{"clientIdentifier":"someone-elses-server","provides":"server"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer plex.Close()
	p := testProvider(plex)
	withAccess(t, p, Settings{}, "my-server")

	state := signedSiloState(t, "install-42")
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: state, RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-42/callback"})
	if err != nil {
		t.Fatal(err)
	}
	flowID := strings.SplitN(strings.SplitN(started.GetAuthorizeUrl(), "flow=", 2)[1], "&", 2)[0]
	query := mustStruct(t, map[string]any{"flow": flowID})
	page, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: query})
	if err != nil || page.GetStatusCode() != http.StatusOK {
		t.Fatalf("page=%v err=%v", page, err)
	}
	claim := claimFromPage(t, page)
	poll := &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {claim}}.Encode())}
	resp, err := p.Handle(context.Background(), poll)
	if err != nil || !strings.Contains(string(resp.GetBody()), `"status":"failed"`) || !strings.Contains(string(resp.GetBody()), "not_allowed") {
		t.Fatalf("stranger must be refused with a clear message: %v err=%v", resp, err)
	}
	exchange, _ := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: flowID, State: state, RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-42/callback"})
	if exchange.GetExternalSubject() != "" {
		t.Fatalf("refused account must not get an identity: %v", exchange)
	}
}

func TestDecide(t *testing.T) {
	yes, no := true, false
	server := []plexResource{{ClientIdentifier: "srv", Provides: "server"}}
	other := []plexResource{{ClientIdentifier: "other", Provides: "server"}}
	player := []plexResource{{ClientIdentifier: "srv", Provides: "player,client"}}
	// A server the account owns with the selected ID: only the connected
	// owner may use it, anyone else could have set that identifier.
	ownedCopy := []plexResource{{ClientIdentifier: "srv", Provides: "server", Owned: true}}
	owner := plexUser{UUID: "owner-uuid", Username: "owner"}
	alex := plexUser{UUID: "u-1", Username: "Alex", Email: "alex@example.test", Confirmed: &yes}
	unconfirmed := plexUser{UUID: "u-1", Username: "Alex", Email: "alex@example.test", Confirmed: &no}
	byName := []ManualEntry{{Input: "alex"}}
	byAt := []ManualEntry{{Input: "@alex"}}
	byEmail := []ManualEntry{{Input: "ALEX@example.test"}}
	byUUID := []ManualEntry{{Input: "old-name", UUID: "u-1"}}
	uuidOther := []ManualEntry{{Input: "alex", UUID: "u-2"}}

	allowedBy := func(r Rule) Decision { return Decision{Allowed: true, Rule: r} }
	refused := func(r ReasonCode) Decision { return Decision{Reason: r} }

	tests := []struct {
		name      string
		serverID  string
		manual    []ManualEntry
		user      plexUser
		resources []plexResource
		want      Decision
	}{
		{"nothing configured", "", nil, alex, server, refused(ReasonNotConfigured)},
		{"nothing configured refuses even a server user", "", nil, alex, nil, refused(ReasonNotConfigured)},
		{"no uuid", "srv", byName, plexUser{Username: "alex"}, server, refused(ReasonIneligible)},
		{"restricted", "srv", byName, plexUser{UUID: "u-1", Username: "alex", Restricted: true}, server, refused(ReasonIneligible)},
		{"guest", "srv", byName, plexUser{UUID: "u-1", Username: "alex", Guest: true}, server, refused(ReasonIneligible)},

		{"server: shared", "srv", nil, alex, server, allowedBy(RuleServer)},
		{"server: other server", "srv", nil, alex, other, refused(ReasonNotAllowed)},
		{"server: player is not the server", "srv", nil, alex, player, refused(ReasonNotAllowed)},
		{"server: own server with the same ID is not the owner's", "srv", nil, alex, ownedCopy, refused(ReasonNotAllowed)},
		{"server: connected owner", "srv", nil, owner, ownedCopy, allowedBy(RuleServer)},
		{"server: manual entry also allowed", "srv", byName, alex, server, allowedBy(RuleServer)},

		{"manual: username ignores case", "", byName, alex, nil, allowedBy(RuleManual)},
		{"manual: leading @", "", byAt, alex, nil, allowedBy(RuleManual)},
		{"manual: confirmed email", "", byEmail, alex, nil, allowedBy(RuleManual)},
		{"manual: unconfirmed email", "", byEmail, unconfirmed, nil, refused(ReasonNotAllowed)},
		{"manual: email with unknown confirmation", "", byEmail, plexUser{UUID: "u-1", Email: "alex@example.test"}, nil, refused(ReasonNotAllowed)},
		{"manual: stored uuid", "", byUUID, alex, nil, allowedBy(RuleManual)},
		{"manual: stored uuid wins over username", "", uuidOther, alex, nil, refused(ReasonNotAllowed)},
		{"manual: empty input never matches", "", []ManualEntry{{Input: " "}}, plexUser{UUID: "u-3"}, nil, refused(ReasonNotAllowed)},

		{"both: server", "srv", nil, alex, server, allowedBy(RuleServer)},
		{"both: manual without server access", "srv", byName, alex, other, allowedBy(RuleManual)},
		{"both: neither", "srv", []ManualEntry{{Input: "sam"}}, alex, other, refused(ReasonNotAllowed)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(Settings{Manual: tt.manual}, tt.serverID, "owner-uuid", tt.user, tt.resources)
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	if got := Decide(Settings{}, "", "", alex, []plexResource{{ClientIdentifier: "", Provides: "server"}}); got.Allowed {
		t.Fatal("no selected server must allow nobody through the server rule")
	}
}

func TestValidateInput(t *testing.T) {
	valid := map[string]string{
		"alex":              "alex",
		" @alex ":           "alex",
		"alex@example.test": "alex@example.test",
		"claire.l":          "claire.l",
		"user_42":           "user_42",
	}
	for in, want := range valid {
		if got, err := validateInput(in); err != nil || got != want {
			t.Errorf("validateInput(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{
		"", " ", "two words", "a@", "@", "a@b@c",
		strings.Repeat("a", 201),
		"0123456789abcdef0123",                 // Plex hex UUID
		"5f2b2e1c-2d4b-4f7a-9a1e-3b7c8d9e0f12", // dashed UUID
		"plex:0123456789abcdef",                // Silo subject
		"plex:alex",
		"12345678", // numeric Plex id
	} {
		if _, err := validateInput(in); !errors.Is(err, errInvalidEntry) {
			t.Errorf("validateInput(%q) must be refused, got %v", in, err)
		}
	}
}

func TestSettingsAddRemoveAndLearn(t *testing.T) {
	var s Settings
	if err := s.add(ManualEntry{Input: "alex"}); err != nil {
		t.Fatal(err)
	}
	if err := s.add(ManualEntry{Input: "ALEX"}); !errors.Is(err, errDuplicate) {
		t.Fatalf("duplicate input: %v", err)
	}
	if err := s.add(ManualEntry{Input: "sam", UUID: "u-9"}); err != nil {
		t.Fatal(err)
	}
	if err := s.add(ManualEntry{Input: "samuel", UUID: "U-9"}); !errors.Is(err, errDuplicate) {
		t.Fatalf("duplicate uuid: %v", err)
	}
	for i := len(s.Manual); i < maxManualEntries; i++ {
		if err := s.add(ManualEntry{Input: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.add(ManualEntry{Input: "one-too-many"}); !errors.Is(err, errListFull) {
		t.Fatalf("201st entry: %v", err)
	}
	if !s.remove("@Alex") || s.remove("alex") {
		t.Fatal("remove must delete exactly once")
	}

	learner := Settings{Manual: []ManualEntry{{Input: "alex"}}}
	user := plexUser{UUID: "u-1", Username: "alex", Title: "Alex M.", Thumb: "https://plex.tv/a.png"}
	if !learner.learn(user) {
		t.Fatal("first match must learn the uuid")
	}
	if e := learner.Manual[0]; e.UUID != "u-1" || e.Title != "Alex M." || e.Input != "alex" || e.Thumb != "https://plex.tv/a.png" {
		t.Fatalf("learned %+v", e)
	}
	if learner.learn(user) {
		t.Fatal("a known uuid is not learned again")
	}
	confirmed := true
	if !learner.learn(plexUser{UUID: "u-1", Username: "alex", Email: "alex@example.test", Confirmed: &confirmed}) {
		t.Fatal("a later sign-in must backfill the missing email")
	}
	if e := learner.Manual[0]; e.Email != "alex@example.test" {
		t.Fatalf("email not stored: %+v", e)
	}
	if learner.learn(plexUser{UUID: "u-1", Username: "alex", Email: "other@example.test"}) {
		t.Fatal("a stored email must not be replaced")
	}
	renamed := plexUser{UUID: "u-7", Username: "alex"}
	if Decide(Settings{Manual: learner.Manual}, "", "", renamed, nil).Allowed {
		t.Fatal("after learning, the username no longer matches another account")
	}
}

func TestReadiness(t *testing.T) {
	connected := plexConnection{ServerMachineID: "srv"}
	list := []ManualEntry{{Input: "alex"}}
	tests := []struct {
		name       string
		settings   Settings
		connection plexConnection
		want       Status
	}{
		{"nothing configured", Settings{}, plexConnection{}, Status{State: StateNotSetUp}},
		{"server access configured", Settings{}, connected, Status{State: StateReady}},
		{"manual access configured without Plex", Settings{Manual: list}, plexConnection{}, Status{State: StateReady}},
		{"server and manual access configured", Settings{Manual: list}, connected, Status{State: StateReady}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Readiness(tt.settings, tt.connection); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckAccountRevocation(t *testing.T) {
	var userStatus, resStatus atomic.Int32
	plex := plexAccountServer(t, `{"uuid":"u-1","username":"alex"}`, `[{"clientIdentifier":"srv","provides":"server"}]`, &userStatus, &resStatus)
	defer plex.Close()
	p := testProvider(plex)
	check := func() pluginv1.CheckAccountStatus {
		t.Helper()
		resp, err := p.CheckAccount(context.Background(), refreshState(t, "tok"))
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetStatus()
	}
	active, revoked := pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED
	steps := []struct {
		name     string
		settings Settings
		server   string
		want     pluginv1.CheckAccountStatus
	}{
		{"manual listed", Settings{Manual: []ManualEntry{{Input: "alex"}}}, "", active},
		{"manual removed", Settings{Manual: []ManualEntry{{Input: "sam"}}}, "", revoked},
		{"server shared", Settings{}, "srv", active},
		{"server unshared", Settings{}, "other", revoked},
		{"both by list", Settings{Manual: []ManualEntry{{Input: "u", UUID: "u-1"}}}, "other", active},
		{"both neither", Settings{}, "other", revoked},
		{"no rules left", Settings{}, "", revoked},
	}
	for _, step := range steps {
		withAccess(t, p, step.settings, step.server)
		if got := check(); got != step.want {
			t.Errorf("%s: got %v, want %v", step.name, got, step.want)
		}
	}
	store := withAccess(t, p, Settings{}, "srv")
	store.failReads = true
	if got := check(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("unreadable state must never revoke, got %v", got)
	}
}

func TestIdentityMapping(t *testing.T) {
	yes := true
	user := plexUser{
		UUID: "u-1", Username: "claire.l", Title: "Claire L.", Email: "claire@example.test",
		Confirmed: &yes, Thumb: "https://plex.tv/users/u-1/avatar",
	}
	resp := identity(&authResult{user: user, token: "tok"})
	if resp.GetExternalSubject() != "plex:u-1" ||
		resp.GetUsername() != "claire.l" ||
		resp.GetDisplayName() != "Claire L." ||
		resp.GetEmail() != "claire@example.test" ||
		!resp.GetEmailVerified() ||
		resp.GetPictureUrl() != "https://plex.tv/users/u-1/avatar" ||
		resp.GetIssuer() != plexAPI ||
		resp.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED ||
		len(resp.GetGroups()) != 0 ||
		resp.GetRefreshState().GetFields()["auth_token"].GetStringValue() != "tok" {
		t.Fatalf("identity = %v", resp)
	}
	if got := identity(&authResult{user: plexUser{UUID: "u", Username: "alex"}}).GetDisplayName(); got != "alex" {
		t.Fatalf("display name falls back to the username, got %q", got)
	}
	if got := identity(&authResult{user: plexUser{UUID: "u", Thumb: "https://evil.example/a.png"}}).GetPictureUrl(); got != "" {
		t.Fatalf("non-Plex avatar must be dropped, got %q", got)
	}
}

func TestManualMatchLearnsUUIDAtSignIn(t *testing.T) {
	plex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/pins":
			_, _ = w.Write([]byte(`{"id":5,"code":"CODE"}`))
		case "/api/v2/pins/5":
			_, _ = w.Write([]byte(`{"id":5,"code":"CODE","authToken":"tok"}`))
		case "/api/v2/user":
			_, _ = w.Write([]byte(`{"uuid":"u-5","username":"Alex","title":"Alex M."}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer plex.Close()
	p := testProvider(plex)
	state := signedSiloState(t, "install-42")
	started, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: state, RedirectUri: "https://media.example.test/api/v2/auth/oauth/install-42/callback"})
	if err != nil {
		t.Fatal(err)
	}
	flowID := strings.SplitN(strings.SplitN(started.GetAuthorizeUrl(), "flow=", 2)[1], "&", 2)[0]
	page, _ := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/plex/start", Query: mustStruct(t, map[string]any{"flow": flowID})})
	claim := claimFromPage(t, page)
	poll := &pluginv1.HandleHTTPRequest{Method: http.MethodPost, Path: "/plex/status", Body: []byte(url.Values{"flow": {flowID}, "claim": {claim}}.Encode())}
	if _, err := p.Handle(context.Background(), poll); err != nil {
		t.Fatal(err)
	}
	settings, err := p.loadSettings(context.Background())
	if err != nil || settings.Manual[0].UUID != "u-5" || settings.Manual[0].Title != "Alex M." {
		t.Fatalf("uuid not learned: %+v err=%v", settings.Manual, err)
	}
}
