package provider

// Administrator pages: the Plex, Users and Activity tabs and their forms.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const (
	accessPath         = "/admin/access"
	peopleAddPath      = "/admin/people/add"
	peopleRemovePath   = "/admin/people/remove"
	activityAllowPath  = "/admin/activity/allow"
	activityExportPath = "/admin/activity/export"
	disconnectPath     = "/admin/plex/disconnect"
	maxFormSize        = 64 << 10
)

var noticeKeys = map[string]string{
	"added": "admin.notice.added", "removed": "admin.notice.removed",
	"connected": "admin.notice.connected", "disconnected": "admin.notice.disconnected",
	"error_state": "admin.notice.error_state", "error_input": "admin.error.invalid_entry",
	"plex_unavailable": "admin.notice.plex_unavailable", "flow_expired": "admin.notice.flow_expired",
	"already_listed": "admin.notice.already_listed", "busy": "admin.notice.busy",
	"ref_missing": "admin.notice.ref_missing",
}

// formToken returns the per-process secret embedded in every admin form. It is
// created on first use; a plugin restart invalidates forms already open.
func (p *Provider) formToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.formSecret == "" {
		p.formSecret, _ = randomID()
	}
	return p.formSecret
}

// adminForm parses an admin POST body and checks its form token, which protects
// the forms against cross-site requests. The int is the HTTP status: 200 when
// the form can be used.
func (p *Provider) adminForm(req *pluginv1.HandleHTTPRequest) (url.Values, int) {
	if len(req.GetBody()) > maxFormSize {
		return nil, http.StatusRequestEntityTooLarge
	}
	form, err := url.ParseQuery(string(req.GetBody()))
	if err != nil {
		return nil, http.StatusBadRequest
	}
	token := p.formToken()
	if token == "" || subtle.ConstantTimeCompare([]byte(form.Get("token")), []byte(token)) != 1 {
		return nil, http.StatusForbidden
	}
	return form, http.StatusOK
}

// adminRedirect answers a form POST with 303 See Other, so a reload does not
// submit the form again.
func adminRedirect(location string) *pluginv1.HandleHTTPResponse {
	resp := httpResponse(http.StatusSeeOther, contentTypeText, "")
	resp.Headers["Location"] = location
	return resp
}

// accessRedirect returns to the admin page on tab with a notice to display.
func accessRedirect(tab, notice string) *pluginv1.HandleHTTPResponse {
	return adminRedirect("../access?" + url.Values{"tab": {tab}, "notice": {notice}}.Encode())
}

// exportActivity answers GET /admin/activity/export with the retained
// decisions as CSV. It exposes only what the Activity tab already shows: no
// token, PIN, claim, email or lookup key.
func (p *Provider) exportActivity(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	if _, ok := requireAdmin(req); !ok {
		return httpResponse(http.StatusForbidden, contentTypeText, English.T("admin.forbidden"))
	}
	entries, err := p.loadActivity(ctx)
	if err != nil {
		logger.Warn("export activity", "error", err)
		return httpResponse(http.StatusInternalServerError, contentTypeText, English.T("admin.notice.error_state"))
	}
	var buf bytes.Buffer
	out := csv.NewWriter(&buf)
	_ = out.Write([]string{"ref", "at", "outcome", "rule", "reason", "plex_account_id", "username", "title"})
	for _, entry := range entries {
		_ = out.Write([]string{
			entry.Ref,
			entry.At.UTC().Format(time.RFC3339),
			entry.Outcome,
			string(entry.Rule),
			string(entry.Reason),
			entry.UUID,
			csvCell(entry.Username),
			csvCell(entry.Title),
		})
	}
	out.Flush()
	resp := httpResponse(http.StatusOK, "text/csv; charset=utf-8", buf.String())
	resp.Headers["Cache-Control"] = "no-store"
	resp.Headers["Content-Disposition"] = `attachment; filename="plex-sign-in-activity-` + time.Now().UTC().Format("20060102-150405") + `.csv"`
	return resp
}

// csvCell protects a spreadsheet from a Plex-provided value being read as a
// formula when the export is opened in Excel or a similar tool.
func csvCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// handleAdmin owns the Access, People and Activity forms. The route descriptor
// and this handler both require Silo administrator access.
func (p *Provider) handleAdmin(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	lang := English
	if _, ok := requireAdmin(req); !ok {
		return httpResponse(http.StatusForbidden, contentTypeText, lang.T("admin.forbidden"))
	}
	if req.GetPath() == accessPath {
		if req.GetMethod() != http.MethodGet {
			return httpResponse(http.StatusMethodNotAllowed, contentTypeText, "")
		}
		var query map[string]any
		if req.GetQuery() != nil {
			query = req.GetQuery().AsMap()
		}
		tab, _ := query["tab"].(string)
		notice, _ := query["notice"].(string)
		ref, _ := query["ref"].(string)
		show, _ := query["show"].(string)
		return p.renderAdmin(ctx, lang, adminInput{tab: tab, notice: noticeKeys[notice], ref: ref, show: show}, http.StatusOK)
	}
	if req.GetMethod() != http.MethodPost {
		return httpResponse(http.StatusMethodNotAllowed, contentTypeText, "")
	}
	form, status := p.adminForm(req)
	if status != http.StatusOK {
		return httpResponse(status, contentTypeText, lang.T("admin.form.invalid"))
	}
	if req.GetPath() == disconnectPath {
		err := p.saveConnection(ctx, plexConnection{})
		if err != nil {
			logger.Warn("save admin settings", "path", req.GetPath())
			return accessRedirect("access", "error_state")
		}
		return accessRedirect("access", "disconnected")
	}
	tab, notice := "access", "saved"
	var err error
	switch req.GetPath() {
	case peopleAddPath:
		tab, notice = "people", "added"
		err = p.addPerson(ctx, form.Get("input"))
	case peopleRemovePath:
		tab, notice = "people", "removed"
		err = p.updateSettings(ctx, func(s *Settings) error {
			for _, entry := range s.Manual {
				if entryKey(entry.Input) == form.Get("entry") {
					s.remove(entry.Input)
					return nil
				}
			}
			return errNoChange
		})
	case activityAllowPath:
		tab, notice = "activity", "added"
		err = p.allowRefusal(ctx, form.Get("ref"))
	default:
		return httpResponse(http.StatusNotFound, contentTypeText, "")
	}
	if err != nil {
		key := inputErrorKey(err)
		if key != "" && req.GetPath() == peopleAddPath {
			// Preserve non-sensitive input without putting it in the URL.
			return p.renderAdmin(ctx, lang, adminInput{tab: tab, fieldError: key, input: form.Get("input"), posting: true}, http.StatusUnprocessableEntity)
		}
		switch {
		case errors.Is(err, errDuplicate) && req.GetPath() == activityAllowPath:
			notice = "already_listed"
		case errors.Is(err, errInvalidEntry) && req.GetPath() == activityAllowPath:
			notice = "ref_missing"
		case key != "":
			notice = "error_input"
		default:
			logger.Warn("save admin settings", "path", req.GetPath())
			notice = "error_state"
		}
	}
	return accessRedirect(tab, notice)
}

// inputErrorKey maps a validation error to its message key, or "" when err is
// not a validation error.
func inputErrorKey(err error) string {
	switch {
	case errors.Is(err, errInvalidEntry):
		return "admin.error.invalid_entry"
	case errors.Is(err, errDuplicate):
		return "admin.error.duplicate"
	case errors.Is(err, errServerAccess):
		return "admin.error.server_access"
	case errors.Is(err, errPlexUnverified):
		return "admin.error.plex_unverified"
	case errors.Is(err, errListFull):
		return "admin.error.list_full"
	default:
		return ""
	}
}

// entryKey identifies a manual entry in forms without echoing the raw input.
func entryKey(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// addPerson validates value and adds it to the manual list, enriched with the
// Plex identity when the owner's directory knows the person.
func (p *Provider) addPerson(ctx context.Context, value string) error {
	input, err := validateInput(value)
	if err != nil {
		return err
	}
	_, connection, err := p.accessState(ctx)
	if err != nil {
		return err
	}
	entry := ManualEntry{Input: input, AddedAt: time.Now().UTC()}
	directory, complete := p.loadDirectory(ctx, connection)
	// With a connected server, a manual entry is only added once Plex has
	// confirmed the person does not already have access through it.
	if connection.ServerMachineID != "" && connection.OwnerToken != "" && !complete {
		return errPlexUnverified
	}
	if person, ok := directoryMatch(input, directory); ok {
		// The owner and users shared on the selected server already sign in
		// through the server; a manual entry would be a second, hidden rule.
		if connection.ServerMachineID != "" && serverAccess(person) {
			return errServerAccess
		}
		entry.UUID, entry.Username, entry.Title = person.UUID, person.Username, person.Title
		entry.Email, entry.Thumb = strings.TrimSpace(person.Email), person.Thumb
	}
	return p.updateSettings(ctx, func(s *Settings) error { return s.add(entry) })
}

// allowRefusal adds the person behind a refused sign-in to the manual list. ref
// is the reference shown to that person; only a not_allowed decision with a
// Plex UUID can be allowed this way.
func (p *Provider) allowRefusal(ctx context.Context, ref string) error {
	activity, err := p.loadActivity(ctx)
	if err != nil {
		return err
	}
	for _, row := range activity {
		if row.Ref != ref || row.Reason != ReasonNotAllowed || row.UUID == "" {
			continue
		}
		input := row.Username
		if input == "" {
			input = row.UUID
		} // UUID came from Plex, not the form.
		entry := ManualEntry{Input: input, UUID: row.UUID, Username: row.Username, Title: row.Title, Thumb: row.Thumb, AddedAt: time.Now().UTC()}
		return p.updateSettings(ctx, func(s *Settings) error {
			if matchManual(s.Manual, plexUser{UUID: row.UUID, Username: row.Username}) >= 0 {
				return errDuplicate
			}
			return s.add(entry)
		})
	}
	return errInvalidEntry
}

// adminInput is what one admin request asks to show: the tab, a notice, a
// form error with the rejected input, the reference to highlight and the
// activity filter.
type adminInput struct {
	tab, notice, fieldError, input, ref string
	show                                string
	posting                             bool
}

// adminPage is the data rendered by the admin templates.
type adminPage struct {
	Lang                                                           Lang
	T                                                              func(string, ...any) string
	CSP, Assets, Token, Tab, Notice, FieldError, Input, Ref, Empty string
	AccessStatus                                                   Status
	ServerName, ServerID, Checked                                  string
	PlexServer, Connected, FromPost                                bool
	HasActivity, RefusedOnly                                       bool
	ActivityLimit, IncompleteLimit, ManualCount, RetentionDays     int
	DirectoryPartial, RefNotFound                                  bool
	People, Suggestions                                            []personRow
	ShowFilter                                                     bool
	Activity                                                       []activityRow
	Refusals                                                       int
}

// personRow is one person on the People tab.
type personRow struct {
	Name, Username, Email, Thumb, Entry, Subject string
	Tags                                         []string
	Cannot, Managed, Redundant, Anonymous        bool
	rank                                         int
}

// activityRow is one access decision on the Activity tab.
type activityRow struct {
	Person                                         personRow
	Ref, When, Absolute, DateTime, Result          string
	Status, Detail                                 string
	Allowed, Allow, Highlight, Interrupted, Listed bool
}

// renderAdmin keeps the tabs server-rendered; Plex is only contacted when a
// selected view needs the directory and an owner connection is available.
func (p *Provider) renderAdmin(ctx context.Context, lang Lang, in adminInput, status int) *pluginv1.HandleHTTPResponse {
	tab := in.tab
	if tab != "people" && tab != "activity" {
		tab = "access"
	}
	now := time.Now().UTC()
	settings, connection, err := p.accessState(ctx)
	data := adminPage{Lang: lang, T: lang.T, CSP: metaContentSecurityPolicy, Assets: assetsBase, Token: p.formToken(),
		Tab: tab, Notice: in.notice, FieldError: in.fieldError, FromPost: in.posting,
		AccessStatus: Readiness(settings, connection), ServerID: connection.ServerMachineID,
		ServerName: publicName(connection.ServerName), PlexServer: connection.ServerMachineID != "",
		Connected: connection.OwnerToken != "" || connection.ServerMachineID != ""}
	if data.FromPost {
		data.Assets = "../../assets/"
	}
	if err != nil {
		data.AccessStatus = Status{State: StateUnavailable}
		data.Notice = noticeKeys["error_state"]
	}
	data.ManualCount = len(settings.Manual)
	if checked, err := time.Parse(time.RFC3339, connection.UpdatedAt); err == nil {
		data.Checked = lang.RelativeTime(checked, now)
	}
	activity, activityErr := p.loadActivity(ctx)
	if activityErr != nil && data.Notice == "" {
		data.Notice = noticeKeys["error_state"]
	}
	for _, entry := range activity {
		// Only a "not allowed" refusal can be settled by the manual list.
		covered := entry.Reason == ReasonNotAllowed && manualCovers(entry, settings)
		if isAccessRefusal(entry) && now.Sub(entry.At) <= 7*24*time.Hour && !covered {
			data.Refusals++
		}
	}
	if in.posting {
		trimmed := strings.TrimSpace(in.input)
		if strings.HasPrefix(trimmed, "@") {
			trimmed = normalizeInput(trimmed)
		}
		data.Input = publicName(trimmed)
	}
	switch tab {
	case "people":
		directory, complete := p.loadDirectory(ctx, connection)
		data.DirectoryPartial = connection.OwnerToken != "" && !complete
		data.People, data.Suggestions = peopleRows(lang, settings, data.PlexServer, directory)
		data.Empty = "admin.people.empty"
		data.ShowFilter = len(data.People) > 8
	case "activity":
		data.HasActivity, data.ActivityLimit, data.IncompleteLimit = len(activity) > 0, maxActivity, maxAnonymous
		data.RetentionDays = int(activityRetention.Hours() / 24)
		data.Ref = formatRef(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(in.ref), "-", "")))
		data.RefusedOnly = in.show == "refused"
		data.Activity = activityRows(lang, settings, activity, in.ref, now)
		if data.RefusedOnly {
			refused := data.Activity[:0]
			for _, row := range data.Activity {
				if !row.Allowed && !row.Interrupted {
					refused = append(refused, row)
				}
			}
			data.Activity = refused
		}
		if in.ref != "" {
			data.RefNotFound = true
			for _, row := range data.Activity {
				if row.Highlight {
					data.RefNotFound = false
				}
			}
		}
	}
	return renderPage(status, "admin_layout.html", data)
}

// managedHomeProfile reports whether person is a managed Plex Home profile:
// a profile without its own plex.tv account.
func managedHomeProfile(person plexDirectoryUser) bool {
	return person.Home && !person.Owner && person.Restricted
}

// serverAccess reports whether person signs in through the connected server:
// its owner, a user it is shared with, or a Plex Home member with an account.
func serverAccess(person plexDirectoryUser) bool {
	return person.Owner || person.Shared || (person.Home && !person.Restricted && !person.Guest)
}

// loadDirectory returns the owner's Plex directory and whether Plex answered
// every part of it (owner, Home and shared users).
func (p *Provider) loadDirectory(ctx context.Context, c plexConnection) ([]plexDirectoryUser, bool) {
	if c.OwnerToken == "" {
		return nil, false
	}
	users, warnings, err := p.fetchPlexDirectory(ctx, c.OwnerToken, c.ServerMachineID)
	if err != nil || len(warnings) != 0 {
		logger.Warn("Plex directory partially unavailable")
		return users, false
	}
	return users, true
}

// plexPerson builds the name, username and avatar shown for a person, hiding a
// username identical to the name and falling back to "Unknown".
func plexPerson(lang Lang, title, username, thumb string) personRow {
	name, username := publicName(title), publicName(username)
	if name == username {
		username = ""
	}
	if name == "" {
		name = username
		username = ""
	}
	if name == "" {
		name = lang.T("admin.people.unknown")
	}
	return personRow{Name: name, Username: username, Thumb: thumb}
}

// visibleEmail returns value when it looks like a single email address, so a
// username is never displayed as an email.
func visibleEmail(value string) string {
	value = strings.TrimSpace(value)
	local, domain, ok := strings.Cut(value, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(strings.Fields(value)) != 1 {
		return ""
	}
	return value
}

// peopleRows builds the People tab: rows for everyone who may sign in (server
// users and manual entries) and suggestions of directory users without
// access.
func peopleRows(lang Lang, s Settings, hasPlexServer bool, directory []plexDirectoryUser) ([]personRow, []personRow) {
	var rows, suggestions []personRow
	used := make(map[int]bool)
	account := func(row *personRow, uuid string) {
		if uuid != "" {
			row.Subject = "plex:" + uuid
		}
	}
	for _, person := range directory {
		i := matchManual(s.Manual, person.plexUser)
		if i < 0 { // display already-stored entries whose email was learned by the owner directory
			for j, e := range s.Manual {
				if e.UUID == "" && directoryInputMatches(e.Input, person) {
					i = j
					break
				}
			}
		}
		// Managed Plex Home profiles have no plex.tv account and can never sign
		// in, so they are not listed. A manual entry pointing at one still
		// shows below, as a plain manual row, so it can be removed.
		if managedHomeProfile(person) {
			continue
		}
		server := hasPlexServer && serverAccess(person)
		row := plexPerson(lang, person.Title, person.Username, person.Thumb)
		row.Email = visibleEmail(person.Email)
		if strings.EqualFold(row.Email, row.Username) {
			row.Email = ""
		}
		row.Cannot = person.Restricted || person.Guest || person.UUID == ""
		if !server && i < 0 {
			if hasPlexServer && !row.Cannot && len(suggestions) < 8 && i < 0 && publicName(person.Username) != "" {
				if input, err := validateInput(person.Username); err == nil {
					row.Entry = input
					suggestions = append(suggestions, row)
				}
			}
			continue
		}
		row.rank = 3
		if server {
			row.Managed, row.rank = true, 2
			if person.Owner {
				row.Tags = append(row.Tags, "owner")
				row.rank = 0
			}
			if person.Home && row.rank > 1 {
				row.rank = 1
			}
			row.Tags = append(row.Tags, "server")
		}
		if i >= 0 {
			used[i] = true
			row.Entry = entryKey(s.Manual[i].Input)
			row.Tags = append(row.Tags, "manual")
			row.Redundant = server
			if row.Email == "" {
				row.Email = visibleEmail(s.Manual[i].Email)
			}
			if row.Email == "" {
				row.Email = visibleEmail(s.Manual[i].Input)
			}
		}
		account(&row, person.UUID)
		rows = append(rows, row)
	}
	{
		for i, e := range s.Manual {
			if used[i] {
				continue
			}
			row := plexPerson(lang, e.Title, e.Username, e.Thumb)
			row.Email = visibleEmail(e.Email)
			if row.Email == "" {
				row.Email = visibleEmail(e.Input)
			}
			if strings.EqualFold(row.Email, row.Username) {
				row.Email = ""
			}
			if e.Title == "" && e.Username == "" {
				row.Name = publicName(e.Input)
				if row.Name == "" || strings.EqualFold(e.Input, e.UUID) {
					row.Name = lang.T("admin.people.unknown")
				}
				if e.UUID == "" {
					row.Username = lang.T("admin.people.waiting")
				}
			}
			row.rank, row.Entry, row.Tags = 3, entryKey(e.Input), []string{"manual"}
			account(&row, e.UUID)
			rows = append(rows, row)
		}
	}
	slices.SortStableFunc(rows, func(a, b personRow) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return rows, suggestions
}

// isAccessRefusal reports whether entry is an access decision that refused
// the account. Expired, reused or Plex-rejected flows are interrupted
// sign-ins: nobody was refused, so they are not counted as refusals.
func isAccessRefusal(e ActivityEntry) bool {
	switch e.Reason {
	case ReasonNotAllowed, ReasonIneligible, ReasonNotConfigured:
		return e.Outcome == outcomeRefuse
	}
	return false
}

// manualCovers reports whether a manual entry now grants access to the account
// behind a decision. Entries bound to a Plex account match by account ID only;
// entries still waiting for their first sign-in match by username or by the
// confirmed email, through the opaque lookup keys stored with the decision.
func manualCovers(e ActivityEntry, s Settings) bool {
	for _, entry := range s.Manual {
		if entry.UUID != "" {
			if e.UUID != "" && strings.EqualFold(entry.UUID, e.UUID) {
				return true
			}
			continue
		}
		if e.NameKey != "" && decisionKey(entry.Input) == e.NameKey {
			return true
		}
		if e.EmailKey != "" && (emailDecisionKey(entry.Input) == e.EmailKey || emailDecisionKey(entry.Email) == e.EmailKey) {
			return true
		}
	}
	return false
}

// activityRows builds the Activity tab rows in stored order. ref highlights the
// decision an administrator opened from a refusal reference.
func activityRows(lang Lang, s Settings, entries []ActivityEntry, ref string, now time.Time) []activityRow {
	var rows []activityRow
	for _, e := range entries {
		row := activityRow{Person: plexPerson(lang, e.Title, e.Username, e.Thumb), Ref: e.Ref,
			When: lang.RelativeTime(e.At, now), Absolute: e.At.UTC().Format("2006-01-02 15:04 UTC"), DateTime: e.At.UTC().Format(time.RFC3339),
			Highlight: strings.EqualFold(e.Ref, strings.ReplaceAll(ref, "-", ""))}
		if e.UUID == "" && publicName(e.Title) == "" && publicName(e.Username) == "" {
			// No Plex account was identified (e.g. an abandoned request):
			// show that plainly rather than as a person named "Unknown".
			row.Person = personRow{Name: lang.T("admin.activity.unknown"), Anonymous: true}
		}
		if e.Outcome == outcomeAllow {
			row.Allowed, row.Status, row.Detail = true, lang.T("admin.activity.signed_in"), lang.T("admin.tag."+string(e.Rule))
			row.Result = row.Status + " · " + row.Detail
		} else {
			row.Status, row.Detail = lang.T("admin.activity.refused"), lang.T("reason."+string(e.Reason))
			if !isAccessRefusal(e) {
				row.Interrupted, row.Status = true, lang.T("admin.activity.interrupted")
			}
			row.Result = row.Status + " · " + row.Detail
			if e.Reason == ReasonNotAllowed && e.UUID != "" {
				// A refused person added to the manual list afterwards can
				// now sign in: say so instead of offering the action again.
				listed := manualCovers(e, s)
				row.Allow, row.Listed = !listed, listed
			}
		}
		rows = append(rows, row)
	}
	return rows
}
