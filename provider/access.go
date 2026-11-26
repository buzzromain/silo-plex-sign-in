package provider

// Access rules: who may sign in, from the selected Plex server and the manual
// list, and validation of manual entries.

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Rule names what allowed an account to sign in.
type Rule string

// Rules.
const (
	RuleNone   Rule = ""
	RuleServer Rule = "server"
	RuleManual Rule = "manual"
)

// ReasonCode is a stable, untranslated code for a refused or failed sign-in.
type ReasonCode string

// Reason codes, shared by the status API, the error screens and activity.
const (
	ReasonNone            ReasonCode = ""
	ReasonNotAllowed      ReasonCode = "not_allowed"
	ReasonNotConfigured   ReasonCode = "not_configured"
	ReasonIneligible      ReasonCode = "ineligible"
	ReasonRejected        ReasonCode = "rejected"
	ReasonExpired         ReasonCode = "expired"
	ReasonClaimed         ReasonCode = "claimed"
	ReasonPlexUnavailable ReasonCode = "plex_unavailable"
)

// Limits on the manual list.
const (
	maxManualEntries  = 200
	maxEntryLength    = 200
	settingsVersion   = 1
	connectionVersion = 2
)

// Settings is everything the administrator chose. The Plex server identity
// lives in plexConnection so there is one source of truth for it. Everyone
// with access to that server may sign in, and the manual list adds people on
// top of it.
type Settings struct {
	Version int           `json:"version"`
	Manual  []ManualEntry `json:"manual"`
}

// ManualEntry is what the administrator typed, plus what the plugin learned
// about the Plex account from Plex or from its first sign-in.
type ManualEntry struct {
	Input    string    `json:"input"`
	UUID     string    `json:"uuid,omitempty"`
	Username string    `json:"username,omitempty"`
	Title    string    `json:"title,omitempty"`
	Email    string    `json:"email,omitempty"`
	Thumb    string    `json:"thumb,omitempty"`
	AddedAt  time.Time `json:"added_at"`
}

// Decision is the outcome of Decide.
type Decision struct {
	Allowed bool
	Rule    Rule       // which rule allowed the account
	Reason  ReasonCode // set when Allowed is false
}

// Decide says whether a Plex account may sign in. It never calls Plex:
// resources are the account's own Plex resources, fetched by the caller when
// a server is connected. serverID is the selected server's machine
// identifier, ownerUUID, and ownerID identify the server selected by the
// administrator. A server's people and the manual list are independent
// sources: matching either one allows the account.
func Decide(settings Settings, serverID, ownerUUID string, ownerID int64, user plexUser, resources []plexResource) Decision {
	switch {
	case serverID == "" && len(settings.Manual) == 0:
		return Decision{Reason: ReasonNotConfigured}
	case user.UUID == "", user.Restricted, user.Guest:
		return Decision{Reason: ReasonIneligible}
	case hasServer(resources, serverID, ownerUUID, ownerID, user):
		return Decision{Allowed: true, Rule: RuleServer}
	case matchManual(settings.Manual, user) >= 0:
		return Decision{Allowed: true, Rule: RuleManual}
	}
	return Decision{Reason: ReasonNotAllowed}
}

// hasServer reports whether resources include the selected Plex Media Server.
// Anyone can run a server and give it any identifier, so a server the signed-in
// account itself owns counts only when that account is the connected owner.
// Everyone else must see it as a server shared with them (owned is false).
func hasServer(resources []plexResource, serverID, ownerUUID string, ownerID int64, user plexUser) bool {
	if serverID == "" {
		return false
	}
	isOwner := ownerUUID != "" && strings.EqualFold(user.UUID, ownerUUID)
	for _, resource := range resources {
		if resource.ClientIdentifier != serverID || !isServerResource(resource) {
			continue
		}
		// A shared resource must identify the configured server owner. This
		// prevents a different account's registration with the same machine ID
		// from satisfying the rule. Older records without ownerID can still
		// authorize the connected owner, but cannot authorize shared users.
		if resource.OwnerID != 0 {
			if ownerID != 0 && resource.OwnerID == ownerID {
				return true
			}
			if isOwner && resource.OwnerID == user.ID {
				return true
			}
			continue
		}
		if isOwner && resource.Owned {
			return true
		}
	}
	return false
}

// ownsResource reports whether Plex attributes a resource to the account with
// this Plex id. "owned" is relative to the token that fetched the list and
// "ownerId" carries the same account id; either is enough when Plex sends it.
func ownsResource(resource plexResource, accountID int64) bool {
	if accountID != 0 && resource.OwnerID != 0 {
		return resource.OwnerID == accountID
	}
	return resource.Owned
}

// isServerResource reports whether a Plex resource is a media server. Plex
// normally advertises that in "provides", but some accounts see their own
// server registered as "controller" instead; the product name is then the
// remaining reliable signal.
func isServerResource(resource plexResource) bool {
	if resource.ClientIdentifier == "" {
		return false
	}
	return providesServer(resource.Provides) || strings.EqualFold(strings.TrimSpace(resource.Product), "Plex Media Server")
}

// providesServer reports whether a Plex resource's comma-separated "provides"
// list includes "server".
func providesServer(provides string) bool {
	for _, capability := range strings.Split(provides, ",") {
		if strings.TrimSpace(capability) == "server" {
			return true
		}
	}
	return false
}

// matchManual returns the index of the manual entry that matches user, or -1.
// An entry with a known UUID matches on the UUID only, because usernames can
// change hands. Otherwise its input matches the username or, when Plex
// confirmed it, the email.
func matchManual(entries []ManualEntry, user plexUser) int {
	for i, entry := range entries {
		if entry.UUID != "" {
			if user.UUID != "" && strings.EqualFold(entry.UUID, user.UUID) {
				return i
			}
			continue
		}
		input := normalizeInput(entry.Input)
		if input == "" {
			continue
		}
		if strings.EqualFold(input, user.Username) {
			return i
		}
		if user.Confirmed != nil && *user.Confirmed && strings.EqualFold(input, strings.TrimSpace(user.Email)) {
			return i
		}
	}
	return -1
}

// learn fills the UUID and display fields of the manual entry that matches
// user. A first match learns the identity; later matches only backfill a
// missing email, so a person added by username ends up with their address. It
// reports whether anything changed.
func (s *Settings) learn(user plexUser) bool {
	i := matchManual(s.Manual, user)
	if i < 0 || user.UUID == "" {
		return false
	}
	entry := &s.Manual[i]
	email := strings.TrimSpace(user.Email)
	if entry.UUID != "" {
		// Keep the displayed address current without erasing it when Plex
		// returns no email or only a case difference.
		if email == "" || strings.EqualFold(entry.Email, email) {
			return false
		}
		entry.Email = email
		return true
	}
	entry.UUID = user.UUID
	entry.Username = user.Username
	entry.Title = user.Title
	entry.Email = email
	entry.Thumb = safeAvatar(user.Thumb)
	return true
}

// Errors returned when a manual entry cannot be added.
var (
	errInvalidEntry   = errors.New("enter a Plex username or email")
	errDuplicate      = errors.New("already in the list")
	errServerAccess   = errors.New("already allowed by the Plex server")
	errPlexUnverified = errors.New("Plex could not confirm the user list")
	errListFull       = errors.New("the list is full")
)

var (
	uuidLike    = regexp.MustCompile(`(?i)^(plex:)?([0-9a-f]{16,40}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	numericLike = regexp.MustCompile(`^[0-9]+$`)
)

// looksLikeUUID reports whether value looks like a Plex account UUID rather
// than a username.
func looksLikeUUID(value string) bool { return uuidLike.MatchString(value) }

// normalizeInput trims value and drops a leading "@" from a username.
func normalizeInput(value string) string {
	value = strings.TrimSpace(value)
	if rest, ok := strings.CutPrefix(value, "@"); ok && !strings.Contains(rest, "@") {
		value = rest
	}
	return value
}

// validateInput checks what the administrator typed and returns it
// normalised. Only a Plex username or email is accepted.
func validateInput(value string) (string, error) {
	value = normalizeInput(value)
	if value == "" || len(value) > maxEntryLength || strings.ContainsFunc(value, unicode.IsSpace) {
		return "", errInvalidEntry
	}
	if looksLikeUUID(value) || numericLike.MatchString(value) || strings.HasPrefix(strings.ToLower(value), "plex:") {
		return "", errInvalidEntry
	}
	if strings.Contains(value, "@") {
		local, domain, _ := strings.Cut(value, "@")
		if local == "" || domain == "" || strings.Contains(domain, "@") {
			return "", errInvalidEntry
		}
	}
	return value, nil
}

// add appends entry to the manual list unless it is a duplicate (same input
// or same UUID) or the list is full.
func (s *Settings) add(entry ManualEntry) error {
	for _, existing := range s.Manual {
		if strings.EqualFold(normalizeInput(existing.Input), normalizeInput(entry.Input)) ||
			(entry.UUID != "" && strings.EqualFold(existing.UUID, entry.UUID)) {
			return errDuplicate
		}
	}
	if len(s.Manual) >= maxManualEntries {
		return errListFull
	}
	s.Manual = append(s.Manual, entry)
	return nil
}

// remove deletes the manual entry whose input matches input. It reports
// whether an entry was removed.
func (s *Settings) remove(input string) bool {
	for i, entry := range s.Manual {
		if strings.EqualFold(normalizeInput(entry.Input), normalizeInput(input)) {
			s.Manual = append(s.Manual[:i:i], s.Manual[i+1:]...)
			return true
		}
	}
	return false
}

// ReadyState is the readiness badge state on the admin page.
type ReadyState string

// Readiness states.
const (
	StateReady       ReadyState = "ready"
	StateNotSetUp    ReadyState = "not_set_up"
	StateUnavailable ReadyState = "unavailable"
)

// Status is the readiness of sign-in.
type Status struct {
	State ReadyState
}

// Readiness says whether anyone can sign in. An unreadable state is
// reported by the caller as StateUnavailable.
func Readiness(settings Settings, connection plexConnection) Status {
	if connection.ServerMachineID == "" && len(settings.Manual) == 0 {
		return Status{State: StateNotSetUp}
	}
	return Status{State: StateReady}
}
