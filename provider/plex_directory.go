package provider

// Plex directory: the people the connected owner account can see, used to
// suggest and enrich manual entries.

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// plexDirectoryUser is a person discovered with the owner's Plex connection.
type plexDirectoryUser struct {
	plexUser
	Owner, Home, Shared bool
}

// fetchPlexDirectory merges the owner, Plex Home members and shared users into
// one list, de-duplicated by Plex UUID (or username) and sorted by username.
// A source that fails is skipped and named in warnings, so the admin page can
// say the list may be incomplete.
func (p *Provider) fetchPlexDirectory(ctx context.Context, token, serverID string) ([]plexDirectoryUser, []string, error) {
	if token == "" {
		return nil, nil, errors.New("no Plex owner connection")
	}
	var users []plexDirectoryUser
	var warnings []string
	seen := make(map[string]int)
	add := func(user plexUser, owner, home, shared bool) {
		key := strings.ToLower(user.UUID)
		if key == "" {
			key = "name:" + strings.ToLower(user.Username)
		}
		if key == "name:" {
			return
		}
		if i, ok := seen[key]; ok {
			old := &users[i]
			old.Owner = old.Owner || owner
			old.Home = old.Home || home
			old.Shared = old.Shared || shared
			if old.Email == "" {
				old.Email, old.Confirmed = user.Email, user.Confirmed
			}
			old.Restricted, old.Guest = old.Restricted || user.Restricted, old.Guest || user.Guest
			return
		}
		user.Thumb = safeAvatar(user.Thumb)
		seen[key] = len(users)
		users = append(users, plexDirectoryUser{plexUser: user, Owner: owner, Home: home, Shared: shared})
	}
	if user, err := p.fetchUser(ctx, token); err == nil {
		add(*user, true, false, false)
	} else {
		warnings = append(warnings, "owner")
	}
	if home, err := p.fetchHomeUsers(ctx, token); err == nil {
		for _, user := range home {
			add(user, false, true, false)
		}
	} else {
		warnings = append(warnings, "home")
	}
	if shared, err := p.fetchSharedServerUsers(ctx, token, serverID); err == nil {
		for _, user := range shared {
			add(user.plexUser, false, false, user.Shared)
		}
	} else {
		warnings = append(warnings, "shared")
	}
	slices.SortStableFunc(users, func(a, b plexDirectoryUser) int {
		return strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username))
	})
	return users, warnings, nil
}

// directoryInputMatches reports whether an administrator's input names person,
// by username or, when Plex confirmed it, email, ignoring case. This is the
// same rule as matchManual, so an unconfirmed email never binds an entry to
// an account.
func directoryInputMatches(input string, person plexDirectoryUser) bool {
	input = normalizeInput(input)
	if input == "" {
		return false
	}
	if strings.EqualFold(input, person.Username) {
		return true
	}
	confirmed := person.Confirmed != nil && *person.Confirmed
	return confirmed && strings.EqualFold(input, strings.TrimSpace(person.Email))
}

// directoryMatch returns the only directory entry matching input. An ambiguous
// input that matches several people returns no match.
func directoryMatch(input string, users []plexDirectoryUser) (plexDirectoryUser, bool) {
	var match plexDirectoryUser
	var found bool
	for _, person := range users {
		if !directoryInputMatches(input, person) {
			continue
		}
		if found {
			return plexDirectoryUser{}, false
		}
		match, found = person, true
	}
	return match, found
}
