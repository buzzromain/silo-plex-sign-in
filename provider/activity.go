package provider

// Activity log: the latest access decisions with their references, kept in
// Silo instance state.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	activityKey       = "plex/activity/v1"
	activityVersion   = 1
	maxActivity       = 100
	activityRetention = 30 * 24 * time.Hour // how long a decision stays visible
	maxAnonymous      = 20                  // entries with no account; anyone can trigger them
	refAlphabet       = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	refLength         = 6
	outcomeAllow      = "allowed"
	outcomeRefuse     = "refused"
)

// activityFile is the stored activity document. The version field lets a
// later release migrate entries instead of reading an unknown format.
type activityFile struct {
	Version int             `json:"version"`
	Entries []ActivityEntry `json:"entries"`
}

// ActivityEntry is one final sign-in decision. It never holds a token, PIN
// code, claim, email or IP address: the username and confirmed email are
// reduced to opaque lookup keys used to match the attempt with the manual
// list. A key is a matching aid, not anonymisation: a short address stays
// guessable by dictionary.
type ActivityEntry struct {
	Ref      string     `json:"ref"`
	At       time.Time  `json:"at"`
	Outcome  string     `json:"outcome"`
	Rule     Rule       `json:"rule,omitempty"`
	Reason   ReasonCode `json:"reason,omitempty"`
	UUID     string     `json:"uuid,omitempty"`
	Username string     `json:"username,omitempty"`
	Title    string     `json:"title,omitempty"`
	Thumb    string     `json:"thumb,omitempty"`
	NameKey  string     `json:"name_key,omitempty"`
	EmailKey string     `json:"email_key,omitempty"`
}

// newRef returns a random six-character reference without look-alike
// characters. It identifies an activity entry; it is not a secret.
func newRef() string {
	b := make([]byte, refLength)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err)) // never fails on supported platforms
	}
	for i := range b {
		b[i] = refAlphabet[int(b[i])%len(refAlphabet)]
	}
	return string(b)
}

// newActivity builds the entry for a decision about user.
func newActivity(ref string, decision Decision, user plexUser) ActivityEntry {
	entry := ActivityEntry{
		Ref:      ref,
		At:       time.Now().UTC(),
		Outcome:  outcomeRefuse,
		Reason:   decision.Reason,
		UUID:     user.UUID,
		Username: publicName(user.Username),
		Title:    publicName(user.Title),
		Thumb:    safeAvatar(user.Thumb),
		NameKey:  decisionKey(user.Username),
	}
	if user.Confirmed != nil && *user.Confirmed {
		entry.EmailKey = emailDecisionKey(user.Email)
	}
	if decision.Allowed {
		entry.Outcome, entry.Rule, entry.Reason = outcomeAllow, decision.Rule, ReasonNone
	}
	return entry
}

// decisionKey is a stable lookup key for a Plex username. The activity log
// keeps it so an administrator's later manual entry can be matched to a
// decision without storing the name itself.
func decisionKey(value string) string {
	return hashKey(strings.ToLower(normalizeInput(value)))
}

// emailDecisionKey is decisionKey for a single email address, and empty for
// anything else so a username is never confused with an address.
func emailDecisionKey(value string) string {
	value = strings.TrimSpace(value)
	if visibleEmail(value) == "" {
		return ""
	}
	return hashKey(strings.ToLower(value))
}

// hashKey returns the hexadecimal SHA-256 of value, or "" for empty input.
func hashKey(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// pushActivity puts entry first and keeps at most maxActivity entries.
func pushActivity(entries []ActivityEntry, entry ActivityEntry) []ActivityEntry {
	entries = append([]ActivityEntry{entry}, pruneActivity(entries, time.Now())...)
	// Untrusted failures can be triggered by anyone, even when a valid but
	// expired flow reveals an account UUID. Keep only the newest few so they
	// never push out genuine access decisions.
	untrusted := 0
	kept := entries[:0]
	for _, e := range entries {
		if e.UUID == "" || e.Reason == ReasonExpired || e.Reason == ReasonClaimed {
			if untrusted++; untrusted > maxAnonymous {
				continue
			}
		}
		kept = append(kept, e)
	}
	entries = kept
	if len(entries) > maxActivity {
		entries = entries[:maxActivity]
	}
	return entries
}

// pruneActivity drops decisions older than activityRetention. The journal is a
// support view, not a permanent audit log.
func pruneActivity(entries []ActivityEntry, now time.Time) []ActivityEntry {
	kept := entries[:0]
	for _, entry := range entries {
		if now.Sub(entry.At) <= activityRetention {
			kept = append(kept, entry)
		}
	}
	return kept
}

// recordActivity stores entry and logs the decision. A storage failure is
// logged and never blocks sign-in.
func (p *Provider) recordActivity(ctx context.Context, entry ActivityEntry) {
	logger.Info("sign-in decision", "ref", entry.Ref, "outcome", entry.Outcome, "rule", entry.Rule, "reason", entry.Reason)
	err := p.update(ctx, activityKey, func(current []byte, found bool) ([]byte, error) {
		var entries []ActivityEntry
		if found && len(current) > 0 {
			var err error
			if entries, err = decodeActivity(current); err != nil {
				return nil, err
			}
		}
		return json.Marshal(activityFile{Version: activityVersion, Entries: pushActivity(entries, entry)})
	})
	if err != nil {
		logger.Warn("record activity", "ref", entry.Ref, "error", err)
	}
}

// loadActivity returns the stored activity, newest first.
func (p *Provider) loadActivity(ctx context.Context) ([]ActivityEntry, error) {
	raw, found, err := p.readRaw(ctx, activityKey)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	entries, err := decodeActivity(raw)
	if err != nil {
		return nil, err
	}
	return pruneActivity(entries, time.Now()), nil
}

// decodeActivity reads the versioned document, and the bare array written by
// releases before the document carried a version.
func decodeActivity(raw []byte) ([]ActivityEntry, error) {
	var file activityFile
	if err := json.Unmarshal(raw, &file); err == nil && file.Version != 0 {
		if file.Version != activityVersion {
			return nil, fmt.Errorf("unsupported activity version %d (want %d)", file.Version, activityVersion)
		}
		return file.Entries, nil
	}
	var entries []ActivityEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("decode activity: %w", err)
	}
	return entries, nil
}
