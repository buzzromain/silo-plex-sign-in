package provider

// Interface text: every user-visible string comes from messagesEN.

import (
	"fmt"
	"time"
)

// Lang is a page language. The plugin's interface is English only; Lang is
// kept so pages and templates read every message from one catalogue and set
// the HTML lang attribute from it.
type Lang string

// English is the only interface language.
const English Lang = "en"

// T returns the message for key, or the key itself when it is not in the
// catalogue. Args are applied with fmt.Sprintf when given.
func (l Lang) T(key string, args ...any) string {
	message, ok := messagesEN[key]
	if !ok {
		return key
	}
	if len(args) == 0 {
		return message
	}
	return fmt.Sprintf(message, args...)
}

// RelativeTime renders how long ago t was, relative to now, in l.
func (l Lang) RelativeTime(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return l.T("time.now")
	case d < time.Hour:
		return l.T("time.minutes", int(d/time.Minute))
	case d < 24*time.Hour:
		return l.T("time.hours", int(d/time.Hour))
	default:
		return l.T("time.days", int(d/(24*time.Hour)))
	}
}
