package identity

import (
	"errors"
	"regexp"
	"strings"
)

var ErrUsernameInvalid = errors.New("username invalid")

const (
	UsernameMinLen = 3
	UsernameMaxLen = 32
)

var usernameRegexp = regexp.MustCompile(`^[a-z0-9_-]+$`)

// NormalizeUsername is the canonical stored/looked-up form: users may type any
// case, but usernames are always lowercase. Applied at the HTTP boundary so
// ValidateUsername stays strict and every lookup sees one spelling.
func NormalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

func ValidateUsername(u string) error {
	if len(u) < UsernameMinLen || len(u) > UsernameMaxLen {
		return ErrUsernameInvalid
	}
	if !usernameRegexp.MatchString(u) {
		return ErrUsernameInvalid
	}
	return nil
}
