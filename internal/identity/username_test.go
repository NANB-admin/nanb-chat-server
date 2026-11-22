package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/identity"
)

func TestValidateUsername_AcceptsLegalUsername(t *testing.T) {
	assert.NoError(t, identity.ValidateUsername("nass"))
	assert.NoError(t, identity.ValidateUsername("abc_123"))
	assert.NoError(t, identity.ValidateUsername("a-b-c"))
	assert.NoError(t, identity.ValidateUsername("xyz"))
}

func TestValidateUsername_AcceptsMaxLength(t *testing.T) {
	assert.NoError(t, identity.ValidateUsername("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) // 32 chars
}

func TestValidateUsername_RejectsTooShort(t *testing.T) {
	err := identity.ValidateUsername("ab")
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}

func TestValidateUsername_RejectsTooLong(t *testing.T) {
	err := identity.ValidateUsername("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 33 chars
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}

func TestValidateUsername_RejectsUppercase(t *testing.T) {
	err := identity.ValidateUsername("Nass")
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}

func TestNormalizeUsername_LowercasesAndTrims(t *testing.T) {
	assert.Equal(t, "nassj", identity.NormalizeUsername("  NassJ "))
}

func TestValidateUsername_RejectsSpaces(t *testing.T) {
	err := identity.ValidateUsername("na ss")
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}

func TestValidateUsername_RejectsPunctuation(t *testing.T) {
	err := identity.ValidateUsername("nass.j")
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}

func TestValidateUsername_RejectsEmpty(t *testing.T) {
	err := identity.ValidateUsername("")
	assert.ErrorIs(t, err, identity.ErrUsernameInvalid)
}
