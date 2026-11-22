package crypto_test

import (
	"errors"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/crypto"
)

func TestNewChallenge_HasCorrectLength(t *testing.T) {
	c, err := crypto.NewChallenge()

	assert.NoError(t, err)
	assert.Len(t, c, crypto.ChallengeLen)
}

func TestNewChallenge_IsRandom(t *testing.T) {
	a, err := crypto.NewChallenge()
	assert.NoError(t, err)

	b, err := crypto.NewChallenge()
	assert.NoError(t, err)

	assert.NotEqual(t, a, b)
}

func TestNewChallenge_PropagatesReaderError(t *testing.T) {
	orig := crypto.ChallengeReader
	t.Cleanup(func() { crypto.ChallengeReader = orig })
	crypto.ChallengeReader = iotest.ErrReader(errors.New("boom"))

	_, err := crypto.NewChallenge()
	assert.Error(t, err)
}
