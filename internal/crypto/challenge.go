package crypto

import (
	stdrand "crypto/rand"
	"io"
)

const ChallengeLen = 32

// ChallengeReader is the source of entropy for NewChallenge.
// Production uses crypto/rand.Reader; tests may override to exercise error paths.
var ChallengeReader io.Reader = stdrand.Reader

func NewChallenge() ([]byte, error) {
	buf := make([]byte, ChallengeLen)
	if _, err := io.ReadFull(ChallengeReader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
