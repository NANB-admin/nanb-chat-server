package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
)

// Login / phrase-restore lockout: anybody who knows a username can request a
// challenge for it, or post a bogus completion. Neither may invalidate the
// challenge the account's real owner is in the middle of answering.

// loginFixture creates "nass" with device dev-1 and returns its device key.
func loginFixture(t *testing.T) (*identity.Service, ed25519.PrivateKey) {
	t.Helper()
	svc, _, _ := newServiceForTest()
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = svc.CreateAccount(context.Background(), makeRequestWithDeviceKey(t, "nass", devPub))
	require.NoError(t, err)
	return svc, devPriv
}

func TestChallengeLockout_AnotherLoginChallengeDoesNotInvalidateTheOwners(t *testing.T) {
	svc, devPriv := loginFixture(t)
	ctx := context.Background()
	owners, _, err := svc.IssueChallenge(ctx, "nass", "dev-1")
	require.NoError(t, err)

	_, _, err = svc.IssueChallenge(ctx, "nass", "dev-1") // the attacker's request
	require.NoError(t, err)

	_, err = svc.CompleteSession(ctx, "nass", "dev-1", owners, ed25519.Sign(devPriv, owners))
	require.NoError(t, err)
}

func TestChallengeLockout_BogusLoginCompletionDoesNotConsumeTheOwners(t *testing.T) {
	svc, devPriv := loginFixture(t)
	ctx := context.Background()
	owners, _, err := svc.IssueChallenge(ctx, "nass", "dev-1")
	require.NoError(t, err)

	_, _ = svc.CompleteSession(ctx, "nass", "dev-1", make([]byte, 32), make([]byte, ed25519.SignatureSize))

	_, err = svc.CompleteSession(ctx, "nass", "dev-1", owners, ed25519.Sign(devPriv, owners))
	require.NoError(t, err)
}

func TestChallengeLockout_LoginChallengeIsSingleUse(t *testing.T) {
	svc, devPriv := loginFixture(t)
	ctx := context.Background()
	chal, _, err := svc.IssueChallenge(ctx, "nass", "dev-1")
	require.NoError(t, err)
	sig := ed25519.Sign(devPriv, chal)
	_, err = svc.CompleteSession(ctx, "nass", "dev-1", chal, sig)
	require.NoError(t, err)

	_, err = svc.CompleteSession(ctx, "nass", "dev-1", chal, sig)

	require.Error(t, err)
}

func TestChallengeLockout_AnotherRestoreChallengeDoesNotInvalidateTheOwners(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")
	ctx := context.Background()
	owners, _, err := svc.IssueRestoreChallenge(ctx, "nass")
	require.NoError(t, err)

	_, _, err = svc.IssueRestoreChallenge(ctx, "nass") // the attacker's request
	require.NoError(t, err)

	_, err = svc.CompleteRestoreSession(ctx, "nass", idPub, owners, ed25519.Sign(idPriv, owners), nil, nil)
	require.NoError(t, err)
}

func TestChallengeLockout_BogusRestoreCompletionDoesNotConsumeTheOwners(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")
	ctx := context.Background()
	owners, _, err := svc.IssueRestoreChallenge(ctx, "nass")
	require.NoError(t, err)

	_, _ = svc.CompleteRestoreSession(ctx, "nass", idPub, make([]byte, 32), make([]byte, ed25519.SignatureSize), nil, nil)

	_, err = svc.CompleteRestoreSession(ctx, "nass", idPub, owners, ed25519.Sign(idPriv, owners), nil, nil)
	require.NoError(t, err)
}

func TestChallengeLockout_RestoreChallengeIsSingleUse(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")
	ctx := context.Background()
	chal, _, err := svc.IssueRestoreChallenge(ctx, "nass")
	require.NoError(t, err)
	sig := ed25519.Sign(idPriv, chal)
	_, err = svc.CompleteRestoreSession(ctx, "nass", idPub, chal, sig, nil, nil)
	require.NoError(t, err)

	_, err = svc.CompleteRestoreSession(ctx, "nass", idPub, chal, sig, nil, nil)

	require.Error(t, err)
}
