-- Unidentified access (sealed sender Phase 2): an account publishes a COMMITMENT
-- to its unidentified-access key (UAK = H(UAK)), never the UAK itself. The UAK is
-- a high-entropy secret the account shares with its contacts over the E2EE
-- channel; a contact presents the raw UAK on the unauthenticated sealed-send path
-- and the server checks H(presented) == this commitment, proving the sender is an
-- authorized contact WITHOUT learning which one (all of the recipient's contacts
-- present the same value). Nullable: NULL = the account has not enabled
-- unidentified access, so the sealed-unauth path is unavailable for it and senders
-- fall back to the authenticated path. A breach of this column yields only the
-- hash, not the UAK, so it cannot be used to forge sends.
ALTER TABLE identity_db.accounts
  ADD COLUMN uak_commitment bytea;
