-- The identity key is derived from the recovery phrase; two active accounts
-- sharing one means two users picked the same phrase and restore would be
-- ambiguous. Partial (active rows only): a deleted account's key may be
-- re-registered, matching the service-level IdentityPubKeyInUse check.
--
-- DEPLOY NOTE: this index build is NOT CONCURRENTLY (golang-migrate runs each
-- migration in a txn), so it takes a brief write lock on `accounts` and, more
-- importantly, will FAIL if any live duplicate identity keys already exist.
-- Before applying on an environment with real data, confirm there are none:
--   SELECT identity_pub_key, count(*) FROM identity_db.accounts
--    WHERE deleted_at IS NULL GROUP BY 1 HAVING count(*) > 1;
-- (Nothing enforced this before, so a legacy dataset could contain dups.)
CREATE UNIQUE INDEX accounts_identity_pub_key_active
    ON identity_db.accounts (identity_pub_key)
    WHERE deleted_at IS NULL;
