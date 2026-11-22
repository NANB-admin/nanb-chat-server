DROP INDEX IF EXISTS identity_db.accounts_username_active_idx;
CREATE INDEX accounts_username_active_idx
  ON identity_db.accounts (username)
  WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS identity_db.accounts_username_lower_key;
