CREATE UNIQUE INDEX accounts_username_lower_key
  ON identity_db.accounts (lower(username));

DROP INDEX IF EXISTS identity_db.accounts_username_active_idx;
CREATE INDEX accounts_username_active_idx
  ON identity_db.accounts (lower(username))
  WHERE deleted_at IS NULL;
