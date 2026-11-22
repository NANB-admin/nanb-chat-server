CREATE TABLE identity_db.accounts (
    account_id        uuid PRIMARY KEY,
    username          text UNIQUE NOT NULL,
    identity_pub_key  bytea NOT NULL,
    display_name      text,
    avatar_url        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz
);

CREATE INDEX accounts_username_active_idx
  ON identity_db.accounts (username)
  WHERE deleted_at IS NULL;
