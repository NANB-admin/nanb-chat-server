CREATE TABLE identity_db.devices (
    device_id        uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES identity_db.accounts(account_id) ON DELETE CASCADE,
    device_pub_key   bytea NOT NULL,
    display_name     text,
    linked_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at       timestamptz
);

CREATE INDEX devices_account_active_idx
  ON identity_db.devices (account_id)
  WHERE revoked_at IS NULL;
