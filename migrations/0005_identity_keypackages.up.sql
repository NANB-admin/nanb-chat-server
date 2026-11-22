CREATE TABLE identity_db.key_packages (
    kp_id          uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES identity_db.accounts(account_id) ON DELETE CASCADE,
    device_id      uuid NOT NULL REFERENCES identity_db.devices(device_id) ON DELETE CASCADE,
    payload        bytea NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz
);

CREATE INDEX kp_claim_idx
  ON identity_db.key_packages (account_id, device_id, consumed_at, expires_at);
