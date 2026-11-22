-- Per-device X25519 pub key. Multi-device linking gives each linked device its
-- own X25519 keypair so a peer can run an independent forward-secret ratchet
-- per device (the account-level key added in 0010 only ever supported a single
-- device). Nullable + backfilled from the owning account's key so the existing
-- primary device keeps decrypting without a re-key.

ALTER TABLE identity_db.devices
    ADD COLUMN x25519_pub_key bytea;

UPDATE identity_db.devices d
   SET x25519_pub_key = a.x25519_pub_key
  FROM identity_db.accounts a
 WHERE d.account_id = a.account_id
   AND d.x25519_pub_key IS NULL;
