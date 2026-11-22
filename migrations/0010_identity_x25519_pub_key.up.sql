-- Adds an X25519 pub key to each account so peers can derive a shared secret
-- via ECDH for the v1 baseline E2EE layer. Plan 6 (full MLS via CoreCrypto)
-- will reuse this column for MLS welcomes; the column is durable.
--
-- Nullable for backwards compatibility with accounts created before this
-- column existed (none in production yet, but the v1 migration is ordered
-- this way for safety).

ALTER TABLE identity_db.accounts
    ADD COLUMN x25519_pub_key bytea;
