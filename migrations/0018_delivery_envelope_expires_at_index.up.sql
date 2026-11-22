-- Retention-sweep index for message_envelopes. DeleteExpiredEnvelopes selects
-- `WHERE expires_at <= $1 ORDER BY expires_at ASC LIMIT $2`, which without this
-- sequential-scans + sorts the whole table each sweep (contrast media_metadata,
-- which already has media_retention_idx). expires_at is NOT NULL here, so a
-- plain (non-partial) btree index serves the range + ordered LIMIT directly.
CREATE INDEX message_envelopes_retention_idx
  ON delivery_db.message_envelopes (expires_at);
