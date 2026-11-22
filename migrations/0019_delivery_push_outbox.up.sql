-- Durable retry queue for wakeup pushes.
--
-- A push used to be fire-and-forget on the sender's submit path: one transient
-- FCM/APNs error (network blip, 5xx, throttle) and the recipient simply never
-- got a notification for that message, with nothing anywhere to retry it. That
-- is the "notifications are iffy" reliability gap — distinct from the delivered=
-- true suppression bug fixed in 5183f91.
--
-- A failed send now lands here and a worker re-sends it with exponential
-- backoff until it succeeds, the token is proven dead, or the row ages out.
-- Rows are DELETED on success, so a healthy fleet keeps this table near-empty.
--
-- No foreign keys on purpose: the queue must outlive an envelope that is acked
-- (and hard-deleted) between the failed send and the retry, and it is addressed
-- by device token, not by any relational parent.
CREATE TABLE delivery_db.push_outbox (
    id              bigserial PRIMARY KEY,
    device_id       uuid NOT NULL,
    envelope_id     uuid NOT NULL,
    conversation_id text NOT NULL,
    push_kind       text NOT NULL DEFAULT '',
    sealed_payload  bytea,
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- The worker's only read is `WHERE next_attempt_at <= now() ORDER BY
-- next_attempt_at LIMIT n`, which this serves directly.
CREATE INDEX push_outbox_due_idx
  ON delivery_db.push_outbox (next_attempt_at);

-- One pending retry per (device, envelope): a re-submitted duplicate must
-- refresh the existing row rather than queue a second buzz for the same message.
CREATE UNIQUE INDEX push_outbox_device_envelope_idx
  ON delivery_db.push_outbox (device_id, envelope_id);
