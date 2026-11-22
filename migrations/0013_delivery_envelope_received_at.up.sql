-- Transport-level "delivered": a recipient device confirms (via POST
-- /messages/received from its FCM background handler) that a wakeup push for
-- an envelope physically landed, WITHOUT decrypting/acking it. Distinct from
-- acked_at (set only after the foreground decrypts + persists). Nullable; the
-- column is written once, on the first confirmation, and read only for
-- idempotency (so a redelivered push doesn't re-notify the sender).
ALTER TABLE delivery_db.message_envelopes
    ADD COLUMN received_at timestamptz;
