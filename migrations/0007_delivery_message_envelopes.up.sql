CREATE TABLE delivery_db.message_envelopes (
    envelope_id           uuid PRIMARY KEY,
    conversation_id       text NOT NULL,
    sender_device_id      uuid NOT NULL,
    recipient_account_id  uuid NOT NULL,
    recipient_device_id   uuid NOT NULL,
    envelope_type         text NOT NULL,
    payload               bytea NOT NULL,
    server_ts             timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    acked_at              timestamptz
);

CREATE INDEX message_envelopes_catchup_idx
  ON delivery_db.message_envelopes (recipient_device_id, server_ts)
  WHERE acked_at IS NULL;

CREATE INDEX message_envelopes_conversation_idx
  ON delivery_db.message_envelopes (recipient_account_id, conversation_id, server_ts);
