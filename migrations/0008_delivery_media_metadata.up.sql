CREATE TABLE delivery_db.media_metadata (
    media_id              uuid PRIMARY KEY,
    uploader_account_id   uuid NOT NULL,
    uploader_device_id    uuid NOT NULL,
    sha256                bytea NOT NULL,
    size_bytes            bigint NOT NULL,
    mime_type             text NOT NULL,
    object_key            text NOT NULL,
    uploaded_at           timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    deleted_at            timestamptz
);

CREATE INDEX media_retention_idx
  ON delivery_db.media_metadata (expires_at)
  WHERE deleted_at IS NULL;
