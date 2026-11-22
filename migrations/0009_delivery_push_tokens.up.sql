CREATE TABLE delivery_db.push_tokens (
    device_id    uuid PRIMARY KEY,
    account_id   uuid NOT NULL,
    platform     text NOT NULL CHECK (platform IN ('apns', 'fcm')),
    token        text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
