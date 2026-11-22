-- Device provenance + web-session expiry. All additive; every column is NULL or
-- defaulted, so code from before this migration keeps working against it.
--   linked_by_device_id : the device that authorized the link (NULL for the
--                         primary / signup / legacy devices). No FK: the
--                         authorizer may later be revoked and the row must stay.
--   kind                : 'phone' (default) or 'web'.
--   expires_at          : NULL = never; web devices get now()+lifetime. A device
--                         with expires_at <= now() is treated as revoked.
ALTER TABLE identity_db.devices
  ADD COLUMN linked_by_device_id uuid NULL,
  ADD COLUMN kind text NOT NULL DEFAULT 'phone',
  ADD COLUMN expires_at timestamptz NULL;

ALTER TABLE identity_db.devices
  ADD CONSTRAINT devices_kind_check CHECK (kind IN ('phone', 'web'));
