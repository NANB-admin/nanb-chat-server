ALTER TABLE identity_db.devices DROP CONSTRAINT IF EXISTS devices_kind_check;
ALTER TABLE identity_db.devices
  DROP COLUMN IF EXISTS expires_at,
  DROP COLUMN IF EXISTS kind,
  DROP COLUMN IF EXISTS linked_by_device_id;
