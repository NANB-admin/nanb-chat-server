-- Sealed-sender capability negotiation: a device advertises that it runs a
-- build with the sealed-envelope RECEIVE path. Senders only seal to devices
-- with supports_sealed = true, so a recipient on an older build (which can't
-- open a sealed message) is sent an unsealed envelope instead of being stranded.
-- Default false = conservative: don't seal until the device confirms it can open.
ALTER TABLE identity_db.devices
  ADD COLUMN supports_sealed boolean NOT NULL DEFAULT false;
