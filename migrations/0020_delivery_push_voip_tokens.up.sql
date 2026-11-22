-- VoIP (PushKit) device tokens, for iOS CallKit ringing.
--
-- Why a SEPARATE table rather than another `push_tokens` row: an iPhone holds
-- TWO tokens at once and needs both. Its ALERT token is minted by Firebase and
-- reached through FCM (every normal message wakeup); its VoIP token comes from
-- PKPushRegistry and can only be reached by talking to APNs DIRECTLY, on the
-- `<bundle>.voip` topic. `push_tokens` is keyed by device_id alone (one row per
-- device), so the second token has nowhere to live there — and widening that
-- primary key would touch every existing read on the hot message path.
--
-- Only iOS ever registers here. Android rings from its own FCM data wakeup
-- (a full-screen-intent notification), which needs nothing extra.
CREATE TABLE delivery_db.push_voip_tokens (
    device_id  uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    token      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
