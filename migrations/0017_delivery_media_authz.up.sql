-- Object-level media authorization. When non-null, only the uploader or an
-- account listed here may download the object; NULL/empty preserves the legacy
-- behaviour of any-authenticated-caller access (older clients that do not
-- declare a download audience at init). Content is already E2EE, so this is
-- defense-in-depth against media_id enumeration by an authenticated user.
ALTER TABLE delivery_db.media_metadata
    ADD COLUMN IF NOT EXISTS authorized_account_ids text[];
