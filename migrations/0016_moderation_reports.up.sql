CREATE SCHEMA IF NOT EXISTS moderation_db;

-- User-abuse reports. The reporter is always an authenticated account; the
-- reported user + any forwarded evidence come from the report body. This is a
-- review-only moderation queue (no in-app admin surface). Evidence messages are
-- stored as JSONB rather than a child table since they are opaque review data.
CREATE TABLE moderation_db.reports (
    report_id            uuid PRIMARY KEY,
    reporter_account_id  uuid NOT NULL REFERENCES identity_db.accounts(account_id) ON DELETE CASCADE,
    reporter_device_id   uuid NOT NULL,
    -- No FK on the reported side: a report must survive the reported account
    -- being deleted, and we keep a username snapshot for triage either way.
    reported_account_id  uuid NOT NULL,
    reported_username    text NOT NULL DEFAULT '',
    conversation_id      text NOT NULL DEFAULT '',
    reason               text NOT NULL,
    note                 text NOT NULL DEFAULT '',
    context_messages     jsonb NOT NULL DEFAULT '[]'::jsonb,
    status               text NOT NULL DEFAULT 'open',
    created_at           timestamptz NOT NULL DEFAULT now(),
    reviewed_at          timestamptz
);

-- Triage queue: open reports oldest-first.
CREATE INDEX reports_triage_idx ON moderation_db.reports (status, created_at);
-- "How many times has this account been reported" lookups.
CREATE INDEX reports_reported_idx ON moderation_db.reports (reported_account_id);
