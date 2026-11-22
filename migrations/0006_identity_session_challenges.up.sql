CREATE TABLE identity_db.session_challenges (
    challenge_key  text PRIMARY KEY,
    challenge      bytea NOT NULL,
    expires_at     timestamptz NOT NULL
);
