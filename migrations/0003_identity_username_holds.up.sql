CREATE TABLE identity_db.username_holds (
    username      text PRIMARY KEY,
    released_at   timestamptz NOT NULL
);
