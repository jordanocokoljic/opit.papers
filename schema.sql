CREATE TABLE identity (
    id              UUID PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL
);

CREATE TABLE reset (
    token_hash  TEXT PRIMARY KEY,
    identity    UUID NOT NULL REFERENCES identity (id),
    expires     TIMESTAMPTZ NOT NULL
);
