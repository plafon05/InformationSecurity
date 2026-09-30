CREATE TABLE IF NOT EXISTS users (
    name TEXT COLLATE "C" PRIMARY KEY,
    password_hash TEXT NOT NULL DEFAULT '',
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    restricted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_name CHECK (char_length(name) BETWEEN 1 AND 64 AND name = btrim(name)),
    CONSTRAINT admin_not_blocked CHECK (name <> 'ADMIN' OR NOT blocked),
    CONSTRAINT hash_format CHECK (password_hash = '' OR
        (length(password_hash) <= 256 AND password_hash LIKE '$argon2id$v=19$%'))
);
INSERT INTO users (name) VALUES ('ADMIN') ON CONFLICT (name) DO NOTHING;
