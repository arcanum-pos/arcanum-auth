-- Guests (demo visitors without an account) and one-time sign-in links;
-- which installation a client belongs to, and who owns it.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote

-- A guest has no password and no real e-mail, and stops existing at
-- expires_at (refused everywhere from then on, deleted by the cron).
ALTER TABLE users ADD COLUMN guest INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN expires_at TEXT;

-- Single use, a minute valid, guests only: starts a session and continues
-- to an address one of the clients registered.
CREATE TABLE IF NOT EXISTS login_links (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  continue_to TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

ALTER TABLE clients ADD COLUMN instance_url TEXT;
ALTER TABLE clients ADD COLUMN owner_email TEXT;
ALTER TABLE clients ADD COLUMN owner_sub TEXT;
