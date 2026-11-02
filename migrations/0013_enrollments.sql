-- Enrollment (2026-11-02, enroll.ts): an application vouches for an address
-- whose mail it receives itself (a mail installation for its own domains),
-- so its user gets a first passkey without a code mailed into the mailbox
-- they can't open yet.
-- enroll_domains: the domains a client may vouch for, set by a platform
-- admin only (PATCH /admin/clients/:id), never by the client: an
-- installation can already read the codes mailed to these addresses, so
-- vouching for them gives it nothing it doesn't have. '[]': none (the default).
-- enroll_reset: it may also start over for an account that has a passkey
-- (the old passkeys, Google link and sessions go) - an admin's recovery.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE clients ADD COLUMN enroll_domains TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN enroll_reset INTEGER NOT NULL DEFAULT 0;

-- A link the application asked for at the moment its user clicked: opened
-- within two minutes, once, and from then on only in the browser that opened
-- it (browser_hash, its cookie), for ten minutes (opened_until). It signs in
-- to nothing: it only lets that browser create the account's first passkey,
-- and the session that follows is made with that passkey.
CREATE TABLE enrollments (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  -- The account's id - for an address without one yet, the id it gets.
  user_id TEXT NOT NULL,
  continue_to TEXT NOT NULL,
  reset INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  browser_hash TEXT,
  opened_until TEXT,
  used_at TEXT
);
CREATE INDEX enrollments_email ON enrollments (email);
CREATE INDEX enrollments_browser ON enrollments (browser_hash);
