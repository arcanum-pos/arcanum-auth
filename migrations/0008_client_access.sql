-- Restricted clients (2026-10): only the people assigned to a client may
-- sign in to it — assigned by one of its admins, after a request on the
-- sign-in page, or by the application itself (/clients/self/users: Arcanum
-- assigns whoever it invites). A client is restricted unless set otherwise
-- (the bootstrapper and the demo: anyone may start there).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE clients ADD COLUMN restricted INTEGER NOT NULL DEFAULT 1;

-- By e-mail address (lower-cased), not by user: the application can assign
-- someone who has no account yet. One row per client and address.
CREATE TABLE IF NOT EXISTS client_access (
  client_id TEXT NOT NULL REFERENCES clients(id),
  email TEXT NOT NULL,
  status TEXT NOT NULL,                -- assigned | requested
  role TEXT NOT NULL DEFAULT 'member', -- member | admin (manages who may use it)
  source TEXT NOT NULL,                -- owner | request | admin | app | migration
  decided_by TEXT,                     -- the admin's address that assigned it
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (client_id, email)
);
CREATE INDEX IF NOT EXISTS idx_client_access_email ON client_access(email);

-- Nobody locked out by the switch: each client's owner becomes its admin,
-- and whoever signed in to it lately (a refresh token, kept 30 days) stays.
INSERT OR IGNORE INTO client_access (client_id, email, status, role, source, created_at, updated_at)
  SELECT id, lower(owner_email), 'assigned', 'admin', 'owner', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM clients WHERE owner_email IS NOT NULL AND owner_email != '';
INSERT OR IGNORE INTO client_access (client_id, email, status, role, source, created_at, updated_at)
  SELECT DISTINCT refresh_tokens.client_id, users.email, 'assigned', 'member', 'migration', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM refresh_tokens JOIN users ON users.id = refresh_tokens.user_id JOIN clients ON clients.id = refresh_tokens.client_id
  WHERE users.guest = 0;
