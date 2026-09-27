-- arcanum-auth's own database: its users, the OAuth clients (one per
-- Arcanum installation), and short-lived protocol state. Secrets and tokens
-- are only ever stored hashed (SHA-256), never as given out.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote

-- One person. `id` is the OIDC `sub` — stable for life, whichever way they
-- sign in (password and Google link to the same user by verified email).
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,          -- lower-cased
  email_verified INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT,                  -- pbkdf2$sha256$<iterations>$<salt>$<hash>; NULL = Google only
  google_sub TEXT UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- An OAuth client: one per Arcanum installation, used for both the
-- authorization-code (console) and device-code (kassa) grants.
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,                 -- client_id
  secret_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,         -- JSON array, exact match
  post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  disabled_at TEXT
);

-- Signed in on login.kaboutersoft.be itself (single sign-on across clients).
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  auth_time INTEGER NOT NULL,          -- unix seconds, the id_token's auth_time
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,        -- S256 only
  auth_time INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code TEXT NOT NULL UNIQUE,      -- XXXX-XXXX
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied
  user_id TEXT,
  auth_time INTEGER,
  interval_seconds INTEGER NOT NULL,
  last_poll_at TEXT,
  expires_at TEXT NOT NULL
);

-- Rotated on every use; a reused (already rotated) token revokes the whole
-- family of that user + client (theft detection).
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  auth_time INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_user_client ON refresh_tokens(user_id, client_id);

-- Six-digit codes mailed for signup and password reset. A signup keeps the
-- chosen name + password hash here until the address is proven.
CREATE TABLE IF NOT EXISTS email_codes (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,               -- signup | reset
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  pending_name TEXT,
  pending_password_hash TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

-- Sign in with Google: the round trip's state.
CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  continue_to TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- Failed attempts, for rate limiting (per e-mail and per IP).
CREATE TABLE IF NOT EXISTS attempts (
  key TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_key_at ON attempts(key, at);
