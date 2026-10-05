-- Passkeys (WebAuthn): another way into the same account — the same user,
-- the same `sub`. Bound to the relying party login.kaboutersoft.be (the
-- ISSUER's host): a passkey only ever works there.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote

CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,                 -- the credential id, base64url
  user_id TEXT NOT NULL REFERENCES users(id),
  public_key TEXT NOT NULL,            -- COSE public key, base64url
  counter INTEGER NOT NULL DEFAULT 0,  -- the authenticator's signature counter (0 for most synced passkeys)
  transports TEXT NOT NULL DEFAULT '[]', -- JSON array, a hint for the browser
  device_type TEXT NOT NULL DEFAULT 'singleDevice', -- singleDevice | multiDevice (synced)
  backed_up INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL,                  -- "iPhone", "Mac" … — renamable on /account
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);

-- A challenge handed to the browser: single use, five minutes. For a
-- registration it belongs to the signed-in user; a sign-in carries where to
-- continue afterwards.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge_hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,               -- register | login
  user_id TEXT,
  expires_at TEXT NOT NULL
);

-- "Not now" on the offer to add a passkey after signing in: asked again 30 days later.
ALTER TABLE users ADD COLUMN passkey_offer_dismissed_at TEXT;
