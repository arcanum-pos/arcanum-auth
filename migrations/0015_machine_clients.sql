-- Machine clients and their secrets (2026-11-20, AUTH_DEDICATED.md sections
-- 3 and 3b, machine.ts): a client of kind 'machine' only gets tokens for
-- itself (grant_type=client_credentials, an API's permissions given to it in
-- client_api_access); no redirect URIs, no people, no sign-in. Every
-- existing client is kind 'user', as it always was.
-- secret_created_at: the secret's age in the admin dashboard (a warning
-- from 12 months); NULL: as old as the client (created_at).
-- previous_secret_hash, previous_secret_expires_at: after a rotation the old
-- secret keeps working 24 hours, so a worker can be updated without
-- downtime; "revoke now" clears them. Secrets are only ever stored as their
-- SHA-256 (256 random bits: nothing to reverse or guess).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE clients ADD COLUMN kind TEXT NOT NULL DEFAULT 'user';
ALTER TABLE clients ADD COLUMN secret_created_at TEXT;
ALTER TABLE clients ADD COLUMN previous_secret_hash TEXT;
ALTER TABLE clients ADD COLUMN previous_secret_expires_at TEXT;
