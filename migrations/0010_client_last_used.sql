-- When a client was last used (2026-10-23): set whenever it gets tokens (a
-- sign-in, a refresh, a kassa's device sign-in) — at most once an hour.
-- For the platform admins' overview (the bootstrapper's Installaties: what's
-- no longer used, to clean up) and an owner's /account. Starts from the
-- refresh tokens that exist now (kept 30 days).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE clients ADD COLUMN last_used_at TEXT;
UPDATE clients SET last_used_at = (SELECT MAX(created_at) FROM refresh_tokens WHERE refresh_tokens.client_id = clients.id);
