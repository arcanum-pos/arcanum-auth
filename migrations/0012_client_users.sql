-- Who used a client, and when last (2026-10-24): one row per client and
-- person, set whenever they get tokens from it (a sign-in, a refresh, a
-- device sign-in) - at most once an hour. "Active users" (tools/admin, the
-- bootstrapper) counts these over 30 days; before, it counted only people
-- with a refresh token, so an app that never asks for one (offline_access)
-- showed 0 while in use. Starts from the refresh tokens that exist now.
-- Rows older than 90 days go (cleanup.ts).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
CREATE TABLE client_users (
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  last_used_at TEXT NOT NULL,
  PRIMARY KEY (client_id, user_id)
);
CREATE INDEX client_users_client_last ON client_users (client_id, last_used_at);
INSERT INTO client_users (client_id, user_id, last_used_at)
  SELECT client_id, user_id, MAX(created_at) FROM refresh_tokens GROUP BY client_id, user_id;
