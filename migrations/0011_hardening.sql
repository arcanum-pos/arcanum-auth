-- Hardening phases 3-4 (2026-10-24, HARDENING.md).
-- How a session was made (amr: 'otp' a mailed code or link, 'fed' Google,
-- 'passkey', 'link' a guest's one-time link) - carried into the codes and
-- tokens it gives (the id_token's amr) and checked for a client that
-- requires a passkey. NULL: from before, counts as not a passkey.
-- last_seen_at: an idle session ends after 7 days (14 at most, as before);
-- user_agent: which browser, for the list on /account.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE sessions ADD COLUMN amr TEXT;
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE auth_codes ADD COLUMN amr TEXT;
ALTER TABLE device_codes ADD COLUMN amr TEXT;
ALTER TABLE refresh_tokens ADD COLUMN amr TEXT;
-- Only sessions made with a passkey may use it (set by its admins on /access/:id).
ALTER TABLE clients ADD COLUMN require_passkey INTEGER NOT NULL DEFAULT 0;
