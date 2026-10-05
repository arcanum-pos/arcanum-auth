-- The authenticator's model id (AAGUID) a passkey reported when it was
-- added: names well-known ones ("iCloud-sleutelhanger", "Windows Hello" …).
-- All zeros when the authenticator doesn't say. Applied with:
-- wrangler d1 migrations apply arcanum-auth --remote
ALTER TABLE passkeys ADD COLUMN aaguid TEXT;
