-- When a refresh token was rotated away by normal use (as opposed to
-- revoked: theft, a new password). Within a few seconds of its rotation the
-- same token may come again from a parallel request of the same app — that
-- gets fresh tokens instead of revoking them all (src/oidc.ts refreshGrant).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
ALTER TABLE refresh_tokens ADD COLUMN rotated_at TEXT;
