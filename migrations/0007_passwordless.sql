-- Sign in without passwords (2026-10): the mailed code also comes with a
-- link, and remembers where to continue, which browser asked (the link
-- signs in directly there) and — for an address without an account — the
-- one-time token of the "what's your name?" step.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE email_codes ADD COLUMN continue_to TEXT;
ALTER TABLE email_codes ADD COLUMN link_hash TEXT;
ALTER TABLE email_codes ADD COLUMN browser_hash TEXT;
ALTER TABLE email_codes ADD COLUMN finish_hash TEXT;
