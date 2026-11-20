-- Consent (security review 2026-11-20, finding 4): a client someone else
-- runs - one the bootstrapper or installer made for an installation
-- (owner_sub set) - gets a person's name and
-- e-mail address only after they said yes once ("<app> (<host>) wants your
-- name and email address"). Remembered per person per client; the
-- platform's own clients never ask. A disabled or deleted client's rows
-- are harmless (nothing reads them without the client).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
CREATE TABLE consents (
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, client_id)
);
