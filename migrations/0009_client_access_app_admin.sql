-- An admin of a client made so by the application itself (Arcanum: whoever
-- is an admin of one of its organisations), as opposed to the owner or a
-- choice on /access/:clientId. Only those the application may make plain
-- members again, or remove.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
ALTER TABLE client_access ADD COLUMN app_admin INTEGER NOT NULL DEFAULT 0;
