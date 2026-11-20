-- APIs, roles and application access (2026-11-20, AUTH_DEDICATED.md section
-- 2, apis.ts): for a dedicated instance (Radio Scorpio, moving off Auth0).
-- Applied on every instance; empty where unused (login.kaboutersoft.be), and
-- then nothing reads them: without an `audience` every token is as before.
--   apis               an API (its id is the audience, e.g. "zaracloud-api")
--   api_permissions    the permissions it knows ("read:shows")
--   roles              hold permissions from one or more APIs; is_default:
--                      everyone who may sign in has it, without a row each
--   role_members       by e-mail address (lower-cased), so someone can be
--                      added before their first sign-in
--   client_api_access  per application and API, per permission:
--                      kind 'user'   it may ask for it on behalf of a user
--                      kind 'client' it gets it itself (machine-to-machine)
-- A user's access token for audience X holds the permissions on X of their
-- roles (default ones included) that the application may ask for ('user').
-- auth_codes.audience, refresh_tokens.audience: the audience asked on
-- /authorize, kept through every refresh. NULL: none (as before).
-- audit_log: admin changes and machine-secret events, for the admin
-- dashboard (kept a year, cleanup.ts). Never a secret, token or code in it.
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
-- (before pushing the code that needs it).
CREATE TABLE apis (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE api_permissions (
  api_id TEXT NOT NULL REFERENCES apis(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (api_id, name)
);
CREATE TABLE roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE role_permissions (
  role_id TEXT NOT NULL REFERENCES roles(id),
  api_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  PRIMARY KEY (role_id, api_id, permission)
);
CREATE INDEX role_permissions_api ON role_permissions (api_id, permission);
CREATE TABLE role_members (
  role_id TEXT NOT NULL REFERENCES roles(id),
  email TEXT NOT NULL,
  added_by TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (role_id, email)
);
CREATE INDEX role_members_email ON role_members (email);
CREATE TABLE client_api_access (
  client_id TEXT NOT NULL,
  api_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'client')),
  permission TEXT NOT NULL,
  PRIMARY KEY (client_id, api_id, kind, permission)
);
CREATE INDEX client_api_access_api ON client_api_access (api_id, permission);
ALTER TABLE auth_codes ADD COLUMN audience TEXT;
ALTER TABLE refresh_tokens ADD COLUMN audience TEXT;
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  name TEXT NOT NULL,
  by TEXT,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at);
