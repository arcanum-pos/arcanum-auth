# tools/admin: the admin API from your laptop

arcanum-auth's admin API (`/admin/*`, bearer `ADMIN_API_KEY`) never answers
from the internet - only calls from another Worker on the same account, which
carry no `CF-Connecting-IP` (the bootstrapper's service binding, on the
kaboutersoft account). On an account without a bootstrapper, this little
Worker is that other Worker: `wrangler dev` runs it on your laptop and
reaches the deployed arcanum-auth through a remote service binding.
Nothing is deployed and nothing on the instance opens up: you need that
account's Wrangler login and that instance's `ADMIN_API_KEY`.

Tested against login.kaboutersoft.be (2026-10-24): straight from the
internet 404, through this Worker 401 without a key (past the check).

```sh
npx wrangler login        # the account of the instance (npx wrangler whoami)
npx wrangler dev -c tools/admin/wrangler.jsonc
```

Then open **http://127.0.0.1:8799** and **sign in**: the instance's own
sign-in page, back on this page with a token for an hour. On the shared
instance that's **a passkey** (none yet: you add one on the way); on a
Google-only instance (`SIGN_IN=google`, e.g. Radio Scorpio) it's **Google**,
with 2-step verification by the Workspace's policy - no passkeys there.
Only the addresses in that instance's **`ADMIN_EMAILS`** variable get in
(comma-separated, set in the dashboard or `wrangler.jsonc` - never through
the API, so an admin can't make another one). No refresh: after the hour,
sign in again. Every change is logged as a security event `admin` with
`by: <your address>`, and in the instance's audit log (migration 0014).

**The admin key** (`ADMIN_API_KEY`, under "Use the admin key instead") stays
the way back in: signing in broken, your passkeys lost, a new instance
without `ADMIN_EMAILS` yet. The bootstrapper keeps using it too.

The token comes from arcanum-auth's built-in client `arcanum-auth-admin`
(src/store.ts): no secret (PKCE), one return address
`http://127.0.0.1:8799/callback` - so the port stays 8799 - and it can't be
changed or removed through the API. A token still only works through this
tool: the admin API never answers from the internet.

### The dashboard

A menu on the left, the content on the right (links are `#page/id/tab`, so
the browser's back button works). The menu follows the instance's settings
(`GET /admin/instance`): a Google-only instance shows APIs, roles and
machine clients; the shared one shows clients with owners, access requests,
passkeys and mail - and APIs and roles only once it has any.

- **Overview** - counts (applications, machine clients, people, active in
  30 days, access requests) and the recent admin actions.
- **Applications** (the shared instance: **Clients**) - every client, for
  people and machine clients, searchable: open or restricted, passkey
  required, owner, last used and active users, the addresses that tell it
  apart, and for an Arcanum installation which release each address runs
  (its public `/version`, or "not answering"). Per application, tabs:
  - *Settings* - rename, open or restrict, require a passkey (shared
    instance), disable, delete a disabled one for good
  - *URLs* - redirect and logout addresses
  - *Credentials* - id, secret age (a warning from 12 months), **rotate the
    secret** (shown once, with a copy button; the old one works 24 hours) and
    **revoke the previous one now**
  - *API access* - per API, which permissions it may ask for on behalf of
    users, or (a machine client) gets itself; Edit opens a list to tick
  - *Who may sign in* - the list of a restricted client: add or remove
    addresses, approve or refuse requests
  - *Enrollment* (shared instance) - the domains whose users get a first
    passkey without a mailed code, and whether it may reset an account
  - New application / new client (the secret shown once, with a button to
    copy issuer, id and secret), new machine client.
- **APIs** - identifier (the audience), permissions (add, describe, remove),
  which roles and applications use each one; rename or delete an API.
- **Roles** - permissions per API (tick and save), members by e-mail
  (also before their first sign-in), default role on or off.
- **Users** - who signed in and when, their roles (or how they sign in, on
  the shared instance), **sign out everywhere**.
- **Access requests** (shared) - open requests on every client, approve or
  refuse.
- **Passkeys** (shared) - remove someone's passkeys (they're told by mail).
- **Mail** (shared) - which mail account it sends with, send a test mail.
- **Audit log** - admin changes, secret rotations and revocations, failed
  machine sign-ins (kept a year).
- **Instance** - read-only: issuer, sign-in methods, Workspace, self-service,
  device flow, action hook, Auth0 compatibility, protections that are off.

The token or key stays in that browser tab only (sessionStorage, "Sign out"
clears it). The Worker answers only as localhost (`127.0.0.1:8799`, also against a
DNS name pointed at it), and another site can't send it the key. Stop it
with `x` or Ctrl-C.

## The same with curl

```sh
export ADMIN_API_KEY=…    # that instance's
A="Authorization: Bearer $ADMIN_API_KEY"
```

| What | Call |
|---|---|
| list clients (with `last_used_at`, `active_users`) | `curl -H "$A" localhost:8799/admin/clients` |
| create a client (secret shown once) | `node scripts/create-client.mjs "<name>" https://<app>` - or POST `/admin/clients` with `name`, `redirect_uris`, `post_logout_redirect_uris`, optional `instance_url`, `owner_email`, `restricted` (default true) |
| open / restrict, passkey required, its addresses | `curl -H "$A" -H 'Content-Type: application/json' -X PATCH localhost:8799/admin/clients/<id> -d '{"restricted":false}'` (also `require_passkey`, `redirect_uris`, `post_logout_redirect_uris`) |
| let a mail installation enroll its own domains | `curl -H "$A" -H 'Content-Type: application/json' -X PATCH localhost:8799/admin/clients/<id> -d '{"enroll_domains":["frigg.be"],"enroll_reset":true}'` - only domains whose mail that installation receives |
| disable a client (`?by=<email>` mails its owner) | `curl -H "$A" -X DELETE localhost:8799/admin/clients/<id>` |
| delete a disabled one for good | `curl -H "$A" -X DELETE 'localhost:8799/admin/clients/<id>?hard=1'` |
| someone's passkeys, all gone (they're told) | `curl -H "$A" -X DELETE localhost:8799/admin/users/<email>/passkeys` |
| the mail account (stored encrypted, needs `SETTINGS_KEY`) | GET / PUT / DELETE `/admin/mail`, test mail POST `/admin/mail/test` `{"to":"…"}` - or skip it and set `MAIL_CONFIG` as a secret |
| the instance's settings | `curl -H "$A" localhost:8799/admin/instance` |
| APIs, roles, members, API access, importing users | see the top of `src/apis.ts` and `src/users.ts` (arcanum-auth README, "Dedicated instances") |
| a machine client (secret shown once) | `curl -H "$A" -H 'Content-Type: application/json' -X POST localhost:8799/admin/clients -d '{"kind":"machine","name":"zara worker"}'` |
| rotate a client's secret (24 h overlap) / end the old one now | `curl -H "$A" -X POST localhost:8799/admin/clients/<id>/secret` / `curl -H "$A" -X DELETE localhost:8799/admin/clients/<id>/secret/previous` |
| overview, audit log, users, sign out everywhere | GET `/admin/overview`, `/admin/audit`, `/admin/users?q=`; POST `/admin/users/<email>/sign-out` |
| who may sign in to a restricted client | GET `/admin/clients/<id>/users`; PUT / DELETE `/admin/clients/<id>/users/<email>`; open requests: GET `/admin/access-requests` |

Every change is a security event `admin` in that instance's Workers Logs.

## Another instance

The binding names the Worker `arcanum-auth` on the account you're logged in
to. One deployed under another name: add an env block to `wrangler.jsonc`
(`"env": { "<name>": { "services": [{ "binding": "AUTH", "service": "<worker>", "remote": true }] } }`)
and run with `--env <name>`.
