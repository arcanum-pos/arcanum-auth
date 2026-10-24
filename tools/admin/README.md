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

Then open **http://127.0.0.1:8799** and **sign in with a passkey**: the
instance's own sign-in page, back on this page with a token for an hour.
Only the addresses in that instance's **`ADMIN_EMAILS`** variable get in
(comma-separated, set in the dashboard or `wrangler.jsonc` - never through
the API, so an admin can't make another one), and only with a passkey (none
yet: you add one on the way). No refresh: after the hour, sign in again.
Every change is logged as a security event `admin` with `by: <your address>`.

**The admin key** (`ADMIN_API_KEY`, under "Use the admin key instead") stays
the way back in: signing in broken, your passkeys lost, a new instance
without `ADMIN_EMAILS` yet. The bootstrapper keeps using it too.

The token comes from arcanum-auth's built-in client `arcanum-auth-admin`
(src/store.ts): no secret (PKCE), one return address
`http://127.0.0.1:8799/callback` - so the port stays 8799 - and it can't be
changed or removed through the API. A token still only works through this
tool: the admin API never answers from the internet.

The page shows which instance it is and what protection is
off (Turnstile, mail - `/admin/info`), and lets you:

- see every client: open or restricted, passkey required, owner, last used,
  active users in the last 30 days
- create one (the secret is shown once, with a button to copy issuer, id
  and secret), open or restrict it, require a passkey, edit its addresses,
  disable it, delete a disabled one for good
- remove someone's passkeys (they're told by mail)
- see which mail account it sends with, and send a test mail

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
| disable a client (`?by=<email>` mails its owner) | `curl -H "$A" -X DELETE localhost:8799/admin/clients/<id>` |
| delete a disabled one for good | `curl -H "$A" -X DELETE 'localhost:8799/admin/clients/<id>?hard=1'` |
| someone's passkeys, all gone (they're told) | `curl -H "$A" -X DELETE localhost:8799/admin/users/<email>/passkeys` |
| the mail account (stored encrypted, needs `SETTINGS_KEY`) | GET / PUT / DELETE `/admin/mail`, test mail POST `/admin/mail/test` `{"to":"…"}` - or skip it and set `MAIL_CONFIG` as a secret |

Every change is a security event `admin` in that instance's Workers Logs.

## Another instance

The binding names the Worker `arcanum-auth` on the account you're logged in
to. One deployed under another name: add an env block to `wrangler.jsonc`
(`"env": { "<name>": { "services": [{ "binding": "AUTH", "service": "<worker>", "remote": true }] } }`)
and run with `--env <name>`.
