export interface Env {
  DB: D1Database;
  // Requests that write a row without anyone signed in (a device code, a
  // Google sign-in's state, a passkey challenge): limited per caller in
  // memory — no D1 write to count them, so they can't eat the daily quota.
  PUBLIC_RATE_LIMITER?: RateLimit;
  // The issuer URL, exactly as clients are configured with (no trailing slash).
  ISSUER: string;
  // Private signing key: a JWK (RSA, alg RS256, with a kid) as JSON. Create
  // one with `npm run generate-key`.
  SIGNING_KEY: string;
  // Public JWKs (JSON array) still published after a key rotation, so tokens
  // signed with the previous key keep verifying until they expire.
  PREVIOUS_PUBLIC_KEYS?: string;
  // Keys the hashes of the mailed 6-digit codes (util.ts codeHash): 32
  // random bytes, base64.
  CODE_HASH_KEY: string;
  // Bearer key for /admin/* (creating clients — the installer uses this).
  ADMIN_API_KEY: string;
  // Who may use the admin API by signing in (tools/admin, the built-in
  // arcanum-auth-admin client, a passkey): e-mail addresses, comma-separated.
  // Only here, never through the API - an admin can't make another one.
  ADMIN_EMAILS?: string;
  // Sign in with Google (optional — the button only shows when both are set).
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  // Cloudflare Turnstile on the sign-in form (turnstile.ts): on when both are set.
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET?: string;
  // Test hook: where Google's token endpoint is (defaults to Google's own).
  GOOGLE_TOKEN_URL?: string;
  // The mailed sign-in codes, via the platform's mailer (optional — without it,
  // codes are only logged).
  MAILER?: Fetcher;
  // "off": no mail leaves this instance, whatever account is set - codes only
  // in the log (an instance for an active security scan, a test instance).
  MAIL_SENDING?: string;
  MAILER_INTERNAL_KEY?: string;
  // JSON: { host, port, username, password, fromAddress, fromName? }
  MAIL_SMTP?: string;
  // Or either provider: {"provider":"smtp"|"gmail_api","credentials":{…}} —
  // gmail_api credentials: { clientEmail, privateKey, impersonatedUser, fromName? }
  // (a Google service account with domain-wide delegation).
  MAIL_CONFIG?: string;
  // Encrypts the platform settings stored in D1 (settings.ts): 32 random
  // bytes, base64. Unset: the bootstrapper can't store a mail account here.
  SETTINGS_KEY?: string;
}
