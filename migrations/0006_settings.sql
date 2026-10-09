-- Platform settings set from the bootstrapper's admin pages (today only
-- 'mail': the platform's mail account, src/settings.ts), each value
-- encrypted with SETTINGS_KEY (AES-GCM).
-- Applied with: wrangler d1 migrations apply arcanum-auth --remote
CREATE TABLE IF NOT EXISTS settings (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
