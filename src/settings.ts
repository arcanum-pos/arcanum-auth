// Platform settings stored in D1 (migrations/0006_settings.sql), set by the
// bootstrapper's /admin pages through /admin/* (ADMIN_API_KEY). Every value
// is encrypted with SETTINGS_KEY (32 random bytes, base64; AES-GCM) — no
// key, nothing stored or read. Today only 'mail': the platform's mail
// account (MAIL.md), used before MAIL_CONFIG.
import type { Env } from './env';
import { nowIso } from './util';

export type MailSetting = { provider: string } & Record<string, unknown>;

// What's never shown back: keys, passwords, a service account's private key.
export const SECRET_FIELDS = ['password', 'apiKey', 'privateKey'];

async function key(env: Env): Promise<CryptoKey | null> {
  if (!env.SETTINGS_KEY) return null;
  const raw = Uint8Array.from(atob(env.SETTINGS_KEY.trim()), (c) => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error('SETTINGS_KEY must be 32 bytes, base64');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

const toB64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const fromB64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

export async function readSetting<T>(env: Env, name: string): Promise<{ value: T; updatedAt: string } | null> {
  const k = await key(env);
  if (!k) return null;
  let row: { value: string; updated_at: string } | null;
  try {
    row = await env.DB.prepare('SELECT value, updated_at FROM settings WHERE name = ?').bind(name).first();
  } catch (err) {
    // Before migration 0006 is applied: as if nothing were set.
    if (/no such table/i.test(String(err))) return null;
    throw err;
  }
  if (!row) return null;
  const [iv, data] = row.value.split('.');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv) }, k, fromB64(data));
  return { value: JSON.parse(new TextDecoder().decode(plain)) as T, updatedAt: row.updated_at };
}

export async function writeSetting(env: Env, name: string, value: unknown): Promise<void> {
  const k = await key(env);
  if (!k) throw new Error('SETTINGS_KEY is not set');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(JSON.stringify(value))));
  await env.DB.prepare('INSERT INTO settings (name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
    .bind(name, `${toB64(iv)}.${toB64(data)}`, nowIso())
    .run();
}

export async function deleteSetting(env: Env, name: string): Promise<void> {
  await env.DB.prepare('DELETE FROM settings WHERE name = ?').bind(name).run();
}

// The setting as the bootstrapper may see it: never a secret's value.
export function mailSummary(config: MailSetting) {
  const { provider, ...rest } = config;
  return {
    provider,
    values: Object.fromEntries(Object.entries(rest).filter(([k]) => !SECRET_FIELDS.includes(k))),
    secretsSet: Object.keys(rest).filter((k) => SECRET_FIELDS.includes(k) && rest[k]),
  };
}
