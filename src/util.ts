// Small building blocks: random tokens, hashing, passwords, responses.

const encoder = new TextEncoder();

export function base64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64url(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(text.length + ((4 - (text.length % 4)) % 4), '=');
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

// An unguessable token (codes, refresh tokens, session ids, client secrets).
export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return base64url(new Uint8Array(digest));
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// PKCE S256: base64url(sha256(verifier)) === challenge.
export async function pkceMatches(verifier: string, challenge: string): Promise<boolean> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  return timingSafeEqual(await sha256(verifier), challenge);
}

// --- Passwords: PBKDF2-SHA256 via WebCrypto (native, and the one KDF Workers
// offer without shipping a JS implementation). Workers caps PBKDF2 at 100 000
// iterations. Format: pbkdf2$sha256$<iterations>$<salt>$<hash>.

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

export async function hashPassword(password: string, iterations: number): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2$sha256$${iterations}$${base64url(salt)}$${base64url(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, digest, iter, salt, hash] = stored.split('$');
  if (scheme !== 'pbkdf2' || digest !== 'sha256' || !salt || !hash) return false;
  const actual = await pbkdf2(password, fromBase64url(salt), Number(iter));
  return timingSafeEqual(base64url(actual), hash);
}

export function iterations(env: { PBKDF2_ITERATIONS?: string }): number {
  const n = Number(env.PBKDF2_ITERATIONS || 100_000);
  return Number.isInteger(n) && n >= 10_000 && n <= 100_000 ? n : 100_000;
}

// --- Device user codes: 8 letters, no vowels (no accidental words) and no
// look-alikes, shown as XXXX-XXXX. 20^8 ≈ 2.6·10^10 combinations.
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

export function newUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const chars = [...bytes].map((b) => USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length]);
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

export function normalizeUserCode(input: string): string {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '');
  return letters.length === 8 ? `${letters.slice(0, 4)}-${letters.slice(4)}` : '';
}

export function newEmailCode(): string {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, '0');
}

// --- Time.

export const nowIso = () => new Date().toISOString();
export const inSeconds = (seconds: number) => new Date(Date.now() + seconds * 1000).toISOString();
export const unixNow = () => Math.floor(Date.now() / 1000);

// --- Responses.

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...NO_STORE, ...headers } });
}

// An OAuth error response (RFC 6749 §5.2 shape).
export function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

export function redirect(location: string, headers: Record<string, string> = {}): Response {
  return new Response(null, { status: 302, headers: { Location: location, ...NO_STORE, ...headers } });
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// Form posts must come from this very origin (with SameSite=Lax cookies,
// the CSRF defence).
export function sameOrigin(request: Request, issuer: string): boolean {
  const origin = request.headers.get('Origin');
  if (origin) return origin === new URL(issuer).origin;
  const site = request.headers.get('Sec-Fetch-Site');
  return site === 'same-origin' || site === 'none';
}

// Where to go after signing in: only our own authorize / device pages.
export function safeContinue(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/account';
  const path = value.split('?')[0];
  return path === '/authorize' || path === '/device' || path === '/account' ? value : '/account';
}

export async function readForm(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/x-www-form-urlencoded') && !type.includes('multipart/form-data')) return {};
  const form = await request.formData();
  const out: Record<string, string> = {};
  for (const [k, v] of form.entries()) if (typeof v === 'string') out[k] = v;
  return out;
}
