// Small building blocks: random tokens, hashing, responses.

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

// A mailed 6-digit code's hash: keyed (HMAC-SHA256 with the CODE_HASH_KEY
// secret), since a plain SHA-256 of one of a million codes is reversed in
// milliseconds — a copy of the database would hand out every code still valid.
export async function codeHash(secret: string | undefined, code: string): Promise<string> {
  if (!secret) throw new Error('CODE_HASH_KEY is not set');
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(code))));
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

export function redirect(location: string, headers: Record<string, string> = {}, status = 302): Response {
  return new Response(null, { status, headers: { Location: location, ...NO_STORE, ...headers } });
}

// The distinct host names in a client's addresses (e.g. its custom domain) —
// what tells one installation of an application from another.
export function hostsOf(uris: string[]): string[] {
  const hosts: string[] = [];
  for (const uri of uris) {
    try {
      const host = new URL(uri).host;
      if (!hosts.includes(host)) hosts.push(host);
    } catch {
      // not a URL — left out
    }
  }
  return hosts;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// Form posts must come from this very origin (with SameSite=Lax cookies,
// the CSRF defence). A browser may send `Origin: null` for its own page's
// form (privacy settings, or a no-referrer policy) — then its
// Sec-Fetch-Site decides.
export function sameOrigin(request: Request, issuer: string): boolean {
  const origin = request.headers.get('Origin');
  if (origin && origin !== 'null') return origin === new URL(issuer).origin;
  const site = request.headers.get('Sec-Fetch-Site');
  return site === 'same-origin' || site === 'none';
}

// Where to go after signing in: only our own authorize / device / account
// pages, an access page, or the passkey step on the way to one of them.
export function safeContinue(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/account';
  const path = value.split('?')[0];
  if (/^\/access\/[^/?]+$/.test(path)) return value;
  return path === '/authorize' || path === '/device' || path === '/account' || path === '/login/passkey' ? value : '/account';
}

export async function readForm(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/x-www-form-urlencoded') && !type.includes('multipart/form-data')) return {};
  const form = await request.formData();
  const out: Record<string, string> = {};
  for (const [k, v] of form.entries()) if (typeof v === 'string') out[k] = v;
  return out;
}
