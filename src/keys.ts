import { importJWK, type JWK } from 'jose';
import type { Env } from './env';

// The signing key (SIGNING_KEY secret, a private RSA JWK) and the public
// keys published at /.well-known/jwks.json. Parsed once per isolate.
let cached: { raw: string; key: CryptoKey; kid: string; publicJwk: JWK } | null = null;

export async function signingKey(env: Env): Promise<{ key: CryptoKey; kid: string }> {
  if (cached?.raw !== env.SIGNING_KEY) {
    if (!env.SIGNING_KEY) throw new Error('SIGNING_KEY is not set');
    const jwk = JSON.parse(env.SIGNING_KEY) as JWK;
    if (jwk.kty !== 'RSA' || !jwk.d || !jwk.kid) throw new Error('SIGNING_KEY must be a private RSA JWK with a kid');
    const key = (await importJWK({ ...jwk, alg: 'RS256' }, 'RS256', { extractable: true })) as CryptoKey;
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicPart } = jwk;
    cached = { raw: env.SIGNING_KEY, key, kid: jwk.kid, publicJwk: { ...publicPart, alg: 'RS256', use: 'sig' } };
  }
  return { key: cached.key, kid: cached.kid };
}

export async function publicKeys(env: Env): Promise<JWK[]> {
  await signingKey(env);
  const previous = env.PREVIOUS_PUBLIC_KEYS ? (JSON.parse(env.PREVIOUS_PUBLIC_KEYS) as JWK[]) : [];
  return [cached!.publicJwk, ...previous.map((k) => ({ ...k, alg: 'RS256', use: 'sig' }))];
}

// The public key as a CryptoKey, to verify our own access tokens (userinfo).
let verifyCache: { raw: string; key: CryptoKey } | null = null;

export async function verificationKey(env: Env): Promise<CryptoKey> {
  await signingKey(env);
  if (verifyCache?.raw !== env.SIGNING_KEY) {
    verifyCache = { raw: env.SIGNING_KEY, key: (await importJWK(cached!.publicJwk, 'RS256')) as CryptoKey };
  }
  return verifyCache.key;
}
