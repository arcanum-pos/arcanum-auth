// Prints a new RS256 signing key as a private JWK, for the SIGNING_KEY secret:
//   npm run generate-key | npx wrangler secret put SIGNING_KEY
// Keep it nowhere else. To rotate: publish the old key's public half in
// PREVIOUS_PUBLIC_KEYS (see README.md), then replace SIGNING_KEY.
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const kid = `${new Date().toISOString().slice(0, 10)}-${randomBytes(4).toString('hex')}`;
process.stdout.write(JSON.stringify({ ...privateKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' }));
