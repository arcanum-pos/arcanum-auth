import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// migrations/0001_initial.sql split into statements (D1 wants one at a
// time); `--` comments stripped first.
function sqlStatements(file: string): string[] {
  return readFileSync(new URL(file, import.meta.url), 'utf8')
    .split('\n')
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
}

// A throwaway signing key per test run.
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingKey = JSON.stringify({ ...privateKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256' });

// Stand-in for arcanum-mailer: records every /send (GET /__calls lists them).
function recordingMailer() {
  const calls: unknown[] = [];
  return async (request: Request) => {
    const path = new URL(request.url).pathname;
    if (path === '/__calls') return Response.json(calls);
    calls.push({ path, auth: request.headers.get('Authorization'), body: await request.json() });
    return Response.json({ ok: true });
  };
}

// Stand-in for Google's token endpoint: the code picks the account.
function fakeGoogle(request: Request): Promise<Response> {
  return request.formData().then((form) => {
    const code = String(form.get('code'));
    const claims = {
      iss: 'https://accounts.google.com',
      aud: 'google-client-id',
      sub: `google-${code}`,
      email: `${code.replace(/^unverified-/, '')}`,
      email_verified: !code.startsWith('unverified-'),
      name: 'Google User',
    };
    const part = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    return Response.json({ id_token: `${part({ alg: 'none' })}.${part(claims)}.` });
  });
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          TEST_SCHEMA: JSON.stringify(sqlStatements('./migrations/0001_initial.sql')),
          // Later migrations, run once per test file after the schema (ALTERs aren't idempotent).
          TEST_MIGRATIONS: JSON.stringify(['./migrations/0002_guests_and_client_metadata.sql'].flatMap((f) => sqlStatements(f))),
          SIGNING_KEY: signingKey,
          ADMIN_API_KEY: 'test-admin-key',
          MAILER_INTERNAL_KEY: 'test-mailer-key',
          MAIL_SMTP: JSON.stringify({ host: 'smtp.test', port: 465, username: 'u', password: 'p', fromAddress: 'noreply@test' }),
          GOOGLE_CLIENT_ID: 'google-client-id',
          GOOGLE_CLIENT_SECRET: 'google-secret',
          GOOGLE_TOKEN_URL: 'https://google.test/token',
          PBKDF2_ITERATIONS: '10000',
        },
        serviceBindings: { MAILER: recordingMailer() },
        outboundService: (request: Request) =>
          new URL(request.url).hostname === 'google.test' ? fakeGoogle(request) : new Response('no outbound in tests', { status: 502 }),
      },
    }),
  ],
  test: { setupFiles: ['./test/setup.ts'] },
});
