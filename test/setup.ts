// Applies the schema before each test file (every statement is IF NOT
// EXISTS). Tests don't rely on a clean database: each uses its own e-mail
// addresses and clients.
import { env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

beforeAll(async () => {
  const statements = JSON.parse(env.TEST_SCHEMA) as string[];
  await env.DB.batch(statements.map((sql) => env.DB.prepare(sql)));
  // Each test file has its own storage, so the ALTERs run exactly once here.
  const already = await env.DB.prepare("SELECT 1 FROM pragma_table_info('users') WHERE name = 'guest'").first();
  if (!already) {
    const migrations = JSON.parse(env.TEST_MIGRATIONS) as string[];
    await env.DB.batch(migrations.map((sql) => env.DB.prepare(sql)));
  }
});
