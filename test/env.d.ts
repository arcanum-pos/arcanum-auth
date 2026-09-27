import type { Env as WorkerEnv } from '../src/env';

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      // migrations/0001_initial.sql as a JSON array of statements — see vitest.config.mts.
      TEST_SCHEMA: string;
    }
  }
}
