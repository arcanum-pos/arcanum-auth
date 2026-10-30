// Every icon the pages link to (ICONS in src/pages.ts) and the manifest's
// icons exist in public/ - static assets, which the Workers test pool
// doesn't serve. Runs before the tests (npm test).
import { existsSync, readFileSync } from 'node:fs';

const icons = readFileSync('src/pages.ts', 'utf8').match(/export const ICONS = '([^']+)'/)?.[1] ?? '';
const paths = [...icons.matchAll(/href="(\/[^"]+)"/g)].map((m) => m[1]);
const manifest = JSON.parse(readFileSync('public/site.webmanifest', 'utf8'));
paths.push(...manifest.icons.map((i) => i.src));
const missing = paths.filter((p) => !existsSync(`public${p}`));
if (paths.length < 5 || missing.length) {
  console.error(paths.length < 5 ? 'No icons found in src/pages.ts - check the pattern.' : `Missing icons:\n  ${missing.join('\n  ')}`);
  process.exit(1);
}
