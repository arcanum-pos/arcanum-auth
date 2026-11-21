// tools/admin/page.html: its one inline script parses (the dashboard has no
// build step, so a syntax error would only show in the browser).
import { readFileSync } from 'node:fs';
const html = readFileSync(new URL('../tools/admin/page.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)].map((m) => m[1]);
if (scripts.length !== 1) throw new Error(`tools/admin/page.html: expected one inline script, found ${scripts.length}`);
new Function(scripts[0]);
if (/[–—]/.test(html)) throw new Error('tools/admin/page.html: a long dash - use -');
console.log('tools/admin/page.html: the script parses');
