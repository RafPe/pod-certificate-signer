// Post-build checks on dist/ that lychee and Lighthouse do not cover:
//   - no third-party font or script hosts leaked into the HTML
//   - the landing page carries its reduced-motion fallback
//   - every root-absolute href/src in the HTML starts with the base path
// Usage: node scripts/check-dist.mjs [--base /pod-certificate-signer]
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const base = args.includes('--base') ? args[args.indexOf('--base') + 1] : '/pod-certificate-signer';
const dist = path.resolve('dist');
const failures = [];

function* html(dir) {
  for (const e of readdirSync(dir)) {
    const p = path.join(dir, e);
    if (statSync(p).isDirectory()) yield* html(p);
    else if (p.endsWith('.html')) yield p;
  }
}

const forbiddenHosts = ['fonts.googleapis.com', 'fonts.gstatic.com', 'googletagmanager.com', 'cdn.jsdelivr.net', 'unpkg.com'];
let pages = 0;
for (const file of html(dist)) {
  pages++;
  const rel = path.relative(dist, file);
  const src = readFileSync(file, 'utf8');
  for (const host of forbiddenHosts) {
    if (src.includes(host)) failures.push(`${rel}: references ${host}`);
  }
  const basePrefix = base.endsWith('/') ? base : `${base}/`;
  for (const m of src.matchAll(/\b(?:href|src)="(\/[^"/][^"]*)"/g)) {
    const url = m[1];
    if (!url.startsWith(basePrefix) && url !== base) failures.push(`${rel}: ${url} is not under ${basePrefix}`);
  }
}
if (pages === 0) failures.push('dist/ contains no HTML files');

const landing = path.join(dist, 'index.html');
try {
  const src = readFileSync(landing, 'utf8');
  if (!src.includes('pcs-guide')) failures.push('index.html: landing page markup missing');
} catch {
  failures.push('index.html: landing page was not built');
}
// The landing CSS is bundled; check the stylesheet set rather than the HTML.
const cssDir = path.join(dist, '_astro');
const css = readdirSync(cssDir).filter((f) => f.endsWith('.css')).map((f) => readFileSync(path.join(cssDir, f), 'utf8')).join('\n');
if (!/prefers-reduced-motion:\s*reduce/.test(css)) failures.push('css: no prefers-reduced-motion rule found');

if (failures.length) {
  console.error(`check-dist: ${failures.length} problem(s)\n` + failures.map((f) => `  - ${f}`).join('\n'));
  process.exit(1);
}
console.log(`check-dist: ${pages} pages ok, base ${base}`);
