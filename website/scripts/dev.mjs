// Local preview: stage the docs, start `astro dev`, and restage whenever a
// staged source (docs/, the other listed files, the manifest or an image)
// changes, so the preview follows edits to the markdown. Changes are found
// by polling modification times once a second: fs.watch is unreliable on
// some filesystems and the tree is small.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stage } from './stage.mjs';

const website = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(website, '..');
const manifestPath = path.join(website, 'site.manifest.json');
const options = { repoRoot, manifestPath, outDir: path.join(website, 'src/content/docs'), imgDir: path.join(website, 'src/assets/img') };

function restage(reason) {
  try {
    const { pages } = stage(options);
    console.log(`[stage] ${pages.length} pages (${reason})`);
  } catch (err) {
    console.error(`[stage] ${err.message}`);
  }
}

// Everything the manifest draws from: its own file, docs/ and the directory
// of every other listed source (root files such as CONTRIBUTING.md).
function watchedRoots() {
  const roots = new Set([manifestPath, path.join(repoRoot, 'docs')]);
  for (const page of JSON.parse(readFileSync(manifestPath, 'utf8')).pages.filter((p) => p.source)) {
    const abs = path.join(repoRoot, page.source);
    // A file at the repository root is watched on its own; watching the root
    // directory would include website/ and loop on staging's own output.
    roots.add(path.dirname(abs) === repoRoot ? abs : path.dirname(abs));
  }
  return [...roots];
}

function snapshot() {
  const out = new Map();
  const visit = (p, depth) => {
    let st;
    try { st = statSync(p); } catch { return; }
    if (st.isDirectory()) {
      if (depth > 6 || p === website || /(^|\/)(node_modules|\.git)$/.test(p)) return;
      for (const e of readdirSync(p)) visit(path.join(p, e), depth + 1);
    } else if (/\.(md|json|png|jpe?g|gif|svg|webp)$/i.test(p)) {
      out.set(p, st.mtimeMs);
    }
  };
  for (const r of watchedRoots()) visit(r, 0);
  return out;
}

restage('start');
let last = snapshot();
setInterval(() => {
  // A half-saved manifest must not kill the watcher: keep the last snapshot
  // and try again on the next tick.
  let now;
  try { now = snapshot(); } catch (err) { console.error(`[stage] ${err.message}`); return; }
  let changed;
  for (const [p, m] of now) if (last.get(p) !== m) { changed = p; break; }
  if (!changed) for (const p of last.keys()) if (!now.has(p)) { changed = p; break; }
  if (changed) { last = now; restage(path.relative(repoRoot, changed)); }
}, 1000).unref?.();

const astro = spawn(path.join(website, 'node_modules/.bin/astro'), ['dev', ...process.argv.slice(2)], { cwd: website, stdio: 'inherit' });
// In a terminal astro stays attached and Ctrl-C ends both. Without a TTY
// Astro 7 daemonises and exits at once; keep polling then, and leave the
// daemon to `astro dev stop`.
astro.on('exit', (code) => { if (code) process.exit(code); });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { astro.kill(sig); process.exit(0); });
setInterval(() => {}, 1 << 30);
