// Runs Lighthouse CI locally the way the pages workflow does: stage dist/
// under the base path, collect, assert. (`lhci autorun` is avoided because
// its upload step waits on a server that is not configured.)
import { rmSync, mkdirSync, cpSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const website = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(website, '..');
const base = process.argv[2] ?? '/pod-certificate-signer';
const root = path.join(website, '.site-root');
rmSync(root, { recursive: true, force: true });
mkdirSync(path.join(root, base), { recursive: true });
cpSync(path.join(website, 'dist'), path.join(root, base), { recursive: true });
// @lhci/cli is not a devDependency: its dependency tree has open advisories.
// npx fetches the pinned version on demand.
for (const step of ['collect', 'assert']) {
  execFileSync('npx', ['--yes', '@lhci/cli@0.15.1', step, '--config=website/lighthouserc.json'], { cwd: repo, stdio: 'inherit' });
}
