// Resolves which release the docs are being built against, from git tags.
// Written to website/.env by `npm run prebuild`, where Astro exposes it as
// import.meta.env.PUBLIC_DOCS_VERSION / PUBLIC_DOCS_IS_RELEASE.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function git(repo, ...args) {
  try {
    return execFileSync('git', ['-C', repo, ...args], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return null;
  }
}

export function docsVersion(repo) {
  const exact = git(repo, 'describe', '--tags', '--exact-match', '--match', 'v*');
  if (exact) {
    const status = git(repo, 'status', '--porcelain', '--untracked-files=normal');
    return { version: exact, isRelease: status === '' };
  }
  const latest = git(repo, 'describe', '--tags', '--abbrev=0', '--match', 'v*');
  return { version: latest ?? 'main', isRelease: false };
}

export function toEnv({ version, isRelease }) {
  return `PUBLIC_DOCS_VERSION=${version}\nPUBLIC_DOCS_IS_RELEASE=${isRelease}\n`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const website = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const v = docsVersion(path.resolve(website, '..'));
  writeFileSync(path.join(website, '.env'), toEnv(v));
  console.log(`version: ${v.version}${v.isRelease ? '' : ' (development)'}`);
}
