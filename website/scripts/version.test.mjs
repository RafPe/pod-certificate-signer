import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { docsVersion, toEnv } from './version.mjs';

let repo;
const git = (...args) => execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } }).toString().trim();
const commit = (msg) => { writeFileSync(path.join(repo, msg), msg); git('add', '.'); git('commit', '-q', '-m', msg); };

beforeEach(() => {
  repo = mkdtempSync(path.join(tmpdir(), 'version-'));
  git('init', '-q');
  commit('one');
  git('tag', 'v1.8.1');
});
afterEach(() => rmSync(repo, { recursive: true, force: true }));

test('on a tagged commit the tag is the version and it is a release', () => {
  assert.deepEqual(docsVersion(repo), { version: 'v1.8.1', isRelease: true });
});

test('local edits at a tag are development documentation', () => {
  writeFileSync(path.join(repo, 'one'), 'modified');
  assert.deepEqual(docsVersion(repo), { version: 'v1.8.1', isRelease: false });
});

test('untracked documentation at a tag is development documentation', () => {
  writeFileSync(path.join(repo, 'new-doc.md'), '# New documentation');
  assert.deepEqual(docsVersion(repo), { version: 'v1.8.1', isRelease: false });
});

test('after the tag the latest reachable tag is reported and it is not a release', () => {
  commit('two');
  assert.deepEqual(docsVersion(repo), { version: 'v1.8.1', isRelease: false });
});

test('with no tags at all the version is "main" and it is not a release', () => {
  git('tag', '-d', 'v1.8.1');
  assert.deepEqual(docsVersion(repo), { version: 'main', isRelease: false });
});

test('toEnv renders PUBLIC_ variables for Astro', () => {
  assert.equal(toEnv({ version: 'v1.8.1', isRelease: false }), 'PUBLIC_DOCS_VERSION=v1.8.1\nPUBLIC_DOCS_IS_RELEASE=false\n');
});
