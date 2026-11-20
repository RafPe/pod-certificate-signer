import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stage } from './stage.mjs';

let root;
const write = (file, text) => {
  mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  writeFileSync(path.join(root, file), text);
};
const run = (pages) => {
  write('website/site.manifest.json', JSON.stringify({ groups: ['Guides'], pages }));
  return stage({
    repoRoot: root,
    manifestPath: path.join(root, 'website/site.manifest.json'),
    outDir: path.join(root, 'website/src/content/docs'),
    imgDir: path.join(root, 'website/src/assets/img'),
  });
};
const staged = (route) => readFileSync(path.join(root, 'website/src/content/docs', `${route}.md`), 'utf8');

beforeEach(() => { root = mkdtempSync(path.join(tmpdir(), 'stage-')); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

test('the H1 becomes the title and the first paragraph the description', () => {
  write('docs/a.md', '# The `A` guide\n\nFirst paragraph.\n\n## Next\n');
  run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]);
  const out = staged('a');
  assert.match(out, /^title: "The A guide"$/m);
  assert.match(out, /^description: "First paragraph."$/m);
  assert.doesNotMatch(out, /^# The/m);
});

test('a link to another staged page becomes a relative route and keeps its anchor', () => {
  write('docs/a.md', '# A\n\nSee [B](b.md#part).\n');
  write('docs/b.md', '# B\n\nText.\n');
  run([
    { source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 },
    { source: 'docs/b.md', route: 'nested/b', group: 'Guides', label: 'B', order: 2 },
  ]);
  assert.match(staged('a'), /\[B\]\(\.\.\/nested\/b\/#part\)/);
});

test('a link to a file that is not staged points to GitHub', () => {
  write('docs/a.md', '# A\n\nSee [the ADR](adr/0001.md).\n');
  write('docs/adr/0001.md', '# ADR\n');
  run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]);
  assert.match(staged('a'), /https:\/\/github\.com\/RafPe\/pod-certificate-signer\/blob\/main\/docs\/adr\/0001\.md/);
});

test('links inside code are not rewritten', () => {
  write('docs/a.md', '# A\n\n```md\n[x](missing.md)\n```\n\n`[y](missing.md)`\n');
  run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]);
  assert.match(staged('a'), /\[x\]\(missing\.md\)/);
});

test('an image is copied next to the content', () => {
  write('docs/a.md', '# A\n\n![shot](assets/shot.png)\n');
  write('docs/assets/shot.png', 'png');
  run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]);
  assert(existsSync(path.join(root, 'website/src/assets/img/docs/assets/shot.png')));
});

test('a missing link target, a link outside the repository and a missing H1 fail the build', () => {
  write('docs/a.md', '# A\n\n[gone](gone.md)\n');
  assert.throws(() => run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]), /missing file/);
  write('docs/a.md', '# A\n\n[out](../../x.md)\n');
  assert.throws(() => run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]), /outside the repository/);
  write('docs/a.md', 'No heading\n');
  assert.throws(() => run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]), /Missing leading H1/);
});

test('authored .mdx pages survive a restage', () => {
  write('website/src/content/docs/interactive/x.mdx', '---\ntitle: X\n---\n');
  write('docs/a.md', '# A\n\nText.\n');
  run([{ source: 'docs/a.md', route: 'a', group: 'Guides', label: 'A', order: 1 }]);
  assert(existsSync(path.join(root, 'website/src/content/docs/interactive/x.mdx')));
});
