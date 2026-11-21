import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sidebarFromManifest } from './sidebar.mjs';

const manifest = {
  groups: ['Start', 'Guides'],
  pages: [
    { source: 'docs/b.md', route: 'guides/b', group: 'Guides', label: 'B', order: 2 },
    { source: 'docs/a.md', route: 'guides/a', group: 'Guides', label: 'A', order: 1 },
    { source: 'docs/s.md', route: 'start/s', group: 'Start', label: 'S', order: 1 },
  ],
};

test('groups follow manifest order and pages sort by order within a group', () => {
  const sb = sidebarFromManifest(manifest);
  assert.deepEqual(sb.map((g) => g.label), ['Start', 'Guides']);
  assert.deepEqual(sb[1].items.map((i) => i.label), ['A', 'B']);
});

test('items link to the route as a slug', () => {
  const sb = sidebarFromManifest(manifest);
  assert.deepEqual(sb[0].items[0], { label: 'S', slug: 'start/s' });
});

test('a page whose group is not declared throws', () => {
  assert.throws(() => sidebarFromManifest({ groups: ['Start'], pages: [{ route: 'x', group: 'Nope', label: 'x', order: 1 }] }), /Nope/);
});
