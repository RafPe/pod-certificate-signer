import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { archiveTags, archiveBanner, routesIn } from './docs-archive.mjs';
import { versionDestination, menuVersions } from '../public/docs-version-picker.js';

test('version navigation preserves existing pages and falls back for missing pages', () => {
  const version = {base:'/project/v2.1.0',routes:['','getting-started/','guides/authentication/']};
  assert.equal(versionDestination(version,'/project/guides/authentication/','/project'),'/project/v2.1.0/guides/authentication/');
  assert.equal(versionDestination(version,'/project/interactive/request-flow/','/project'),'/project/v2.1.0/getting-started/');
  assert.equal(versionDestination({...version,base:'/v2.1.0'},'/guides/authentication/','/'),'/v2.1.0/guides/authentication/');
  assert.equal(versionDestination({base:'/project',routes:['']},'/project/v2.1.0/missing/','/project/v2.1.0'),'/project/');
});
test('historical navigation replaces the version picker without changing page content', () => {
  const html = '<head></head><body><header><a href="https://github.com/RafPe/pod-certificate-signer" rel="me">GitHub</a><select aria-label="Documentation version" data-docs-version data-current="current"><option>Development</option></select></header><main>Historical content</main></body>';
  const updated = archiveBanner(html,{tag:'v2.1.0',rootBase:'/project',base:'/project/v2.1.0'});
  assert(!updated.includes('Development'));
  assert(updated.includes('Historical content'));
  assert(updated.includes('data-current="v2.1.0"'));
  assert(updated.includes('src="/project/docs-version-picker.js"'));
  assert.equal(archiveBanner('<main>No banner</main>',{}),'<main>No banner</main>');
});
test('only stable tags with the website build files enter the archive', () => {
  const root=mkdtempSync(path.join(tmpdir(),'docs-tags-test-'));
  const git = (...args)=>execFileSync('git',['-C',root,...args],{stdio:'pipe',env:{...process.env,GIT_AUTHOR_NAME:'test',GIT_AUTHOR_EMAIL:'test@example.com',GIT_COMMITTER_NAME:'test',GIT_COMMITTER_EMAIL:'test@example.com'}});
  try {
    git('init','-q'); git('commit','--allow-empty','-qm','before docs'); git('tag','v1.0.0');
    mkdirSync(path.join(root,'website'));
    for(const file of ['package.json','package-lock.json','site.manifest.json']) writeFileSync(path.join(root,'website',file),'{}');
    git('add','.');git('commit','-qm','docs');
    for(const tag of ['v2.1.0','v2.2.0','v2.3.0-rc.1']) git('tag',tag);
    assert.deepEqual(archiveTags(root),['v2.2.0','v2.1.0']);
    mkdirSync(path.join(root,'dist/start'),{recursive:true});
    writeFileSync(path.join(root,'dist/index.html'),'');writeFileSync(path.join(root,'dist/start/index.html'),'');
    assert.deepEqual(routesIn(path.join(root,'dist')),['','start/']);
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('the menu limits releases to three and identifies an older current page', () => {
  const versions = ['current','v2.0.0','v2.9.0','v2.10.0','v3.0.0','v1.9.0'].map(id=>({id,label:id}));
  assert.deepEqual(menuVersions(versions,'current').map(v=>v.id),['current','v3.0.0','v2.10.0','v2.9.0']);
  const older = menuVersions(versions,'v1.9.0');
  assert.equal(older.length,5);
  assert.equal(older.at(-1).disabled,true);
  assert.equal(older.at(-1).label,'v1.9.0 (archived)');
  assert.equal(menuVersions(versions,'v3.0.0').length,4);
});

test('all versions exposes every release in version order', () => {
  const versions = ['current','v2.0.0','v2.9.0','v2.10.0','v3.0.0','v1.9.0'].map(id=>({id,label:id}));
  const all = menuVersions(versions,'v1.9.0',true);
  assert.deepEqual(all.map(v=>v.id),['current','v3.0.0','v2.10.0','v2.9.0','v2.0.0','v1.9.0']);
  assert.equal(all.at(-1).disabled,undefined);
  assert.equal(menuVersions(versions,'current',false).length,4);
});
