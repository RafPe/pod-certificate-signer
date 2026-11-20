import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdtempSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { docsVersion } from './version.mjs';

const git = (root, ...args) => execFileSync('git',['-C',root,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
export function archiveTags(root) {
  return git(root,'tag','--list','v*','--sort=-version:refname').split('\n').filter(tag => /^v\d+\.\d+\.\d+$/.test(tag)).filter(tag => {
    return ['website/package.json','website/package-lock.json','website/site.manifest.json'].every(file => {
      try { git(root,'cat-file','-e',`${tag}:${file}`); return true; } catch { return false; }
    });
  });
}
export function routesIn(dir, prefix = '') {
  return readdirSync(dir,{withFileTypes:true}).flatMap(entry => {
    if (entry.isDirectory()) return routesIn(path.join(dir,entry.name),`${prefix}${entry.name}/`);
    return entry.name === 'index.html' ? [prefix] : [];
  });
}
export function archiveBanner(html, {tag, rootBase, base}) {
  const picker = `<select aria-label="Documentation version" data-docs-version data-root="${rootBase}" data-base="${base}" data-current="${tag}"><option value="${tag}">${tag}</option></select>`;
  const github = /<a\b(?=[^>]*href="https:\/\/github.com\/RafPe\/pod-certificate-signer")(?=[^>]*rel="me")[^>]*>[\s\S]*?<\/a>/g;
  if (!html.match(github)) return html;
  // Historical content stays at its tag. Only the shared version navigation changes.
  return html.replace(/<select\b[^>]*data-docs-version[^>]*>[\s\S]*?<\/select>/g,'')
    .replace(github,link => link + picker)
    .replace(/<script\b[^>]*src="[^"]*\/docs-version-picker\.js"[^>]*><\/script>/g,'')
    .replace(/<link\b[^>]*href="[^"]*\/docs-version-picker\.css"[^>]*>/g,'')
    .replace('</head>',`<link rel="stylesheet" href="${rootBase}/docs-version-picker.css"></head>`)
    .replace('</body>',`<script type="module" src="${rootBase}/docs-version-picker.js"></script></body>`);
}
function visitHtml(dir, change) {
  for(const entry of readdirSync(dir,{withFileTypes:true})) {
    const file = path.join(dir,entry.name);
    if(entry.isDirectory()) visitHtml(file,change);
    else if(entry.name.endsWith('.html')) writeFileSync(file,change(readFileSync(file,'utf8')));
  }
}
export function buildArchives({root, base = '/pod-certificate-signer', site = 'https://rafpe.github.io'}) {
  const rootBase = base.replace(/\/$/,'');
  const dist = path.join(root,'website/dist');
  if(!existsSync(path.join(dist,'index.html'))) throw new Error('Build the current website before its archives.');
  // Repeated local runs replace only directories recorded by this script.
  const previous = JSON.parse(readFileSync(path.join(dist,'docs-versions.json'),'utf8'));
  for(const version of previous.versions) if(/^v\d+\.\d+\.\d+$/.test(version.id)) rmSync(path.join(dist,version.id),{recursive:true,force:true});
  const current = docsVersion(root);
  const versions = [{id:'current',label:current.isRelease ? `${current.version} (current)` : 'Development',base:rootBase,routes:routesIn(dist)}];
  const temp = mkdtempSync(path.join(tmpdir(),'docs-archives-'));
  try {
    for(const tag of archiveTags(root)) {
      const checkout = path.join(temp,tag);
      console.log(`docs-archive: build ${tag}`);
      execFileSync('git',['clone','--shared','--quiet','--no-checkout',root,checkout],{stdio:'inherit'});
      execFileSync('git',['-C',checkout,'checkout','--quiet','--detach',tag],{stdio:'inherit'});
      const website = path.join(checkout,'website');
      const versionBase = `${rootBase}/${tag}`;
      execFileSync('npm',['ci','--no-audit','--no-fund'],{cwd:website,stdio:'inherit'});
      execFileSync('npm',['run','build','--','--site',site,'--base',versionBase],{cwd:website,stdio:'inherit'});
      const output = path.join(website,'dist');
      if(!existsSync(path.join(output,'index.html'))) throw new Error(`No website output for ${tag}.`);
      visitHtml(output,html => archiveBanner(html,{tag,rootBase,base:versionBase}));
      versions.push({id:tag,label:tag,base:versionBase,routes:routesIn(output)});
      cpSync(output,path.join(dist,tag),{recursive:true});
      rmSync(checkout,{recursive:true,force:true});
    }
    writeFileSync(path.join(dist,'docs-versions.json'),JSON.stringify({versions},null,2)+'\n');
  } finally { rmSync(temp,{recursive:true,force:true}); }
  console.log(`docs-archive: ${versions.length - 1} tagged sites ready`);
}
if(process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const value = (flag,fallback) => process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag)+1] : fallback;
  buildArchives({root:path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),base:value('--base','/pod-certificate-signer'),site:value('--site','https://rafpe.github.io')});
}
