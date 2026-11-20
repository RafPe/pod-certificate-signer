import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const github = 'https://github.com/RafPe/pod-certificate-signer';
const website = fileURLToPath(new URL('../', import.meta.url));
const imageExtensions = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif']);
const markdownTokens = /^(?<fence>`{3,}|~{3,})[^\n]*\n[\s\S]*?^[ \t]*\k<fence>[ \t]*$|(?<tick>`+)[^\n]+?\k<tick>|(?<image>!)?\[(?<label>[^\]]*)\]\((?<target>[^)\s]+)(?<title>\s+"[^"]*")?\)/gm;

function clearMarkdown(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) clearMarkdown(filename);
    else if (entry.name.endsWith('.md')) rmSync(filename);
  }
}

function readSource(repoRoot, source) {
  const raw = readFileSync(path.join(repoRoot, source), 'utf8').replace(/\r\n/g, '\n');
  const metadata = raw.match(/^---\n([\s\S]*?)\n---\n/);
  const markdown = (metadata ? raw.slice(metadata[0].length) : raw).trimStart();
  const heading = markdown.match(/^# (.+)\n/);
  if (!heading) throw new Error(`Missing leading H1 in ${source}`);

  const title = heading[1].replaceAll('`', '');
  const body = markdown.slice(heading[0].length).trimStart();
  const decision = metadata?.[1].split('\n').map((line) => {
    const [key, value] = line.split(/:\s+/, 2);
    const labels = { status: 'Status', date: 'Date', 'decision-makers': 'Decision-makers' };
    return labels[key] ? `- **${labels[key]}** — ${value}` : '';
  }).filter(Boolean).join('\n');
  return { title, body, decision };
}

function describe(body) {
  const paragraph = body.split(/\n\s*\n/, 1)[0];
  if (/^(#|-|\*|\||>|!|```|<|\d+\.)/.test(paragraph)) return '';
  const text = paragraph.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*]/g, '').replace(/\s+/g, ' ').trim();
  return text.length > 160 ? text.slice(0, 157).replace(/\s+\S*$/, '') + '…' : text;
}

function lastUpdated(repoRoot, source) {
  try {
    return execFileSync('git', ['-C', repoRoot, 'log', '-1', '--format=%cs', '--', source], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return '';
  }
}

function relativeRoute(from, to) {
  const relative = path.posix.relative(`/${from}`, `/${to}`);
  return relative ? `${relative}/` : './';
}

function rewriteLinks(body, { repoRoot, imgDir, page, bySource, outputFile, images }) {
  const rewrite = (match, ...args) => {
    const { image, label, target, title = '' } = args.at(-1);
    if (!target || /^(?:[\w+.-]+:|#|\/)/.test(target)) return match;

    const [, pathname, suffix] = target.match(/^([^?#]+)(.*)$/);
    const input = path.resolve(repoRoot, path.dirname(page.source), decodeURIComponent(pathname));
    const source = path.relative(repoRoot, input).split(path.sep).join('/');
    if (source === '..' || source.startsWith('../')) {
      throw new Error(`${page.source} links outside the repository to ${target}`);
    }
    const file = statSync(input, { throwIfNoEntry: false });
    if (!file) throw new Error(`${page.source} links to missing file ${target}`);

    let href;
    if (image) {
      const output = path.join(imgDir, source);
      images.set(output, input);
      href = path.relative(path.dirname(outputFile), output).split(path.sep).join('/');
    } else if (bySource.has(source)) {
      href = relativeRoute(page.route, bySource.get(source).route);
    } else {
      const kind = file.isDirectory() ? 'tree' : 'blob';
      const encoded = source.split('/').map(encodeURIComponent).join('/');
      const host = imageExtensions.has(path.extname(source).toLowerCase())
        ? `${github}/raw/main`
        : `${github}/${kind}/main`;
      href = `${host}/${encoded}`;
    }
    return `${image ?? ''}[${label}](${href}${suffix}${title})`;
  };
  return body.replace(markdownTokens, rewrite);
}

export function stage({
  repoRoot = path.resolve(website, '..'),
  manifestPath = path.join(website, 'site.manifest.json'),
  outDir = path.join(website, 'src/content/docs'),
  imgDir = path.join(website, 'src/assets/img'),
} = {}) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const pages = manifest.pages.filter((page) => page.source);
  const bySource = new Map(pages.map((page) => [page.source, page]));
  const images = new Map();
  const staged = pages.map((page) => {
    const { title, body, decision } = readSource(repoRoot, page.source);
    const outputFile = path.join(outDir, `${page.route}.md`);
    const rewritten = rewriteLinks(body, { repoRoot, imgDir, page, bySource, outputFile, images });
    const description = describe(rewritten);
    const date = lastUpdated(repoRoot, page.source);
    const editUrl = `${github}/edit/main/${page.source}`;
    const frontmatter = [
      '---',
      `title: ${JSON.stringify(title)}`,
      description && `description: ${JSON.stringify(description)}`,
      `editUrl: ${JSON.stringify(editUrl)}`,
      date && `lastUpdated: ${date}`,
      'sidebar:',
      `  order: ${page.order}`,
      '---',
    ].filter(Boolean).join('\n');
    const rendered = [frontmatter, decision, rewritten.trimEnd()].filter(Boolean).join('\n\n') + '\n';
    return { ...page, title, outputFile, rendered };
  });

  // The content directory also contains authored .mdx pages.
  mkdirSync(outDir, { recursive: true });
  clearMarkdown(outDir);
  rmSync(imgDir, { recursive: true, force: true });
  for (const [output, input] of images) {
    mkdirSync(path.dirname(output), { recursive: true });
    copyFileSync(input, output);
  }
  for (const { outputFile, rendered } of staged) {
    mkdirSync(path.dirname(outputFile), { recursive: true });
    writeFileSync(outputFile, rendered);
  }
  return { pages: staged.map(({ outputFile, rendered, ...page }) => page) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { pages } = stage();
  console.log(`stage: wrote ${pages.length} pages`);
}
