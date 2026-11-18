#!/usr/bin/env python3
"""Render article images and a standalone HTML preview."""
import argparse
import html
import math
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

SHARED = Path(__file__).resolve().parent


def enter_environment():
    """Use the external virtual environment when Python starts outside it."""
    environment = Path(os.environ.get('PCS_ARTICLE_VENV', '/tmp/pcs-article-toolkit-venv'))
    if Path(sys.prefix).resolve() != environment.resolve():
        executable = environment / 'bin/python'
        if not executable.exists():
            raise ValueError(f'Create the external environment first. See {SHARED / "README.md"}')
        os.execv(str(executable), [str(executable), str(Path(__file__).resolve()), *sys.argv[1:]])


def local_image(base, source):
    parsed = urlsplit(source)
    if parsed.scheme or parsed.netloc or source.startswith('/'):
        raise ValueError(f'Use a relative local image path: {source}')
    return (base / unquote(parsed.path)).resolve()


def document(body, css, title):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{css}</style></head><body>{body}</body></html>')



def text_card_lines(code):
    """Classify transcript lines without changing their text or line endings."""
    lines = code.splitlines(keepends=True)
    if not any(line.startswith('$ ') for line in lines):
        return [dict(text=line, kind='command', prompt=False) for line in lines]
    result = []
    quote = None
    continuation = False
    for line in lines:
        prompt = line.startswith('$ ') and not continuation
        command = prompt or continuation
        result.append(dict(text=line, kind='command' if command else 'output', prompt=prompt))
        if not command:
            continue
        body = line[2:] if prompt else line
        body = body.rstrip('\r\n')
        escaped = False
        for char in body:
            if quote == "'":
                if char == "'":
                    quote = None
            elif escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
        continuation = bool(quote or escaped)
    return result


def render(base):
    import markdown
    from playwright.sync_api import sync_playwright

    source = (base / 'article.md').read_bytes().decode('utf-8')
    cards = []
    table_cards = []
    card_sections = {}
    card_errors = []
    # The block body remains untouched, including tabs and final line endings.
    pattern = re.compile(r'^!\[([^\]\n]*)\]\(([^)\n]+)\)[ \t]*\r?\n(?:[ \t]*\r?\n)*'
                         r'(?P<fence>`{3,}|~{3,})(sh|yaml|text|promql|json)[ \t]*\r?\n'
                         r'(.*?)^(?P=fence)[ \t]*(?:\r?\n|$)', re.M | re.S)

    def replace_card(match):
        title, filename, _, language, code = match.groups()
        first_line = source.count('\n', 0, match.start(5)) + 1
        lines = code.splitlines()
        for offset, line in enumerate(lines):
            length = len(line.expandtabs(4))
            if length > 90:
                card_errors.append(
                    f'{base / "article.md"}:{first_line + offset}: '
                    f'{filename}: code line has {length} characters (maximum 90).')
        if len(lines) > 25:
            card_errors.append(
                f'{base / "article.md"}:{first_line + 25}: '
                f'{filename}: code block has {len(lines)} lines (maximum 25).')
        path = local_image(base, filename)
        if path.suffix.lower() != '.png' or not path.is_relative_to(base / 'assets'):
            raise ValueError(f'Code card must use assets/*.png: {filename}')
        if any(card['path'] == path for card in cards):
            raise ValueError(f'Duplicate code-card path: {filename}')
        escaped = html.escape(code).replace('\r', '&#13;')
        assert html.unescape(escaped).encode('utf-8') == code.encode('utf-8')
        cards.append(dict(title=title, filename=filename, path=path, language=language, code=code, escaped=escaped))
        marker = f'PCSCARDSECTION{len(cards)}END'
        card_sections[marker] = (f'{figure(filename, title)}\n<details class="src"><summary>View and copy the code</summary>'
                f'<pre class="code"><code>{escaped}</code></pre></details>')
        return f'\n\n{marker}\n\n'

    def figure(filename, alt, cover=False):
        filename, alt = html.escape(filename, quote=True), html.escape(alt, quote=True)
        cls = ' class="cover"' if cover else ''
        return f'<figure{cls}><a href="{filename}" target="_blank" rel="noopener"><img src="{filename}" alt="{alt}"></a></figure>'

    transformed = pattern.sub(replace_card, source)
    if card_errors:
        raise ValueError('\n' + '\n'.join(card_errors))
    body = markdown.markdown(transformed, extensions=['fenced_code', 'tables'])
    def replace_table(match):
        number = len(table_cards) + 1
        filename = f'assets/table-{number}.png'
        path = base / filename
        if path in [card['path'] for card in cards]:
            raise ValueError(f'Table filename conflicts with a code card: {filename}')
        table = match[0]
        label = f'Table {number}'
        table_cards.append(dict(filename=filename, path=path, title=label, table=table))
        return (figure(filename, label)
                + '<details class="table-src"><summary>View the table as text</summary>'
                + f'<div class="table-wrap">{table}</div></details>')

    body = re.sub(r'<table>.*?</table>', replace_table, body, flags=re.S)
    for marker, section in card_sections.items():
        body = body.replace(f'<p>{marker}</p>', section)
    body = re.sub(r'<p><img alt="([^"]*)" src="([^"]*)" /></p>',
                  lambda m: figure(html.unescape(m[2]), html.unescape(m[1])), body)
    heading = re.search(r'<h1>(.*?)</h1>', body, re.S)
    if not heading:
        raise ValueError('article.md must contain an H1 title.')
    title = re.sub('<[^>]+>', '', heading[1])
    cover = re.search(r'</h1>\s*(<figure>.*?</figure>)', body, re.S)
    if not cover:
        raise ValueError('Place the cover image directly after the H1 title.')
    cover_html = cover[1].replace('<figure>', '<figure class="cover">', 1)
    body = body[:cover.start(1)] + body[cover.end(1):]
    body = body.replace(heading[0], '<h1>' + re.sub(r'^(\S+)', r'<span class="lead">\1</span>', heading[1])
                        + '</h1><p class="byline">Rafal Pieniazek</p>', 1)
    css = (SHARED / 'preview.css').read_text()
    preview = document(f'<div class="stripe"></div><main class="wrap">{cover_html}<article>{body}</article></main>', css, title)
    card_css = '''body{margin:0;background:linear-gradient(120deg,#faf6ea,#f3ebd6);color:#1f2a44;font-family:ui-rounded,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:var(--card-width);padding:0 16px 24px;box-sizing:border-box}.stripe{height:8px;margin:0 -16px;background:linear-gradient(90deg,#2f63d6,#2a9d5c)}header{padding:24px 8px;font-size:24px;font-weight:700}header span{color:#5b6785;font-size:18px;font-weight:400}pre{margin:0;padding:16px;background:white;border:1px solid #e3ddcb;border-radius:18px;font:20px/1.5 Menlo,Consolas,monospace;white-space:pre;overflow-wrap:normal;tab-size:4}pre code{font:inherit}'''
    with sync_playwright() as pw:
        browser_path = os.environ.get('PCS_ARTICLE_BROWSER')
        options = {'executable_path': browser_path} if browser_path else {}
        browser = pw.chromium.launch(**options)
        context = browser.new_context(viewport={'width': 1400, 'height': 900}, device_scale_factor=2)
        context.route(re.compile(r'^https?://'), lambda route: route.abort())
        page = context.new_page()
        page.set_content(document('<pre><code>' + '0' * 90 + '</code></pre>', card_css, 'Measure code'))
        page.evaluate('document.fonts.ready')
        line_width = page.locator('code').evaluate('(node) => node.getBoundingClientRect().width')
        # Two card margins, two code paddings, and two border pixels surround the 90 columns.
        card_width = math.ceil(line_width) + 66
        text_size = 20 * 744 / card_width
        if text_size < 12.5:
            raise ValueError(f'Code text at 744px is {text_size:.2f}px (minimum 12.5px).')
        card_css += f':root{{--card-width:{card_width}px}}'
        card_css += '.transcript-output{color:#5b6785}.transcript-command{color:#1f2a44}.transcript-prompt{color:#2f63d6}'
        print(f'Card width: {card_width}px for 90 characters. Code text at 744px: {text_size:.2f}px.')
        for card in cards:
            card['path'].parent.mkdir(parents=True, exist_ok=True)
            card_body = (f'<div class="card"><div class="stripe"></div><header>{html.escape(card["title"])} '
                         f'<span>{card["language"]}</span></header><pre><code></code></pre></div>')
            card_html = document(card_body, card_css, card['title'])
            page.set_content(card_html)
            # DOM assignment avoids HTML's removal of the first newline in a pre element.
            page.locator('code').evaluate('(node, text) => node.textContent = text', card['code'])
            if card['language'] == 'text':
                page.locator('code').evaluate('''(node, lines) => {
                    node.replaceChildren();
                    lines.forEach(line => {
                        const span = document.createElement('span');
                        span.className = 'transcript-' + line.kind;
                        if (line.prompt) {
                            const prompt = document.createElement('span');
                            prompt.className = 'transcript-prompt';
                            prompt.textContent = '$';
                            span.append(prompt, document.createTextNode(line.text.slice(1)));
                        } else {
                            span.textContent = line.text;
                        }
                        node.append(span);
                    });
                }''', text_card_lines(card['code']))
            actual = page.locator('code').text_content().encode('utf-8')
            assert actual == card['code'].encode('utf-8'), f'Code text mismatch: {card["filename"]}'
            if not page.locator('pre').evaluate('(node) => node.scrollWidth <= node.clientWidth'):
                raise ValueError(f'Code exceeds the fixed card width: {card["filename"]}')
            card['path'].with_suffix('.html').write_text(page.content(), encoding='utf-8')
            page.locator('.card').screenshot(path=str(card['path']))
        table_font = math.ceil(14 * card_width / 744)
        table_text_size = table_font * 744 / card_width
        table_css = card_css + (
            f'table{{width:100%;table-layout:auto;border-collapse:collapse;font-size:{table_font}px;line-height:1.5}}'
            '.table-panel{background:white;border:1px solid #e3ddcb;border-radius:18px;overflow:hidden}'
            'th,td{padding:16px;text-align:left;vertical-align:top;border:1px solid #e3ddcb;'
            'white-space:normal;overflow-wrap:normal;word-break:normal}'
            'th{font-weight:700;background:#e8efff}td{font-weight:400}'
            'td code,th code{font-family:Menlo,Consolas,monospace;font-size:1em;color:#2f63d6}'
            'code .identifier-part{white-space:nowrap}.table-card .stripe{margin-bottom:16px}')
        for card in table_cards:
            card['path'].parent.mkdir(parents=True, exist_ok=True)
            card_body = (f'<div class="card table-card"><div class="stripe"></div>'
                         f'<div class="table-panel">{card["table"]}</div></div>')
            page.set_content(document(card_body, table_css, card['title']))
            page.locator('td code, th code').evaluate_all(r'''(nodes) => nodes.forEach(node => {
                const original = node.textContent;
                const parts = original.match(/[^./:,\-_]*[./:,\-_]|[^./:,\-_]+$/g) || [];
                node.replaceChildren();
                parts.forEach(part => {
                    const span = document.createElement('span');
                    span.className = 'identifier-part';
                    span.textContent = part;
                    node.append(span);
                    if (/[./:,\-_]$/.test(part)) node.append(document.createElement('wbr'));
                });
                if (node.textContent !== original) throw new Error('Table code text changed');
            })''')
            page.evaluate('document.fonts.ready')
            if not page.locator('.table-panel').evaluate('(n) => n.scrollWidth <= n.clientWidth'):
                raise ValueError(f'Table cannot fit the common card width without splitting an identifier: {card["filename"]}')
            assert page.locator('td, th').evaluate_all(
                '(cells) => cells.every(c => c.scrollWidth <= c.clientWidth && c.scrollHeight <= c.clientHeight)'), \
                f'Table cell overflow: {card["filename"]}'
            card['path'].with_suffix('.html').write_text(page.content(), encoding='utf-8')
            page.locator('.card').screenshot(path=str(card['path']))
        print(f'Table body text at 744px: {table_text_size:.2f}px.')
        for svg in sorted((base / 'assets').glob('*.svg')):
            if svg.with_suffix('.png') in [c['path'] for c in cards + table_cards]:
                raise ValueError(f'Diagram conflicts with a code card: {svg.name}')
            page.goto(svg.as_uri())
            page.evaluate('document.fonts.ready')
            page.locator('svg').screenshot(path=str(svg.with_suffix('.png')))
        for image_source in re.findall(r'<img\b[^>]*\bsrc="([^"]+)"', preview):
            image_path = local_image(base, html.unescape(image_source))
            if not image_path.is_file():
                raise ValueError(f'Missing image referenced by article.md: {image_source} ({image_path})')
        (base / 'preview.html').write_text(preview, encoding='utf-8')
        gallery_css = ('body{margin:0;background:#faf6ea;color:#1f2a44;font-family:system-ui,sans-serif}'
                       'main{width:744px;max-width:100%;margin:auto}h1{font-size:24px;padding:16px}'
                       'p{padding:0 16px}figure{margin:24px 0}img{display:block;width:100%;height:auto}')
        gallery_body = (f'<main><h1>Card inspection</h1><p>Code text at 744 px: {text_size:.2f} px. '
                        f'Table text: {table_text_size:.2f} px. All cards use a {card_width} px source width.</p>'
                        + ''.join(figure(c['filename'], c['title']) for c in cards + table_cards) + '</main>')
        (base / 'card-inspection.html').write_text(
            document(gallery_body, gallery_css, 'Card inspection'), encoding='utf-8')
        context.close()
        context = browser.new_context(device_scale_factor=1)
        context.route(re.compile(r'^https?://'), lambda route: route.abort())
        page = context.new_page()
        for name, width, height in [('desktop', 1200, 1000), ('mobile', 390, 844)]:
            page.set_viewport_size({'width': width, 'height': height})
            page.goto((base / 'preview.html').as_uri())
            page.wait_for_function('Array.from(document.images).every(i => i.complete && i.naturalWidth > 0)')
            assert page.locator('details.src').count() == len(cards)
            for index, card in enumerate(cards):
                actual = page.locator('details.src code').nth(index).text_content()
                assert actual.encode('utf-8') == card['code'].encode('utf-8'), 'Copyable code differs from source.'
            assert page.locator('details.table-src').count() == len(table_cards)
            for index, card in enumerate(table_cards):
                assert page.locator('details.table-src table').nth(index).evaluate('(n) => n.outerHTML') == card['table']
            for expanded in [False, True]:
                page.locator('details.src, details.table-src').evaluate_all('(nodes, state) => nodes.forEach(n => n.open = state)', expanded)
                if not page.evaluate('document.documentElement.scrollWidth <= innerWidth'):
                    raise ValueError(f'Horizontal overflow at {width}px (code expanded: {expanded}).')
            page.locator('details.src, details.table-src').evaluate_all('(nodes) => nodes.forEach(n => n.open = false)')
            page.screenshot(path=str(base / f'{name}.png'), full_page=True)
        page.set_viewport_size({'width': 744, 'height': 1})
        page.goto((base / 'card-inspection.html').as_uri())
        page.wait_for_function('Array.from(document.images).every(i => i.complete && i.naturalWidth > 0)')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(base / 'card-inspection.png'), full_page=True)
        browser.close()
    print(f'Rendered {base}: {len(cards)} code cards, {len(table_cards)} table cards, diagrams at 2x, desktop and mobile without horizontal overflow.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('article_dir', type=Path)
    args = parser.parse_args()
    enter_environment()
    render(args.article_dir.resolve())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, AssertionError) as error:
        sys.exit(f'Render failed: {error}')
