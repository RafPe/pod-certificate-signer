"""Check supported languages, exact code text, and missing-image failures."""
from pathlib import Path
import shutil
import subprocess
import sys
import struct
import tempfile
from render import text_card_lines

transcripts = {
    'two-commands': ("$ echo first\nfirst\n$ echo second\nsecond\n", ['command', 'output', 'command', 'output']),
    'backslash': ("$ printf '%s\\n' \\\n  'result'\nresult\n", ['command', 'command', 'output']),
    'single-quote': ("$ printf '%s\\n' 'first\nsecond'\nfirst\nsecond\n", ['command', 'command', 'output', 'output']),
    'no-prompt': ("plain output\nwith 'quotes'\n", ['command', 'command']),
}
for name, (code, expected) in transcripts.items():
    classified = text_card_lines(code)
    assert [line['kind'] for line in classified] == expected, (name, classified)
    assert ''.join(line['text'] for line in classified).encode() == code.encode()

shared = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='render-check-', dir=shared) as scratch:
    base = Path(scratch)
    (base / 'assets').mkdir()
    shutil.copyfile(shared / 'sample/assets/cover.svg', base / 'assets/cover.svg')
    source = '# Test article\r\n![cover](assets/cover.png)\r\n\r\n'
    for language in ['sh', 'yaml', 'text', 'promql', 'json']:
        source += (f'![{language} & text](assets/{language}.png)\r\n```{language}\r\n'
                   '\r\n\t<&> "quotes"  \r\nlast line\r\n```\r\n\r\n')
    source += '![Boundary](assets/boundary.png)\r\n```text\r\n' + ('x' * 90 + '\r\n') * 25 + '```\r\n'
    source += ('\n| File | Purpose | Inspection |\n| --- | --- | --- |\n'
               '| `preview.html` | ' + 'Long cell text must remain inside its cell. ' * 8
               + '| ' + '`spiffe://cluster.local/ns/default/sa/long_service-account.name,other:identifier`' + ' |\n\n'
               '| Name | Value |\n| --- | --- |\n| Second table | Document order |\n')
    for name, (code, _) in transcripts.items():
        source += f'\n![{name}](assets/{name}.png)\n```text\n{code}```\n'
    (base / 'article.md').write_bytes(source.encode())
    command = [sys.executable, str(shared / 'render.py'), str(base)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    for name, (code, expected) in transcripts.items():
        rendered = (base / f'assets/{name}.html').read_text()
        assert rendered.count('class="transcript-output"') == expected.count('output')
        assert rendered.count('class="transcript-command"') == expected.count('command')
        assert rendered.count('class="transcript-prompt"') == sum(line['prompt'] for line in text_card_lines(code))
    assert 'class="transcript-' not in (base / 'assets/sh.html').read_text()
    print('PASS: transcript commands, output, continuations, quoted arguments, and prompt-free text retain exact bytes.')
    widths = {struct.unpack('>II', path.read_bytes()[16:24])[0] for path in (base / 'assets').glob('*.png') if path.name != 'cover.png'}
    assert len(widths) == 1, f'Card widths differ: {widths}'
    assert struct.unpack('>II', (base / 'card-inspection.png').read_bytes()[16:24])[0] == 744
    preview = (base / 'preview.html').read_text()
    assert preview.count('View the table as text') == 2
    assert preview.index('assets/table-1.png') < preview.index('assets/table-2.png')
    table_html = (base / 'assets/table-1.html').read_text()
    assert '<header>' not in table_html
    assert 'table-layout:auto' in table_html
    assert '<span class="identifier-part">preview.</span><wbr><span class="identifier-part">html</span>' in table_html
    assert 'overflow-wrap:anywhere' not in table_html
    assert 'identifier-part{white-space:nowrap}' in table_html
    gallery = (base / 'card-inspection.html').read_text()
    assert 'assets/table-1.png' in gallery and 'assets/table-2.png' in gallery
    print('PASS: three-column tables wrap long text, preserve inline code, and appear in the preview and gallery.')
    print('PASS: 90 characters and 25 lines render without wrapping, with uniform card widths and a 744px gallery.')
    print('PASS: all five languages preserve CRLF, tabs, blank lines, spaces, and HTML characters.')
    (base / 'article.md').write_bytes((source + '\r\n![Missing](assets/missing.png)\r\n').encode())
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0, 'Missing image must fail.'
    assert 'Missing image referenced by article.md: assets/missing.png' in result.stderr, result.stderr
    print('PASS: missing image fails with its source path.')

    for code, expected in [('x' * 91 + '\n', ':6: assets/limit.png: code line has 91 characters'),
                           ('x\n' * 26, ':31: assets/limit.png: code block has 26 lines')]:
        limit_source = '# Limits\n![cover](assets/cover.png)\n\n![Limit](assets/limit.png)\n```text\n' + code + '```\n'
        (base / 'article.md').write_text(limit_source)
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode != 0, 'An oversized card must fail.'
        assert expected in result.stderr, result.stderr
    print('PASS: 91 characters and 26 lines fail with the exact article line number.')

    (base / 'article.md').write_text('# Limits\n![cover](assets/cover.png)\n\n| Key | Value |\n| --- | --- |\n| ID | `' + 'a' * 200 + '` |\n')
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Table cannot fit the common card width' in result.stderr, result.stderr
    print('PASS: an identifier wider than the entire card fails instead of clipping or splitting letters.')
