"""Validate every published HTML page, linked document and sitemap route."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import json
import re
import xml.etree.ElementTree as ET
from build_docs import ROUTES, TRACKING_ID, outputs
from doc_render import render_document

ROOT = Path(__file__).resolve().parent
ORIGIN = 'https://intertexum.com/'


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []
        self.ids = set()
        self.structured = []
        self.in_json = False
        self.part = []
        self.canonical = None
        self.description = None
        self.h1_count = 0
        self.lang = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.refs.extend(a[k] for k in ('href', 'src') if k in a)
        if 'id' in a:
            assert a['id'] not in self.ids, 'duplicate ID ' + a['id']
            self.ids.add(a['id'])
        if tag == 'script' and a.get('type') == 'application/ld+json':
            self.in_json = True
        if tag == 'img':
            assert 'alt' in a, 'image needs alternative text'
        if tag == 'html':
            self.lang = a.get('lang')
        if tag == 'h1':
            self.h1_count += 1
        if tag == 'link' and a.get('rel') == 'canonical':
            self.canonical = a.get('href')
        if tag == 'meta' and a.get('name') == 'description':
            self.description = a.get('content')

    def handle_data(self, data):
        if self.in_json:
            self.part.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.in_json:
            self.structured.append(json.loads(''.join(self.part)))
            self.part = []
            self.in_json = False


def markdown_ids(path):
    fragment = render_document(path.read_text(), path.relative_to(ROOT).as_posix(), ROUTES)
    page = Page()
    page.feed(fragment['body_html'])
    return page.ids


pages = {}
for path in ROOT.rglob('*.html'):
    if any(part.startswith('.') or part == '__pycache__' for part in path.relative_to(ROOT).parts):
        continue
    page = Page()
    content = path.read_text()
    page.feed(content)
    tracking_url = f'https://www.googletagmanager.com/gtag/js?id={TRACKING_ID}'
    assert content.count(tracking_url) == 1, f'{path}: expected exactly one Google tag loader'
    assert content.count(f"gtag('config', '{TRACKING_ID}')") == 1, f'{path}: expected one tracking configuration'
    assert content.index(tracking_url) < content.index('</head>'), f'{path}: Google tag must be in head'
    pages[path.resolve()] = page
    relative = path.relative_to(ROOT).as_posix()
    expected = ORIGIN + ('' if relative == 'index.html' else relative)
    assert page.lang == 'en' and page.h1_count == 1, path.name
    assert page.description and page.canonical == expected, path.name
    assert page.structured and page.structured[0]['name'] == 'Intertexum', path.name
    assert page.structured[0]['url'] == expected, path.name


def check_ref(source, ref):
    url = urlsplit(ref)
    if url.scheme or url.netloc:
        return
    if url.path.startswith('/'):
        target = (ROOT / unquote(url.path).lstrip('/')).resolve()
    else:
        target = (source.parent / unquote(url.path)).resolve() if url.path else source.resolve()
    assert target.is_relative_to(ROOT) and target.is_file(), (source.name, ref)
    if url.fragment:
        if target in pages:
            assert unquote(url.fragment) in pages[target].ids, (source.name, ref)
        elif target.suffix == '.md':
            assert unquote(url.fragment) in markdown_ids(target), (source.name, ref)


for path, page in pages.items():
    for ref in page.refs:
        check_ref(path, ref)
manifest = json.loads((ROOT / 'agent.json').read_text())
assert manifest['name'] == 'Intertexum' and manifest['runtime']['command'] == 'intertexum'
for key in ('instructions', 'instructions_alias', 'specification', 'setup',
            'disclaimer', 'third_party_notices', 'visual_guide', 'system_guide', 'documentation', 'documentation_sources'):
    check_ref(ROOT / 'agent.json', manifest[key])
assert (ROOT / 'llm.txt').read_bytes() == (ROOT / 'llms.txt').read_bytes()
assert (ROOT / 'CNAME').read_text().strip() == 'intertexum.com'
assert (ROOT / '.nojekyll').is_file()
sitemap = ET.fromstring((ROOT / 'sitemap.xml').read_text())
locations = {node.text for node in sitemap.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')}
assert {page.canonical for page in pages.values()} <= locations
for location in locations:
    assert location.startswith(ORIGIN), location
    assert (ROOT / (location[len(ORIGIN):] or 'index.html')).is_file(), location
assert ORIGIN + 'sitemap.xml' in (ROOT / 'robots.txt').read_text()
html = (ROOT / 'index.html').read_text()
for token in ('Intertexum', 'docs/agent-setup.html#your-first-exchange-two-nodes', 'tools/list', 'agentmesh://policy', 'experimental', 'as-is'):
    assert token in html, token
assert 'intertexum --data' in (ROOT / 'docs/AGENT_SETUP.md').read_text()
for path in list(ROOT.glob('*.md')) + list((ROOT / 'docs').glob('*.md')):
    for ref in re.findall(r'\[[^\]]*\]\(([^)]+)\)', path.read_text()):
        check_ref(path, ref)
for path in list(ROOT.glob('*')) + list((ROOT / 'docs').glob('*')):
    if path.is_file() and path.suffix in ('.html', '.css', '.js', '.svg', '.md', '.txt', '.json'):
        content = path.read_text().replace('calvincs/Intertexum', 'calvincs/repository')
        assert not re.search(r'\baether\b', content, re.I), path.name
print(f'{len(pages)} HTML pages: links, anchors, metadata, documentation, sitemap and branding checks passed.')

for path in (ROOT / 'docs').glob('*.md'):
    if path.name != 'index.md':
        assert path.relative_to(ROOT).as_posix() in ROUTES, (path.name, 'missing readable documentation route')
for source, route in ROUTES.items():
    page = pages[(ROOT / route).resolve()]
    source_target = (ROOT / source).resolve()
    assert any((ROOT / route).parent.joinpath(ref).resolve() == source_target for ref in page.refs if not urlsplit(ref).scheme), (route, 'missing original source link')
for route, expected in outputs().items():
    assert (ROOT / route).read_text() == expected, (route, 'generated documentation drift; run build_docs.py')
print('All Google tags, original source links and generated documentation checks passed.')
