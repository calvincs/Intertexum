"""Static publication checks; content must remain available without JavaScript."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import json
import re
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent

class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.refs=[]; self.ids=set(); self.structured=[]; self.in_json=False; self.part=[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        self.refs.extend(a[k] for k in ('href','src') if k in a)
        if 'id' in a:
            assert a['id'] not in self.ids, 'duplicate ID '+a['id']
            self.ids.add(a['id'])
        if tag=='script' and a.get('type')=='application/ld+json':self.in_json=True
        if tag=='img':assert 'alt' in a, 'image needs alternative text'
    def handle_data(self,data):
        if self.in_json:self.part.append(data)
    def handle_endtag(self,tag):
        if tag=='script' and self.in_json:
            self.structured.append(json.loads(''.join(self.part)));self.part=[];self.in_json=False

page=Page();html=(ROOT/'index.html').read_text();page.feed(html)
for ref in page.refs:
    u=urlsplit(ref)
    if u.scheme:continue
    if not u.path:
        assert not u.fragment or u.fragment in page.ids,ref
    else:
        path=(ROOT/unquote(u.path)).resolve()
        assert path.is_relative_to(ROOT) and path.is_file(),ref
assert page.structured[0]['name']=='Intertexum'
assert page.structured[0]['url']=='https://intertexum.com/'
manifest=json.loads((ROOT/'agent.json').read_text())
assert manifest['name']=='Intertexum' and manifest['runtime']['command']=='intertexum'
for key in ('instructions','instructions_alias','specification','setup','disclaimer','third_party_notices'):
    assert (ROOT/manifest[key]).is_file(),key
assert (ROOT/'llm.txt').read_bytes()==(ROOT/'llms.txt').read_bytes()
assert (ROOT/'CNAME').read_text().strip()=='intertexum.com'
assert (ROOT/'.nojekyll').is_file()
ET.fromstring((ROOT/'sitemap.xml').read_text())
assert 'https://intertexum.com/sitemap.xml' in (ROOT/'robots.txt').read_text()
for token in ('Intertexum','intertexum --data','tools/list','agentmesh://policy','experimental','as-is'):
    assert token in html,token
for p in list(ROOT.glob('*.md'))+list((ROOT/'docs').glob('*.md')):
    for ref in re.findall(r'\[[^\]]*\]\(([^)]+)\)',p.read_text()):
        u=urlsplit(ref)
        if not u.scheme and u.path:assert (p.parent/unquote(u.path)).is_file(),(p.name,ref)
for p in list(ROOT.glob('*'))+list((ROOT/'docs').glob('*')):
    if p.is_file() and p.suffix in ('.html','.css','.js','.svg','.md','.txt','.json'):
        content=p.read_text()
        # Check current published prose, excluding the verified repository URL.
        content=content.replace('calvincs/Intertexum','calvincs/repository')
        assert not re.search(r'\baether\b',content,re.I),p.name
print('HTML links, semantic metadata, documentation, domain and branding checks passed.')
