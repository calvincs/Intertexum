"""Publish readable documentation from the preserved Markdown snapshots.

Run after main's scripts/sync_website_docs.py. Use --check in CI.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import posixpath
from pathlib import Path

from doc_render import render_document

ROOT = Path(__file__).resolve().parent
ORIGIN = 'https://intertexum.com/'
TRACKING_ID = 'G-YKJ2WJNQBD'
ANALYTICS = f'''  <!-- Google tag (gtag.js) -->
  <script async src="https://www.googletagmanager.com/gtag/js?id={TRACKING_ID}"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){{dataLayer.push(arguments);}}
    gtag('js', new Date());
    gtag('config', '{TRACKING_ID}');
  </script>'''

# Explicit public catalog: never discover operational notes or arbitrary files.
CATALOG = [
    ('docs/UNDERSTANDING.md', 'Understand the system', 'Start here', 'How identities, invitations, permissions and independent nodes fit together.'),
    ('docs/AGENT_SETUP.md', 'Connect your first nodes', 'Start here', 'Owner-approved profiles, local setup, MCP connection and troubleshooting.'),
    ('docs/GLOSSARY.md', 'Glossary', 'Start here', 'Plain-language definitions: bootstrap nodes (seeds), peers, profiles, grants and more.'),
    ('docs/MCP.md', 'MCP & agent tools', 'Start here', 'Connect a harness and discover the tools, resources and owner controls.'),
    ('docs/OPEN_MESH.md', 'Sharing & conversations', 'Memory & collaboration', 'Public discovery, directional grants, durable messages and hosted threads.'),
    ('docs/CACHING.md', 'Caching & participation', 'Memory & collaboration', 'How public copies travel, keep their signatures and expire from bounded caches.'),
    ('docs/EMBEDDINGS.md', 'Search & embeddings', 'Memory & collaboration', 'The bundled embedding model, retrieval behavior and offline runtime.'),
    ('docs/PEER_VIEWS.md', 'Peer views', 'Memory & collaboration', 'Signed peer referrals and the limits of distributed discovery.'),
    ('docs/CONNECTIVITY.md', 'Connectivity', 'Network & operations', 'Direct paths, mDNS, ICE, STUN, TURN and changing network addresses.'),
    ('docs/BOOTSTRAP.md', 'Bootstrap profiles', 'Network & operations', 'Configure bootstrap nodes (called seeds) and trusted discovery profiles.'),
    ('docs/DEFENSE.md', 'Defenses & rate limits', 'Network & operations', 'Local defense controls, admission limits and bounded resource use.'),
    ('docs/OPERATING_LIMITS.md', 'Operating limits', 'Network & operations', 'Capacity bounds, partial results, delivery guarantees and recovery.'),
    ('docs/ERASURE.md', 'Bootstrap deregistration', 'Network & operations', 'Remove bootstrap-directory registrations and understand retention boundaries.'),
    ('docs/VALIDATION.md', 'Validation status', 'Network & operations', 'What has been tested and which deployment claims still need evidence.'),
    ('docs/SPEC.md', 'Protocol specification', 'Reference & safety', 'Signed records, transport, audiences and validation rules.'),
    ('docs/RECEIVING_CONTENT.md', 'Receiving peer content', 'Reference & safety', 'Keep retrieved text separate from the authority to use tools and data.'),
    ('docs/PRIVACY.md', 'Privacy & data flows', 'Reference & safety', 'Where data travels, what peers can observe and what withdrawal cannot recall.'),
    ('docs/ROADMAP.md', 'Project direction', 'Reference & safety', 'Open questions and the next areas of development.'),
    ('docs/RELEASING.md', 'Release process', 'Reference & safety', 'Validate, package and publish reviewed project changes.'),
    ('docs/WEBSITE.md', 'Website maintenance', 'Reference & safety', 'Keep the public website and its human and agent documentation aligned.'),
    ('SECURITY.md', 'Security', 'Project information', 'Report vulnerabilities and understand the deployment boundary.'),
    ('DISCLAIMER.md', 'Project disclaimer', 'Project information', 'Experimental software, owner responsibilities and limits of guarantees.'),
    ('LICENSE', 'MIT license', 'Project information', 'The license for Intertexum project code.'),
    ('NOTICE', 'Third-party notices', 'Project information', 'Licensing and attribution for bundled models and dependencies.'),
]
ROUTES = {source: (source.removesuffix('.md').lower().replace('_', '-') + '.html')
          for source, *_ in CATALOG}
CATEGORIES = list(dict.fromkeys(row[2] for row in CATALOG))

DIAGRAMS = {
    'docs/AGENT_SETUP.md': (
        'Bring a node online',
        [('01 / PROVISION', 'Owner-provided profile', 'Choose the authorized network.'),
         ('02 / ONBOARD', 'Create a node identity', 'Save identity and configuration.'),
         ('03 / RUN', 'Start MCP or daemon', 'Keep the runtime listening.'),
         ('04 / DISCOVER', 'Meet your peers', 'Apply access rules to requests.')],
        'Onboarding prepares a node. A running runtime maintains discovery and communication.',
        'Running onboard or status alone does not keep a node online.'),
    'docs/OPEN_MESH.md': (
        'The receiver grants access',
        [('SENDER / A', 'Request to message B', 'A’s owner permits sending.'),
         ('RECEIVER / B', 'Check B’s local grant', 'B grants A message permission.'),
         ('DELIVERY / B', 'Store in B’s inbox', 'A receipt confirms storage.')],
        'A → B is one direction. For B to message A, A must grant B access separately.',
        'Public-thread replies follow their own public access rules. A stored message does not mean an agent has acted on it.'),
    'docs/CACHING.md': (
        'A copy keeps its author',
        [('ORIGIN / A', 'Publish a public record', 'A signs the content and audience.'),
         ('HOLDER / B', 'Cache a verified copy', 'Pending local approval; A’s signature stays.'),
         ('REQUESTER / C', 'Retrieve from B', 'Eligible public copies may be re-served.')],
        'On a separate local path, B can inspect and approve its copy for B’s ordinary knowledge search.',
        'Retrieval is selective and caches are bounded. This is not whole-network replication or nearest-cache routing.'),
    'docs/RECEIVING_CONTENT.md': (
        'Content is separate from authority',
        [('INPUT', 'Read peer content', 'Treat it as untrusted data.'),
         ('CONTEXT', 'Check provenance', 'Verify the claim in context.'),
         ('AUTHORITY', 'Check the owner’s task', 'Enforce tool and data boundaries.'),
         ('DECISION', 'Act or decline', 'Only within authorized scope.')],
        'Signatures and local approval do not turn retrieved text into instructions.',
        'Protocol tests do not establish model-level prompt-injection resistance.'),
}


def esc(value):
    return html.escape(str(value), quote=True)


def relative(route, target):
    return posixpath.relpath(target, posixpath.dirname(route) or '.')


def link(route, target, text, attrs=''):
    return f'<a href="{esc(relative(route, target))}"{attrs}>{esc(text)}</a>'


def head(route, title, description, source=None):
    canonical = ORIGIN + route
    alternate = ''
    if source:
        media = 'text/markdown' if source.endswith('.md') else 'text/plain'
        alternate = f'<link rel="alternate" type="{media}" href="{esc(relative(route, source))}" title="Original source">'
    structured = json.dumps({'@context': 'https://schema.org', '@type': 'WebPage',
                             'name': 'Intertexum', 'headline': title, 'url': canonical,
                             'description': description}, ensure_ascii=False)
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
{ANALYTICS}
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#080f18">
  <meta name="description" content="{esc(description)}">
  <meta property="og:type" content="website">
  <meta property="og:title" content="{esc(title)} · Intertexum">
  <meta property="og:description" content="{esc(description)}">
  <meta property="og:url" content="{canonical}">
  <title>{esc(title)} · Intertexum</title>
  <link rel="canonical" href="{canonical}">
  <link rel="icon" href="{relative(route, 'mark.svg')}" type="image/svg+xml">
  <link rel="stylesheet" href="{relative(route, 'style.css')}">
  <link rel="stylesheet" href="{relative(route, 'docs.css')}">
{alternate}
  <link rel="alternate" type="text/markdown" href="{relative(route, 'docs/index.md')}" title="Documentation index for agents">
  <script defer src="{relative(route, 'docs.js')}"></script>
  <script type="application/ld+json">{structured}</script>
</head>
<body class="documentation">
<a class="skip" href="#main">Skip to content</a>
<header class="wrap header">
  <a class="brand" href="{relative(route, 'index.html')}" aria-label="Intertexum home"><img src="{relative(route, 'mark.svg')}" width="36" height="36" alt=""><span>intertexum</span></a>
  <nav aria-label="Main navigation">{link(route, 'how-it-works.html', 'How it works')}{link(route, 'docs/index.html', 'Docs', ' aria-current="' + ('page' if route == 'docs/index.html' else 'true') + '"')}{link(route, 'llm.txt', 'For agents ↗', ' class="agent-link"')}</nav>
</header>'''


def footer(route):
    return f'''<footer class="wrap footer"><a class="brand" href="{relative(route, 'index.html')}"><img src="{relative(route, 'mark.svg')}" width="30" height="30" alt=""><span>intertexum</span></a><p>Independent minds. Interwoven knowledge.</p><nav aria-label="Project links"><a href="https://github.com/calvincs/Intertexum">Source</a>{link(route, 'license.html', 'MIT license')}{link(route, 'notice.html', 'Notices')}{link(route, 'security.html', 'Security')}</nav></footer>
</body>
</html>
'''


def sidebar(route):
    groups = []
    for category in CATEGORIES:
        entries = ''.join('<li>' + link(route, ROUTES[source], label,
                          ' aria-current="page"' if ROUTES[source] == route else '') + '</li>'
                          for source, label, group, _ in CATALOG if group == category)
        groups.append(f'<div class="nav-group"><p>{esc(category)}</p><ul>{entries}</ul></div>')
    return f'''<aside class="doc-sidebar"><details class="doc-browse" open><summary>Browse documentation</summary><nav aria-label="Documentation">{''.join(groups)}</nav></details></aside>'''


def figure(source):
    if source == 'docs/CONNECTIVITY.md':
        return '''<figure class="doc-diagram transport-figure"><figcaption><span class="eyebrow">CONNECTION MAP / ILLUSTRATIVE</span><strong>Separate setup from traffic</strong></figcaption>
<div class="transport-lane setup"><span>SETUP</span><ol><li>Node A</li><li>Bootstrap node · introductions &amp; signaling</li><li>Node B</li></ol></div>
<div class="transport-lane"><span>DIRECT PATH</span><ol><li>Node A</li><li>Authenticated, encrypted connection</li><li>Node B</li></ol></div>
<div class="transport-lane relay"><span>FALLBACK</span><ol><li>Node A</li><li>TURN · encrypted traffic relay</li><li>Node B</li></ol></div>
<p class="diagram-caption">Bootstrap nodes (called seeds in configuration) help peers connect. Application traffic travels directly or through a provisioned TURN relay. On a LAN, mDNS can provide introductions without a bootstrap node.</p>
<p class="diagram-caution">Bootstrap nodes do not relay application content. These nodes and relays can still observe connection metadata.</p><button class="diagram-motion" type="button" aria-pressed="false" hidden>Pause motion</button></figure>'''
    if source not in DIAGRAMS:
        return ''
    title, nodes, caption, caution = DIAGRAMS[source]
    items = ''.join(f'<li><span>{esc(label)}</span><strong>{esc(name)}</strong><p>{esc(note)}</p></li>'
                    for label, name, note in nodes)
    return f'''<figure class="doc-diagram"><figcaption><span class="eyebrow">PROCESS MAP / ILLUSTRATIVE</span><strong>{esc(title)}</strong></figcaption><ol class="doc-flow">{items}</ol><p class="diagram-caption">{esc(caption)}</p><p class="diagram-caution">{esc(caution)}</p><button class="diagram-motion" type="button" aria-pressed="false" hidden>Pause motion</button></figure>'''


def article(row, index):
    source, label, category, description = row
    route = ROUTES[source]
    raw = (ROOT / source).read_text()
    if not source.endswith('.md'):
        raw = '# ' + label + '\n\n' + raw
    doc = render_document(raw, source, ROUTES)
    doc['body_html'] = doc['body_html'].replace('<table>', '<div class="table-scroll" tabindex="0" role="region" aria-label="Documentation table"><table>').replace('</table>', '</table></div>')
    title = doc['title'] or label
    source_label = 'Markdown source ↗' if source.endswith('.md') else 'Plain-text source ↗'
    source_link = link(route, source, source_label, ' class="source-link" data-source-link')
    digest = hashlib.sha256((ROOT / source).read_bytes()).hexdigest()
    toc = ''.join(f'<li class="toc-level-{item["level"]}"><a href="#{esc(item["id"])}">{esc(item["title"])}</a></li>' for item in doc['toc'])
    toc_html = f'<aside class="doc-toc"><details open><summary>On this page</summary><nav aria-label="On this page"><ol>{toc}</ol></nav><a class="top-link" href="#main">Back to top ↑</a></details></aside>' if toc else ''
    previous = CATALOG[index - 1] if index else None
    following = CATALOG[index + 1] if index + 1 < len(CATALOG) else None
    adjacent = ''.join(link(route, ROUTES[item[0]], direction + ' · ' + item[1])
                       for item, direction in [(previous, '← Previous'), (following, 'Next →')] if item)
    return head(route, title, description, source) + f'''
<div class="wrap doc-layout">
{sidebar(route)}
<main id="main" class="doc-main" data-source-sha256="{digest}">
  <nav class="breadcrumbs" aria-label="Breadcrumb">{link(route, 'index.html', 'Home')}<span aria-hidden="true">/</span>{link(route, 'docs/index.html', 'Documentation')}<span aria-hidden="true">/</span><span>{esc(label)}</span></nav>
  <header class="doc-heading"><p class="eyebrow">{esc(category)}</p><h1>{esc(title)}</h1><p class="doc-description">{esc(description)}</p><div class="doc-meta"><span>INTERTEXUM / DOCUMENTATION</span>{source_link}</div><p class="glossary-nudge">New to the terminology? {link(route, 'docs/glossary.html', 'Open the glossary ↗')}</p></header>
{figure(source)}
  <article class="prose" aria-label="{esc(label)} documentation">{doc['body_html']}</article>
  <div class="doc-source"><strong>Reading with an agent?</strong><p>This page is rendered from the public source document. {source_link} · {link(route, 'docs/index.md', 'Markdown documentation index')} · {link(route, 'llm.txt', 'Agent instructions')}</p></div>
  <nav class="doc-adjacent" aria-label="Continue reading">{adjacent}</nav>
  <div class="doc-back">{link(route, 'docs/index.html', '← All documentation')}{link(route, 'how-it-works.html', 'Visual walkthrough ↗')}</div>
</main>
{toc_html}
</div>
{footer(route)}'''


def hub():
    route = 'docs/index.html'
    sections = []
    for number, category in enumerate(CATEGORIES, 1):
        cards = []
        for source, label, group, description in CATALOG:
            if group != category:
                continue
            cards.append(f'''<li class="doc-card" data-doc-card><a href="{relative(route, ROUTES[source])}"><span>{esc(label)}</span><b aria-hidden="true">↗</b><p>{esc(description)}</p></a><a class="card-source" href="{relative(route, source)}">{'Markdown' if source.endswith('.md') else 'Plain text'} source</a></li>''')
        sections.append(f'<section class="doc-category" data-doc-category aria-labelledby="category-{number}"><div class="category-heading"><span class="eyebrow">0{number}</span><h2 id="category-{number}">{esc(category)}</h2></div><ul class="doc-card-grid">{"".join(cards)}</ul></section>')
    return head(route, 'Documentation', 'A readable guide to Intertexum: setup, signed memory, peer communication and operating boundaries.') + f'''
<main class="wrap docs-hub" id="main">
<nav class="breadcrumbs" aria-label="Breadcrumb">{link(route, 'index.html', 'Home')}<span aria-hidden="true">/</span><span>Documentation</span></nav>
<header class="hub-heading"><div><p class="eyebrow">FIELD GUIDE / INTERTEXUM</p><h1>Understand the mesh.<br><em>Then make it yours.</em></h1><p class="doc-description">From your first local nodes to the details of signed memory. Read the guides, follow the diagrams, or give your agent the original Markdown.</p></div><div class="hub-map" aria-hidden="true"><span class="hub-dot dot-a"></span><span class="hub-dot dot-b"></span><span class="hub-dot dot-c"></span><span class="hub-dot dot-d"></span><svg viewBox="0 0 260 190"><path d="M40 90L120 25L215 95L120 165ZM40 90L215 95M120 25L120 165"/></svg><span class="hub-map-label">MANY NODES. LOCAL DECISIONS.</span></div></header>
<div class="docs-entry"><a class="visual-entry" href="../how-it-works.html"><span class="eyebrow">START WITH THE PICTURE</span><strong>How the whole system works <span aria-hidden="true">→</span></strong><p>A visual journey through ownership, discovery, communication and shared memory.</p></a><div class="agent-entry"><span class="eyebrow">FOR AGENTS &amp; SOURCE READERS</span><strong>Same knowledge. Original format.</strong><p>{link(route, 'docs/index.md', 'Markdown index ↗')} · {link(route, 'llm.txt', 'Agent instructions ↗')}</p></div></div>
<div class="doc-filter" hidden><label for="doc-search">Find a guide</label><input id="doc-search" type="search" placeholder="Try setup, permissions, caching…" autocomplete="off" aria-describedby="filter-hint"><span id="filter-hint">Filters guide titles and descriptions.</span><p id="filter-status" role="status" aria-live="polite"></p></div>
<div class="doc-categories">{''.join(sections)}</div>
<p id="no-doc-results" hidden>No matching guides. Try a broader term or clear the search.</p>
<div class="hub-foot"><p>Intertexum is experimental alpha software. {link(route, 'disclaimer.html', 'Read the project disclaimer')} and {link(route, 'docs/operating-limits.html', 'operating limits')} before deployment.</p>{link(route, 'index.html', '← Back to Intertexum')}</div>
</main>
{footer(route)}'''


def outputs():
    result = {ROUTES[row[0]]: article(row, i) for i, row in enumerate(CATALOG)}
    result['docs/index.html'] = hub()
    lines = ['# Intertexum documentation index', '',
             'Original public sources for agents and source readers. Start with [agent instructions](../llm.txt).', '',
             '[Readable documentation](index.html) · [Visual system guide](../how-it-works.html) · [Home](../index.html)', '']
    for category in CATEGORIES:
        lines.extend(['## ' + category, ''])
        for source, label, group, description in CATALOG:
            if group == category:
                lines.append(f'- [{label}]({relative("docs/index.md", source)}) — {description}')
        lines.append('')
    result['docs/index.md'] = '\n'.join(lines)
    urls = [ORIGIN, ORIGIN + 'how-it-works.html'] + [ORIGIN + route for route in result if route.endswith('.html')]
    result['sitemap.xml'] = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + ''.join(f'  <url><loc>{url}</loc></url>\n' for url in urls) + '</urlset>\n'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Fail if published pages differ from current sources/templates.')
    args = parser.parse_args()
    stale = []
    for name, content in outputs().items():
        path = ROOT / name
        if not path.exists() or path.read_text() != content:
            stale.append(name)
            if not args.check:
                path.write_text(content)
    if stale and args.check:
        parser.exit(1, 'Documentation needs rebuilding: ' + ', '.join(stale) + '\nRun python3 build_docs.py\n')
    print(f'{len(CATALOG)} readable documents + documentation hub: ' + ('current.' if args.check else f'{len(stale)} files updated.'))


if __name__ == '__main__':
    main()
