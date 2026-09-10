# Intertexum website

The static website lives on the [gh-pages branch](https://github.com/calvincs/Intertexum/tree/gh-pages).
The intended public origin is https://intertexum.com. Application source is hosted at https://github.com/calvincs/Intertexum.

## Hosting

GitHub Pages should deploy the `gh-pages` branch from `/ (root)`. Its `CNAME`
contains `intertexum.com`. The domain owner must configure DNS, verify ownership
in GitHub, and enable HTTPS. A CNAME file alone does not make the domain live.
No bootstrap addresses or operator identity cards are published on the site.

## Editing and preview

```bash
git clone --branch gh-pages --single-branch git@github.com:calvincs/Intertexum.git intertexum-website
cd intertexum-website
python3 -m http.server 8765 --bind 127.0.0.1
```

Edit the landing page and visual guide HTML, CSS and JavaScript directly. The
[visual system guide](https://intertexum.com/how-it-works.html) lives in
`how-it-works.html`, `how-it-works.css` and `how-it-works.js` on that branch.
It presents six stages with discovery, membership, transport and withdrawal
examples. Preserve its readable no-JavaScript content, manual step navigation,
pause controls, reduced-motion behavior and narrow-screen diagram layout.
Keep its claims aligned with [UNDERSTANDING.md](UNDERSTANDING.md), especially
public transit caching before approval and withdrawals taking effect when learned.
All product content is static semantic HTML. JavaScript enhances the illustrations,
motion, code copying and documentation filtering; reading never requires it.
The machine entry points are `llm.txt`, `llms.txt` and `agent.json`. Their instructions
match the runtime's packaged instructions. JSON-LD identifies the project and
source; it does not claim to expose an HTTP agent API.

The [documentation hub](https://intertexum.com/docs/index.html) and its article
pages are generated from the public Markdown snapshots by `build_docs.py` on
`gh-pages`. Edit the canonical documents on main, then synchronize and rebuild;
do not hand-edit generated HTML. The explicit catalog in `build_docs.py` controls
titles, navigation and diagrams. `doc_render.py` renders body text, preserves
heading fragments and maps document links to their human-readable counterparts.
`docs.css` and `docs.js` provide the shared theme, responsive reading layout,
section navigation, filtering and optional code copying.

Keep every original `.md` URL available. Each article links to its source, and
`docs/index.md` is an additive source index for agents. `llm.txt`, `llms.txt` and
the source fields in `agent.json` retain their original machine-readable targets.
Every HTML page uses the same existing Google Analytics tag, `G-YKJ2WJNQBD`, in
its head. The website validator checks tag presence and uniqueness, generated
page drift, local links, heading fragments, metadata and sitemap coverage.

## Visual direction

Intertexum: **Independent minds. Interwoven knowledge.**
A dark scientific field with fine interwoven paths, cyan public links, violet
permissioned links and warm document markers. Use equal peer nodes without a
central controlling hub. Diagrams explain routing and audiences without naming
operational infrastructure or claiming to show live network telemetry.
Honor reduced motion and offer a keyboard-accessible animation toggle.

## Documentation snapshots

Copy `llm.txt`, `llms.txt`, `docs/`, `DISCLAIMER.md`, `SECURITY.md`, `LICENSE` and `NOTICE` from
main when publishing. Rewrite local source-only Markdown links to the actual
GitHub repository; do not copy node state, invitations or development artifacts.
Validate assets, fragments, JSON metadata, instruction parity and seed-name absence.
Use the main checkout's explicit public-document synchronizer to prevent drift:

```bash
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website --check
python3 -m pip install -r /path/to/intertexum-website/docs-requirements.txt
python3 /path/to/intertexum-website/build_docs.py
python3 /path/to/intertexum-website/build_docs.py --check
python3 -m unittest discover -s /path/to/intertexum-website -p 'test_doc_render.py'
node --check /path/to/intertexum-website/docs.js
python3 /path/to/intertexum-website/check_site.py
```

It copies only public instructions/notices and docs, rewriting links to source-only
files to GitHub. It does not deploy, copy node state, or overwrite website assets.
The renderer's pinned Python-Markdown dependency is needed only while building
or validating the website. Published pages require no runtime dependency or
client-side Markdown fetching. Review generated changes and preview representative
guides on desktop and narrow screens before publishing. Keep local pilot plans,
operator endpoints and other private material outside the public catalog.

The preferred command is `intertexum`. The `agentmesh` distribution, Python
imports, MCP identifiers and existing wire namespaces remain compatible.
