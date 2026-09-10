# Intertexum website

Static documentation for https://intertexum.com. Application source and canonical
documentation live on [main](https://github.com/calvincs/Intertexum/tree/main).

GitHub Pages: deploy `gh-pages` from `/ (root)`. `CNAME` specifies the custom
domain; the owner must configure DNS and GitHub domain verification/HTTPS.

Edit index.html, style.css, sky.js and mark.svg here. The visual guide uses
how-it-works.html, how-it-works.css and how-it-works.js. Preserve its readable
static content and keyboard, reduced-motion and responsive behavior. Preview with
`python3 -m http.server 8765 --bind 127.0.0.1`. Run `node --check sky.js` and
`node --check how-it-works.js` and `python3 check_site.py`. The workflow performs
these same checks for every page, cross-page anchors and sitemap routes.

The content is semantic HTML without JavaScript dependencies. `llm.txt`,
`llms.txt`, `agent.json`, JSON-LD, robots.txt and sitemap.xml provide machine entry
points. This site is documentation; it exposes no hosted node or MCP endpoint.

Refresh docs/, llm.txt, llms.txt, DISCLAIMER.md, SECURITY.md, LICENSE and NOTICE
from main when publishing. Resolve links to source-only files against the actual
GitHub main branch. Keep the manifest consistent with the runtime. Do not copy
node data, credentials, model files or local build artifacts here.

Graphics illustrate public and permissioned exchanges; they are not live network
telemetry. Do not publish operational seed names, addresses or identity cards.
Website code is MIT licensed. The project disclaimer adds no license conditions.

## Readable documentation

Keep original Markdown URLs for agents and render human pages from the same
snapshots. The public catalog, page shell and diagrams live in `build_docs.py`;
`doc_render.py` handles Markdown and internal links. The reading theme and optional
interactions live in `docs.css` and `docs.js`. Do not edit generated article HTML.
See [the maintenance guide](docs/website.html) for the full synchronization process.

```sh
python3 -m pip install -r docs-requirements.txt
python3 build_docs.py
python3 -m unittest -v test_doc_render
python3 build_docs.py --check
node --check docs.js
python3 check_site.py
```

Every HTML page includes the existing Google tag `G-YKJ2WJNQBD`. Validation checks
it, preserved source links and the generated pages. `docs/index.md` is the additive
Markdown index; `docs/index.html` is the human documentation hub. Keep navigation,
section links, tables and article content readable without JavaScript. Respect
reduced motion and preserve the animation pause controls.
