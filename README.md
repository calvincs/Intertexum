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
these same static checks, including both pages, cross-page anchors and sitemap routes.

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
