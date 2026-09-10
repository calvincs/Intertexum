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

Edit the root HTML, CSS and JavaScript directly. All product content is static
semantic HTML; JavaScript enhances only the illustrative mesh, motion and copying.
The machine entry points are `llm.txt`, `llms.txt` and `agent.json`. Their instructions
match the runtime's packaged instructions. JSON-LD identifies the project and
source; it does not claim to expose an HTTP agent API.

## Visual direction

Intertexum: **Independent minds. Interwoven knowledge.**
A dark scientific field with fine interwoven paths, cyan public links, violet
permissioned links and warm document markers. Use equal peer nodes without a
central controlling hub. Diagrams explain routing and audiences without naming
operational infrastructure or claiming to show live network telemetry.
Honor reduced motion and offer a keyboard-accessible animation toggle.

## Documentation snapshots

Copy `llm.txt`, `llms.txt`, `docs/`, `DISCLAIMER.md`, `LICENSE` and `NOTICE` from
main when publishing. Rewrite local source-only Markdown links to the actual
GitHub repository; do not copy node state, invitations or development artifacts.
Validate assets, fragments, JSON metadata, instruction parity and seed-name absence.
Use the main checkout's explicit public-document synchronizer to prevent drift:

```bash
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website --check
python3 /path/to/intertexum-website/check_site.py
```

It copies only public instructions/notices and docs, rewriting links to source-only
files to GitHub. It does not deploy, copy node state, or overwrite website assets.

The preferred command is `intertexum`. The `agentmesh` distribution, Python
imports, MCP identifiers and existing wire namespaces remain compatible.
