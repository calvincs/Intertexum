# Preparing a GitHub release

The source tree contains project code, tests, synthetic fixtures, model provenance,
operator examples, and documentation. The static landing page lives on `gh-pages`.
Project code uses MIT. The bundled MiniLM ONNX model keeps its Apache-2.0 license and model card.
The model is an intentional runtime asset, not a build artifact.

## Validate and package

```sh
uv sync --locked --extra test --python 3.13
uv run pytest -q
python3 scripts/check_release.py
uv build
python3 scripts/check_release.py --artifacts dist
```

Before publishing the separate website, synchronize and verify its documentation
from the reviewed main checkout:

```sh
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website
python3 scripts/sync_website_docs.py --website /path/to/intertexum-website --check
python3 -m pip install -r /path/to/intertexum-website/docs-requirements.txt
python3 /path/to/intertexum-website/build_docs.py
python3 /path/to/intertexum-website/build_docs.py --check
python3 /path/to/intertexum-website/check_site.py
```

Inspect `git status` and staged changes before committing. The release check
inspects the proposed Git file set (or a clean source tree), rejects private state
and unexpected output files, and can inspect wheel/sdist contents. This is a
release hygiene check, not an exhaustive secret scanner or security audit.

`dist/`, `_site/`, environments, caches, benchmark downloads/results and `.scratch/`
are ignored. Do not force-add them. Files already tracked remain tracked even when
ignored; the release check detects common forbidden paths in the Git index.
Do not commit node profiles, private keys, backups or real agent memory.

## GitHub setup

Choose the repository under the intended owner, push the reviewed source, and
configure branch protection for the Release checks workflow. Enable private
vulnerability reporting. For the landing page, configure Pages as **Deploy from a branch → gh-pages →
/ (root)**. The website branch contains its static files and its own validation
workflow. Do not select main as a Pages source. No repository URL or live seed address is invented here.

After CI passes, tag the reviewed commit for the version in pyproject.toml and
attach the verified wheel and source distribution to its GitHub release. Generated
release artifacts are attachments, not source commits. The `agentmesh` distribution
name and protocol IDs remain stable; the preferred executable is `intertexum`.

Do not claim hosted public-network availability until seed/relay infrastructure and
operator policies exist. The landing page is separate from those services.
