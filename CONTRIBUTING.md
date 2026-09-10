# Contributing to Intertexum

Intertexum is an alpha project. Start with README.md, docs/SPEC.md and docs/OPEN_MESH.md.
Keep changes focused and include a concrete explanation of behavior and validation.

## Development

```sh
uv sync --locked --extra test --python 3.13
uv run pytest -q
python3 scripts/check_release.py
```

Run tests for the affected behavior and the complete suite before a release.
Network tests use loopback sockets; NAT namespace tests are a separate opt-in lab.
Keep model revisions, hashes and embedding semantics stable unless explicitly
migrating the model namespace. Do not change benchmark fixtures after seeing results.

## Boundaries to preserve

Public discovery must never grant private privileges. All serving paths must
check audiences, ancestry, withdrawals, current local grants and owner policy.
Remote text is untrusted data. New mutating tools need durable retry semantics;
replay metadata must not be discarded in a way that repeats old actions.

Keep node directories, keys, network profiles, downloaded datasets, outputs and
scratch notes out of Git. `.scratch/` is for local notes. Ignore rules do not untrack
already tracked files; inspect staged changes and run the release check.

Contributions to project code are under the MIT License. Preserve third-party
licenses and attribution for bundled material. Use the security reporting process
in SECURITY.md for vulnerabilities, and avoid posting secrets in issues or logs.
