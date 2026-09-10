"""Copy public documentation to a separate website checkout, or check for drift.

Only the explicit public documents below are copied. Node state, application
source, and build artifacts are never included.
"""
import argparse
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ('llm.txt', 'llms.txt', 'DISCLAIMER.md', 'LICENSE', 'NOTICE', 'SECURITY.md')
# Maintainer workflows stay in the source repository, never on the user site.
INTERNAL_DOCS = ('docs/RELEASING.md', 'docs/WEBSITE.md')
PUBLIC_DOCS = (
    'AGENT_SETUP', 'BOOTSTRAP', 'CACHING', 'CONNECTIVITY', 'DEFENSE',
    'EMBEDDINGS', 'ERASURE', 'GLOSSARY', 'MCP', 'OPEN_MESH',
    'OPERATING_LIMITS', 'PEER_VIEWS', 'PRIVACY', 'RECEIVING_CONTENT',
    'ROADMAP', 'SPEC', 'UNDERSTANDING', 'VALIDATION',
)
SOURCE_URL = 'https://github.com/calvincs/Intertexum/blob/main/'


def snapshots(source=ROOT):
    source = Path(source).resolve()
    names = list(PUBLIC) + ['docs/' + name + '.md' for name in PUBLIC_DOCS]
    published = set(names)
    result = {}
    for name in names:
        path = source / name
        content = path.read_text()
        if path.suffix == '.md':
            def rewrite(match):
                label, target = match.groups()
                url = urlsplit(target)
                if url.scheme or url.netloc or not url.path:
                    return match.group(0)
                resolved = (path.parent / unquote(url.path)).resolve()
                if not resolved.is_relative_to(source):
                    raise ValueError('documentation link escapes source: ' + target)
                relative = resolved.relative_to(source).as_posix()
                if not resolved.is_file():
                    raise ValueError('documentation link target missing: ' + relative)
                if relative in published:
                    return match.group(0)
                remote = SOURCE_URL + quote(relative, safe='/')
                if url.fragment:
                    remote += '#' + url.fragment
                return '[' + label + '](' + remote + ')'
            content = re.sub(r'\[([^\]]*)\]\(([^)]+)\)', rewrite, content)
        result[name] = content.encode()
    return result


def sync(website, *, check=False, source=ROOT):
    website = Path(website).resolve()
    if website == Path(source).resolve() or not (website / 'index.html').is_file():
        raise ValueError('use a separate existing website checkout containing index.html')
    changed = []
    for name, content in snapshots(source).items():
        target = website / name
        if target.is_symlink() or not target.resolve().is_relative_to(website):
            raise ValueError('website target must not escape checkout: ' + name)
        if not target.exists() or target.read_bytes() != content:
            changed.append(name)
            if not check:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
    for name in INTERNAL_DOCS:
        for retired in (name, name.removesuffix('.md').lower() + '.html'):
            target = website / retired
            if target.is_symlink() or not target.resolve().is_relative_to(website):
                raise ValueError('website target must not escape checkout: ' + retired)
            if target.exists():
                changed.append(retired)
                if not check:
                    target.unlink()
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--website', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    changed = sync(args.website, check=args.check)
    if args.check and changed:
        parser.exit(1, 'Website documentation differs: ' + ', '.join(changed) + '\n')
    print(('Checked' if args.check else 'Synchronized') + ' public website documentation.')


if __name__ == '__main__':
    main()
