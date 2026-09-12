"""Check the proposed source file set and optional distribution archives."""
import argparse
import fnmatch
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = {'agentmesh', 'tests', 'examples', 'integration', 'benchmarks',
               'docs', 'ops', 'scripts', '.github'}
FILES = {'README.md', 'LICENSE', 'NOTICE', 'CONTRIBUTING.md', 'SECURITY.md', 'DISCLAIMER.md', 'AGENTS.md',
         'MANIFEST.in', 'pyproject.toml', 'uv.lock', 'llm.txt', 'llms.txt', '.gitignore'}
FORBIDDEN_PARTS = {'archived', '.scratch', 'scratch', 'notes-local', '.venv', 'venv',
                   '__pycache__', '.pytest_cache', '.git', '.codex', '.agents',
                   'node-data', 'nodes', 'backups', 'dist', 'build', '_site'}
FORBIDDEN_NAMES = {'network-profile.json', 'connectivity.json', 'connectivity-status.json',
                   'policy.json', 'source-policy.json', 'routing.json', 'message-policy.json', 'connectivity-suspended', 'runtime.lock'}
FORBIDDEN_SUFFIXES = ('.key', '.pem', '.p12', '.pfx', '.sqlite', '.db', '.sock',
                      '.log', '.ses', '.pyc', '.pyo', '.tmp', '.part')
SECRET = re.compile(rb'(?m)^-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*$')


def validate_path(name, *, package=False):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError(f'unsafe path: {name}')
    if set(p.parts) & FORBIDDEN_PARTS or name.startswith(('benchmarks/assets/', 'benchmarks/results/')):
        raise ValueError(f'local artifact in release: {name}')
    if (p.name in FORBIDDEN_NAMES or p.name.startswith('.env') or
            p.name.endswith(FORBIDDEN_SUFFIXES) or '.sqlite-' in p.name or '.db-' in p.name):
        raise ValueError(f'private or generated file in release: {name}')
    if package and any(x.endswith(('.dist-info', '.egg-info')) for x in p.parts):
        return
    if len(p.parts) == 1:
        if p.name not in FILES and not (package and p.name in {'PKG-INFO', 'setup.cfg'}):
            raise ValueError(f'unexpected root file: {name}')
    elif p.parts[0] not in DIRECTORIES:
        raise ValueError(f'unexpected directory: {name}')


def validate_bytes(name, data):
    if SECRET.search(data):
        raise ValueError(f'private key material in {name}')
    if name.endswith('.json'):
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeError):
            return
        if isinstance(obj, dict) and isinstance(obj.get('admission'), dict) and 'key' in obj['admission']:
            raise ValueError(f'credential-bearing profile in {name}')


def candidates(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '--cached', '--others',
                             '--exclude-standard', '-z'], capture_output=True)
    if result.returncode == 0:
        return sorted(set(result.stdout.decode().rstrip('\0').split('\0')) - {''})
    # A source archive has no Git metadata. Honor the shipped ignore patterns.
    patterns = [x.strip() for x in (root / '.gitignore').read_text().splitlines()
                if x.strip() and not x.startswith(('#', '!'))]
    selected = []
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        parts = PurePosixPath(name).parts
        ignored = any(
            (pat.endswith('/') and (pat.rstrip('/') in parts or name.startswith(pat))) or
            (not pat.endswith('/') and (fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(path.name, pat)))
            for pat in patterns)
        if not ignored and (path.is_file() or path.is_symlink()):
            selected.append(name)
    return sorted(selected)


def check_source(root=ROOT):
    names = candidates(root)
    if not {'LICENSE', 'pyproject.toml', 'README.md', 'agentmesh/node.py'} <= set(names):
        raise ValueError('required project sources are missing')
    for name in names:
        validate_path(name, package=(root / "PKG-INFO").is_file())
        path = root / name
        if path.is_symlink():
            raise ValueError(f'symlink in release: {name}')
        if not path.is_file():
            raise ValueError(f'indexed file missing from working tree: {name}')
        if path.stat().st_size >= 100 * 1024 * 1024:
            raise ValueError(f'file exceeds GitHub regular-file limit: {name}')
        validate_bytes(name, path.read_bytes())
    return len(names)


def check_archives(directory):
    archives = sorted(Path(directory).glob('*.whl')) + sorted(Path(directory).glob('*.tar.gz'))
    if not archives:
        raise ValueError('no release archives found')
    for archive in archives:
        names = []
        if archive.suffix == '.whl':
            with zipfile.ZipFile(archive) as z:
                for entry in z.infolist():
                    if entry.is_dir():
                        continue
                    if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError('symlink in wheel')
                    validate_path(entry.filename, package=True)
                    validate_bytes(entry.filename, z.read(entry))
                    names.append(entry.filename)
                metadata_name = next(n for n in names if n.endswith('.dist-info/METADATA'))
                if b'License-Expression: MIT' not in z.read(metadata_name):
                    raise ValueError('wheel metadata must declare MIT')
                license_name = next(n for n in names if n.endswith('/licenses/LICENSE'))
                if b'MIT License' not in z.read(license_name):
                    raise ValueError('wheel project license is not MIT')
        else:
            with tarfile.open(archive) as t:
                for entry in t.getmembers():
                    if entry.isdir():
                        continue
                    if not entry.isfile():
                        raise ValueError('non-regular entry in source archive')
                    original = PurePosixPath(entry.name)
                    parts = original.parts
                    if original.is_absolute() or '..' in parts:
                        raise ValueError('unsafe source archive path')
                    if len(parts) < 2:
                        raise ValueError('missing source archive prefix')
                    name = '/'.join(parts[1:])
                    validate_path(name, package=True)
                    data = t.extractfile(entry).read()
                    validate_bytes(name, data)
                    if name == 'LICENSE' and b'MIT License' not in data:
                        raise ValueError('source project license is not MIT')
                    if name == 'PKG-INFO' and b'License-Expression: MIT' not in data:
                        raise ValueError('source metadata must declare MIT')
                    names.append(name)
        if 'agentmesh/assets/embedding/LICENSE-APACHE-2.0.txt' not in names:
            raise ValueError('missing bundled model license')
    return len(archives)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    print(f'Source hygiene verified: {check_source()} project files.')
    if args.artifacts:
        print(f'Archive hygiene verified: {check_archives(args.artifacts)} artifacts.')


if __name__ == '__main__':
    main()
