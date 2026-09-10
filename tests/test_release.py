"""Publication boundaries and a transaction regression found during release review."""
from pathlib import Path
import subprocess
import pytest
from scripts.check_release import validate_path, validate_bytes, check_source
from agentmesh.lifecycle import maintain, retain
from conftest import publish


@pytest.mark.parametrize('name', [
    'archived/conversation.md', '.scratch/notes.md', 'benchmarks/assets/model.onnx',
    'benchmarks/results/run.json', 'agentmesh/identity.key', 'examples/network-profile.json',
    'agentmesh/mesh.sqlite-wal', 'docs/.env.production', '../private.txt', '/tmp/private.txt',
])
def test_release_rejects_sensitive_or_generated_paths(name):
    with pytest.raises(ValueError):validate_path(name)


def test_secret_content_is_rejected_under_innocent_filename():
    with pytest.raises(ValueError):validate_bytes('docs/notes.txt',b'-----BEGIN PRIVATE KEY-----\nsecret\n')
    with pytest.raises(ValueError):validate_bytes('examples/setup.json',b'{"admission":{"key":"secret"}}')


def test_git_index_cannot_hide_already_tracked_secrets(tmp_path):
    subprocess.run(['git','init',str(tmp_path)],capture_output=True,check=True)
    (tmp_path/'agentmesh').mkdir()
    for name in ('LICENSE','pyproject.toml','README.md','agentmesh/node.py'):
        (tmp_path/name).write_text('placeholder')
    (tmp_path/'.gitignore').write_text('*.key\n')
    (tmp_path/'identity.key').write_text('test-only')
    subprocess.run(['git','-C',str(tmp_path),'add','.'],check=True)
    subprocess.run(['git','-C',str(tmp_path),'add','--force','identity.key'],check=True)
    with pytest.raises(ValueError,match='private or generated'):check_source(tmp_path)


def test_storage_helpers_do_not_commit_the_callers_transaction(mesh):
    a,b,_=mesh
    rid=publish(a);b.ingest(a.get(rid,b.id))
    msg=a.make_message(b.id,'must survive rollback');b.receive_message(msg,a.id)
    with pytest.raises(RuntimeError):
        with b.transaction():
            retain(b,rid,priority=1)
            b.inbox_page()
            maintain(b,ack_before=2**63-1,evict_to=0)
            raise RuntimeError('rollback requested')
    assert b._row(rid) is not None
    assert len(b.inbox())==1
    assert b.db.execute('SELECT count(*) FROM retention').fetchone()[0]==0


def test_website_document_snapshot_detects_drift_and_excludes_source_state(tmp_path):
    from scripts.sync_website_docs import PUBLIC, sync
    source = tmp_path / 'source'
    website = tmp_path / 'website'
    source.mkdir(); website.mkdir(); (source / 'docs').mkdir()
    (website / 'index.html').write_text('<html></html>')
    for name in PUBLIC:
        (source / name).write_text('public instructions\n')
    (source / 'node.key').write_text('synthetic private state')
    (source / 'sample.py').write_text('source-only example')
    (source / 'docs' / 'guide.md').write_text('[example](../sample.py)\n[license](../LICENSE)\n')
    assert sync(website, check=True, source=source)
    sync(website, source=source)
    assert not sync(website, check=True, source=source)
    assert not (website / 'node.key').exists()
    assert not (website / 'sample.py').exists()
    assert '(https://github.com/calvincs/Intertexum/blob/main/sample.py)' in (website / 'docs' / 'guide.md').read_text()
    (source / 'docs' / 'guide.md').write_text('current version\n')
    assert sync(website, check=True, source=source) == ['docs/guide.md']
