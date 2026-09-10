"""Offline operator recovery. Backups include private keys and must stay private."""
from pathlib import Path
import os
import sqlite3
import shutil
from datetime import datetime,timedelta,timezone
from .crypto import canonical,decode,digest,Invalid,Denied,Identity
from .service import runtime_lock

FILES={'identity.key','identity.pem','config.json','network-profile.json','connectivity.json','policy.json','connectivity-suspended'}
DATABASES={'mesh.sqlite','defense.sqlite','connectivity.sqlite'}


def backup(directory,target):
    directory=Path(directory);target=Path(target)
    with runtime_lock(directory):
        target.mkdir(mode=0o700,parents=True,exist_ok=False)
        try:
            for name in sorted(FILES|DATABASES):
                src=directory/name;dst=target/name
                if not src.exists():continue
                if src.is_symlink() or not src.is_file():raise Invalid('unexpected state file')
                if name in DATABASES:
                    source=sqlite3.connect(src);dest=sqlite3.connect(dst)
                    try:source.backup(dest)
                    finally:source.close();dest.close()
                else:shutil.copyfile(src,dst)
                dst.chmod(0o600)
            manifest={p.name:digest(p.read_bytes()) for p in target.iterdir()}
            (target/'manifest.json').write_bytes(canonical({'version':1,'files':manifest}))
            (target/'manifest.json').chmod(0o600)
        except Exception:
            shutil.rmtree(target);raise
    return {'backup':str(target.resolve()),'contains_private_keys':True,'restore_rule':'stop the original node permanently before activating a restored copy'}


def restore(source,target):
    source=Path(source);target=Path(target)
    value=decode((source/'manifest.json').read_bytes())
    if not isinstance(value,dict) or set(value)!={'version','files'} or value['version']!=1 or not isinstance(value['files'],dict):raise Invalid('invalid backup manifest')
    names=set(value['files'])
    if not {'identity.key','identity.pem','config.json','mesh.sqlite'}<=names or not names<=FILES|DATABASES:raise Invalid('invalid backup file list')
    for name,checksum in value['files'].items():
        p=source/name
        if p.is_symlink() or not p.is_file() or digest(p.read_bytes())!=checksum:raise Invalid('backup checksum mismatch')
    target.mkdir(parents=True,mode=0o700,exist_ok=False)
    try:
        for name in names:
            shutil.copyfile(source/name,target/name);(target/name).chmod(0o600)
        Identity(target)
        # Prevent two restored/original instances automatically advertising one identity.
        (target/'connectivity-suspended').touch(mode=0o600)
    except Exception:shutil.rmtree(target);raise
    return {'restored':str(target.resolve()),'network_suspended':True,'next_action':'stop the original instance, verify owner policy, then run resume'}


def renew(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    directory=Path(directory)
    with runtime_lock(directory):
        identity=Identity(directory);now=datetime.now(timezone.utc)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,identity.id)])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(identity.key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),False)
            .sign(identity.key,algorithm=None))
        temporary=directory/'identity.pem.new'
        with open(temporary,'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM));f.flush();os.fsync(f.fileno())
        temporary.replace(directory/'identity.pem')
    return {'id':identity.id,'renewed':True,'next_action':'restart; peers learn the same-key certificate through signed discovery. Manually pinned peers and seed consumers need updated cards.'}
