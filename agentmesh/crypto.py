"""Ed25519 signed objects and self-issued certificates for pinned mutual TLS.

The TLS implementation is OpenSSL via Python's ssl module. Certificates are
key containers, not delegatable mesh membership credentials.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_WIRE_BYTES = 2 * 1024 * 1024
ID_RE = re.compile(r"[0-9a-f]{64}\Z")


class Invalid(ValueError):
    """Malformed, inconsistent, or unverifiable input."""


class Denied(PermissionError):
    """An authenticated operation is not authorized."""


def canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise Invalid("not canonical JSON") from exc


def decode(data: bytes):
    if len(data) > MAX_WIRE_BYTES:
        raise Invalid("message too large")

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise Invalid("duplicate JSON key")
            out[k] = v
        return out

    def bad_constant(_):
        raise Invalid("non-finite JSON number")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_id(key: Ed25519PublicKey) -> str:
    if not isinstance(key, Ed25519PublicKey):
        raise Invalid("Ed25519 key required")
    return digest(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def valid_id(value) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def sign(key: Ed25519PrivateKey, domain: str, body: dict) -> dict:
    # Copy through serialization so callers never retain mutable aliases.
    body = decode(canonical(body))
    payload = domain.encode() + b"\x00" + canonical(body)
    return {"body": body, "id": digest(payload), "sig": key.sign(payload).hex()}


def verify(obj: dict, key: Ed25519PublicKey, domain: str) -> dict:
    try:
        if not isinstance(obj, dict) or set(obj) != {"body", "id", "sig"}:
            raise Invalid("invalid signed object fields")
        if not isinstance(obj["body"], dict):
            raise Invalid("body must be an object")
        payload = domain.encode() + b"\x00" + canonical(obj["body"])
        if obj["id"] != digest(payload):
            raise Invalid("content hash mismatch")
        key.verify(bytes.fromhex(obj["sig"]), payload)
        return decode(canonical(obj["body"]))
    except Invalid:
        raise
    except Exception as exc:
        raise Invalid("signature verification failed") from exc


def certificate(pem: str) -> x509.Certificate:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        key = cert.public_key()
        public_id(key)
        if cert.issuer != cert.subject:
            raise Invalid("peer certificate must be self-issued")
        key.verify(cert.signature, cert.tbs_certificate_bytes)
        return cert
    except Invalid:
        raise
    except Exception as exc:
        raise Invalid("invalid peer certificate") from exc


class Identity:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.key_path = self.directory / "identity.key"
        self.cert_path = self.directory / "identity.pem"
        self.key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        if not isinstance(self.key, Ed25519PrivateKey):
            raise Invalid("Ed25519 identity required")
        self.pem = self.cert_path.read_text()
        cert = certificate(self.pem)
        self.id = public_id(self.key.public_key())
        if public_id(cert.public_key()) != self.id:
            raise Invalid("identity key and certificate disagree")

    @classmethod
    def create(cls, directory: Path) -> Identity:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(directory.iterdir()):
            raise Invalid("new node directory must be empty")
        directory.chmod(0o700)
        key = Ed25519PrivateKey.generate()
        peer_id = public_id(key.public_key())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, peer_id)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(key, algorithm=None))
        secret = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
        fd = os.open(directory / "identity.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        (directory / "identity.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cls(directory)
