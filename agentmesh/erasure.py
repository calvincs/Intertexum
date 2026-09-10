"""Authenticated, seed-specific removal requests and verifiable receipts."""
import secrets
import time
from .crypto import Invalid, canonical, certificate, public_id, sign, verify

REQUEST_DOMAIN='agentmesh.deregister.v1'
RECEIPT_DOMAIN='agentmesh.deregister-receipt.v1'


def request(node, seed, network):
    now=int(time.time())
    return sign(node.identity.key,REQUEST_DOMAIN,dict(peer=node.id,certificate=node.identity.pem,
        seed=seed,network=network,issued=now,expires=now+300,nonce=secrets.token_hex(16)))


def validate(obj, seed, network):
    try:
        if len(canonical(obj))>8192: raise Invalid('oversized removal request')
        body=obj['body']
        if set(body)!={'peer','certificate','seed','network','issued','expires','nonce'}:
            raise Invalid('invalid removal schema')
        if body['seed']!=seed or body['network']!=network:
            raise Invalid('removal request targets another seed or network')
        now=int(time.time())
        if (type(body['issued']) is not int or type(body['expires']) is not int
                or not 0<body['expires']-body['issued']<=300
                or body['issued']>now+30 or not now<body['expires']<=now+330):
            raise Invalid('removal request expired or future dated')
        if not isinstance(body['nonce'],str) or len(body['nonce'])!=32:
            raise Invalid('invalid request nonce')
        cert=certificate(body['certificate'])
        if public_id(cert.public_key())!=body['peer']:
            raise Invalid('removal identity mismatch')
        # An expired transport certificate does not invalidate proof of key
        # possession for removal. This grants no connection/data permission.
        return verify(obj,cert.public_key(),REQUEST_DOMAIN)
    except (KeyError,TypeError) as exc:
        raise Invalid('invalid removal request') from exc
