"""Optional admission friction. Work grants no identity trust or data permission."""
import hashlib
import hmac
import secrets
import time

from .crypto import Invalid, canonical, valid_id

DOMAIN = b"agentmesh.admission-work.v1\x00"
MAX_BITS = 20


def work_valid(ticket, nonce):
    if type(nonce) is not int or not 0 <= nonce < 2**64:
        return False
    bits = ticket['body']['bits']
    if type(bits) is not int or not 0 <= bits <= MAX_BITS:
        return False
    hashed = hashlib.sha256(DOMAIN + canonical(ticket) + nonce.to_bytes(8, 'big')).digest()
    return int.from_bytes(hashed, 'big') < 2**(256-bits)


class Issuer:
    def __init__(self, server_id, network, bits=0):
        if type(bits) is not int or not 0 <= bits <= MAX_BITS:
            raise Invalid('work difficulty must be between 0 and 20 bits')
        self.secret = secrets.token_bytes(32)
        self.server_id, self.network, self.bits = server_id, network, bits

    def issue(self, peer, payload, *, now=None):
        if not valid_id(peer) or not valid_id(payload):
            raise Invalid('invalid challenge binding')
        now = int(time.time()) if now is None else now
        body = dict(server=self.server_id, network=self.network, action='register', peer=peer,
                    payload=payload, expires=now+120, bits=self.bits, salt=secrets.token_hex(16))
        return {'body': body, 'mac': hmac.digest(self.secret, canonical(body), 'sha256').hex()}

    def verify(self, ticket, nonce, peer, payload, *, now=None):
        now = int(time.time()) if now is None else now
        try:
            body = ticket['body']
            if set(ticket) != {'body', 'mac'} or set(body) != {
                'server','network','action','peer','payload','expires','bits','salt'}:
                raise Invalid('invalid ticket schema')
            expected = hmac.digest(self.secret, canonical(body), 'sha256').hex()
            if not isinstance(ticket['mac'], str) or not hmac.compare_digest(expected, ticket['mac']):
                raise Invalid('invalid challenge authenticator')
            if (body['server'] != self.server_id or body['network'] != self.network
                    or body['action'] != 'register' or body['peer'] != peer or body['payload'] != payload
                    or type(body['expires']) is not int or not now < body['expires'] <= now+120
                    or body['bits'] != self.bits):
                raise Invalid('expired or mismatched challenge')
            if not work_valid(ticket, nonce):
                raise Invalid('insufficient work')
            return body['salt'], body['expires']
        except (KeyError, TypeError) as exc:
            raise Invalid('invalid challenge') from exc


def solve(ticket, *, max_seconds=2.0, max_bits=MAX_BITS):
    """A hostile seed cannot demand unbounded computation from the client."""
    try:
        bits = ticket['body']['bits']
        if type(bits) is not int or not 0 <= bits <= min(max_bits, MAX_BITS):
            raise Invalid('seed requested excessive work')
        prefix = DOMAIN + canonical(ticket)
    except (KeyError, TypeError) as exc:
        raise Invalid('invalid work challenge') from exc
    deadline = time.monotonic()+max_seconds
    target = 2**(256-bits)
    for nonce in range(2**64):
        if nonce % 1024 == 0 and time.monotonic() >= deadline:
            raise Invalid('work budget exhausted; retry later or choose another seed')
        if int.from_bytes(hashlib.sha256(prefix+nonce.to_bytes(8,'big')).digest(),'big') < target:
            return nonce
    raise Invalid('work nonce space exhausted')
