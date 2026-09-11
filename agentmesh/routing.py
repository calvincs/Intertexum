"""Opt-in, bounded link-state routing of sealed messages.

Advertisements are hints, never grants. Each custody hop pays its successor's
hashcash toll; only a signed recipient receipt marks end-to-end delivery.
"""
import hashlib
import secrets
import threading
import time
from collections import deque

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import Invalid, Denied, canonical, decode, sign, verify, valid_id, digest

LSA = 'agentmesh.route-advertisement.v1'
SEALED = 'agentmesh.routed-message.v1'
HOP = 'agentmesh.route-hop.v1'
RECEIPT = 'agentmesh.route-receipt.v1'
DEFAULTS = dict(enabled=False, forward=False, neighbors=[], pow_bits=16,
                max_hops=4, max_solve_bits=20, max_solve_ms=2000,
                solve_hour_ms=120000, max_pending=256, max_bytes=8388608)


def config(node):
    p = node.directory / 'routing.json'
    return validate_config(decode(p.read_bytes()) if p.exists() else {})


def validate_config(values):
    if not isinstance(values, dict) or set(values) - set(DEFAULTS):
        raise Invalid('unknown routing policy')
    c = {**DEFAULTS, **values}
    if any(type(c[k]) is not bool for k in ('enabled', 'forward')):
        raise Invalid('routing switches must be booleans')
    bounds = {'pow_bits': (8, 24), 'max_hops': (1, 4), 'max_solve_bits': (8, 24),
              'max_solve_ms': (100, 10000), 'solve_hour_ms': (1000, 3600000),
              'max_pending': (1, 1024), 'max_bytes': (65536, 33554432)}
    for k, (lo, hi) in bounds.items():
        if type(c[k]) is not int or not lo <= c[k] <= hi:
            raise Invalid('invalid routing limit: ' + k)
    if (not isinstance(c['neighbors'], list) or len(c['neighbors']) > 8
            or any(not valid_id(x) for x in c['neighbors'])
            or len(set(c['neighbors'])) != len(c['neighbors'])):
        raise Invalid('routing neighbors must be up to eight distinct admitted peer IDs')
    return c


def configure(node, values):
    from .onboarding import private_write
    c = validate_config(values)
    for peer in c['neighbors']:
        node.peer(peer)
    private_write(node.directory / 'routing.json', c)
    return c


def schema(node):
    node.db.executescript('''
      CREATE TABLE IF NOT EXISTS route_lsas(peer TEXT PRIMARY KEY,seq INTEGER,expires INTEGER,wire TEXT);
      CREATE TABLE IF NOT EXISTS route_sequence(id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER);
      INSERT OR IGNORE INTO route_sequence VALUES(1,0);
      CREATE TABLE IF NOT EXISTS route_queue(id TEXT PRIMARY KEY,message TEXT,origin TEXT,destination TEXT,
        wire TEXT,chain TEXT,state TEXT,attempts INTEGER,next INTEGER,expires INTEGER,error TEXT,next_hop TEXT);
      CREATE TABLE IF NOT EXISTS route_receipts(id TEXT PRIMARY KEY,wire TEXT,expires INTEGER);
      CREATE TABLE IF NOT EXISTS route_work(hour INTEGER PRIMARY KEY,spent INTEGER);
    ''')
    node.route_lock = threading.Lock()
    node.route_links = {}
    node.route_failures = {}


def require(node, forwarding=False):
    node.capability('network')
    c = config(node)
    if not c['enabled'] or (forwarding and not c['forward']):
        raise Denied('mesh routing disabled by owner')
    return c


def key(node):
    # Independent X25519 secret, domain-separated from the signing identity.
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'agentmesh.route-key.v1').derive(node.identity.key.private_bytes_raw())
    return X25519PrivateKey.from_private_bytes(seed)


def neighbors(node):
    c = config(node)
    ids = c['neighbors'] or sorted(p['card']['id'] for p in node.peers())[:8]
    out = []
    for peer in ids:
        try:
            node.peer(peer)
            if peer != node.id and not node.defense.blocked(peer=peer):
                out.append(peer)
        except Denied:
            pass
    return out


def price(node):
    from .message_work import config as message_config
    return max(config(node)['pow_bits'], message_config(node)['bits'])


def advertise(node):
    c = require(node)
    now = int(time.time())
    with node.transaction():
        seq = node.db.execute('UPDATE route_sequence SET value=value+1 WHERE id=1 RETURNING value').fetchone()[0]
        links = sorted(p for p, until in node.route_links.items()
                       if until > now and p in neighbors(node))
        obj = sign(node.identity.key, LSA, dict(version=1, origin=node.id, seq=seq,
                   expires=now+90, links=links, forward=c['forward'], bits=price(node),
                   key=key(node).public_key().public_bytes_raw().hex()))
        _store_lsa(node, obj, obj['body'])
    return obj


def _store_lsa(node, obj, b):
    old = node.db.execute('SELECT seq FROM route_lsas WHERE peer=?', (b['origin'],)).fetchone()
    if old and b['seq'] <= old[0]:
        return
    if not old and node.db.execute('SELECT count(*) FROM route_lsas').fetchone()[0] >= 32:
        raise Denied('routing table capacity reached')
    node.db.execute('INSERT OR REPLACE INTO route_lsas VALUES(?,?,?,?)',
                    (b['origin'], b['seq'], b['expires'], canonical(obj).decode()))


def ingest_lsa(node, obj):
    try:
        if (not isinstance(obj, dict) or not isinstance(obj.get('body'), dict)
                or not valid_id(obj['body'].get('origin')) or len(canonical(obj)) > 16384):
            raise Invalid('invalid route advertisement bounds')
        b = obj['body']; origin = b['origin']
        b = verify(obj, node._key(origin), LSA)
        if (set(b) != {'version', 'origin', 'seq', 'expires', 'links', 'forward', 'bits', 'key'}
                or type(b['version']) is not int or b['version'] != 1
                or type(b['seq']) is not int or not 0 < b['seq'] < 2**63
                or type(b['expires']) is not int or not int(time.time()) < b['expires'] <= int(time.time())+120
                or type(b['forward']) is not bool or type(b['bits']) is not int or not 8 <= b['bits'] <= 28
                or not valid_id(b['key']) or not isinstance(b['links'], list) or len(b['links']) > 8
                or any(not valid_id(p) or p == origin for p in b['links'])
                or len(set(b['links'])) != len(b['links'])):
            raise Invalid('invalid route advertisement')
        if origin == node.id:
            return  # A gossip peer cannot advance our own sequence.
        with node.transaction():
            _store_lsa(node, obj, b)
    except (KeyError, TypeError, ValueError) as exc:
        raise Invalid('invalid route advertisement') from exc


def exchange(node, requester):
    require(node); node.peer(requester)

    if not node.defense.consume([('route-sync:'+requester, .2, 4)]):
        raise Denied('route exchange rate limited')
    with node.lock:
        lsas = [decode(r[0].encode()) for r in node.db.execute(
            'SELECT wire FROM route_lsas WHERE expires>? ORDER BY peer LIMIT 32', (int(time.time()),))]
        receipts = [decode(r[0].encode()) for r in node.db.execute(
            'SELECT wire FROM route_receipts WHERE expires>? ORDER BY id LIMIT 256', (int(time.time()),))]
    return {'protocol': LSA, 'advertisements': lsas, 'receipts': receipts}


def refresh(node):
    from .network import Client
    require(node)
    advertise(node)
    for peer in neighbors(node):
        try:
            answer = Client(node, peer, timeout=20).request('route_exchange')
            if (not isinstance(answer, dict) or set(answer) != {'protocol', 'advertisements', 'receipts'}
                    or answer['protocol'] != LSA or not isinstance(answer['advertisements'], list)
                    or len(answer['advertisements']) > 32 or not isinstance(answer['receipts'], list)
                    or len(answer['receipts']) > 256):
                raise Invalid('invalid routing exchange')
            for obj in answer['advertisements']:
                try:
                    ingest_lsa(node, obj)
                except (Denied, Invalid):
                    continue  # Unknown identities never become trusted by gossip.
            for receipt in answer['receipts']:
                try:
                    ingest_receipt(node, receipt)
                except (Denied, Invalid):
                    continue
            node.route_links[peer] = int(time.time())+90
            node.route_failures.pop(peer, None)
        except (Denied, Invalid, OSError):
            node.route_links.pop(peer, None)
            node.route_failures[peer] = int(time.time())+30
    advertise(node)
    return status(node)


def table(node):
    now = int(time.time())
    with node.lock:
        rows = node.db.execute('SELECT wire FROM route_lsas WHERE expires>?', (now,)).fetchall()
    ads = {}
    for r in rows:
        obj = decode(r[0].encode()); b = obj['body']
        try:
            node.peer(b['origin']) if b['origin'] != node.id else None
            if not node.defense.blocked(peer=b['origin']):
                ads[b['origin']] = b
        except Denied:
            pass
    return ads


def routes(node, destination, *, visited=(), remaining=None):
    c = require(node); ads = table(node)
    limit = c['max_hops'] if remaining is None else min(remaining, c['max_hops'])
    queue = deque([[node.id]]); found = []
    while queue and len(found) < 8:
        path = queue.popleft(); at = path[-1]
        if at == destination:
            found.append(path[1:]); continue
        if len(path)-1 >= limit or (at != node.id and not ads.get(at, {}).get('forward')):
            continue
        for peer in sorted(ads.get(at, {}).get('links', [])):
            if peer in path or peer in visited or peer not in ads:
                continue
            if at not in ads[peer]['links']:
                continue  # Require both endpoints' signed, live observations.
            if at == node.id and (peer not in neighbors(node) or
                    node.route_failures.get(peer, 0) > time.time()):
                continue
            queue.append(path+[peer])
        if len(queue) > 256:
            break
    return sorted(found, key=lambda path: (len(path), sum(1 << ads[p]['bits'] for p in path), path))


def status(node):
    c = config(node)
    with node.lock:
        deliveries = [dict(r) for r in node.db.execute(
            'SELECT id,message,destination,state,attempts,expires,error,next_hop FROM route_queue ORDER BY id LIMIT 256')]
    ads = table(node)
    try:
        learned = {peer: routes(node, peer) for peer in sorted(ads) if peer != node.id} if c['enabled'] else {}
    except Denied:
        learned = {}
    return {'protocol': LSA, 'enabled': c['enabled'], 'forward': c['forward'],
            'max_hops': c['max_hops'], 'advertisements': len(ads),
            'routes': learned, 'worker_error': getattr(node, 'routing_error', None),
            'deliveries': deliveries, 'failed_neighbors_until': dict(node.route_failures),
            'acknowledgement': 'forwarded means next-hop custody; delivered requires signed recipient receipt'}


def _aead(shared, header):
    return ChaCha20Poly1305(HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'agentmesh.route-seal.v1\0'+canonical(header)).derive(shared))


def queue_message(node, peer, content, ttl=600):
    node.capability('send'); c = require(node); node.peer(peer)
    if type(ttl) is not int or not 60 <= ttl <= 3600 or not isinstance(content, str) or len(content.encode()) > 8192:
        raise Invalid('routed message requires 60-3600s TTL and at most 8 KiB text')
    ads = table(node)
    if peer not in ads or not routes(node, peer):
        raise Denied('no learned route; refresh routing and check owner-enabled neighbors')
    message = node.make_message(peer, content, expires=int(time.time())+ttl)
    if len(canonical(message)) > 16000:
        raise Invalid('encoded routed message exceeds 16000 bytes')
    ephemeral = X25519PrivateKey.generate()
    header = dict(version=1, origin=node.id, recipient=peer, message=message['id'],
                  expires=message['body']['expires'], max_hops=c['max_hops'],
                  ephemeral=ephemeral.public_key().public_bytes_raw().hex(), nonce=secrets.token_hex(12))
    try:
        cipher = _aead(ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(ads[peer]['key']))), header)
    except ValueError as exc:
        raise Invalid('invalid recipient encryption key') from exc
    envelope = sign(node.identity.key, SEALED, {**header,
                    'ciphertext': cipher.encrypt(bytes.fromhex(header['nonce']), canonical(message), canonical(header)).hex()})
    with node.transaction():
        _enqueue(node, envelope, [])
    return {'id': envelope['id'], 'message': message['id'], 'state': 'queued',
            'expires': header['expires'], 'acknowledgement': 'await signed recipient receipt in routing_status'}


def _envelope(node, obj):
    try:
        if (not isinstance(obj, dict) or not isinstance(obj.get('body'), dict)
                or not valid_id(obj['body'].get('origin')) or len(canonical(obj)) > 40000):
            raise Invalid('invalid sealed route envelope bounds')
        b = verify(obj, node._key(obj['body']['origin']), SEALED)
        if (set(b) != {'version','origin','recipient','message','expires','max_hops','ephemeral','nonce','ciphertext'}
                or type(b['version']) is not int or b['version'] != 1
                or any(not valid_id(b[x]) for x in ('origin','recipient','message','ephemeral'))
                or b['origin'] == b['recipient'] or type(b['expires']) is not int
                or not int(time.time()) < b['expires'] <= int(time.time())+3600
                or type(b['max_hops']) is not int or not 1 <= b['max_hops'] <= 4
                or not isinstance(b['nonce'], str) or len(bytes.fromhex(b['nonce'])) != 12
                or not isinstance(b['ciphertext'], str) or not 16 <= len(bytes.fromhex(b['ciphertext'])) <= 16384):
            raise Invalid('invalid sealed route envelope')
        return b
    except (KeyError, TypeError, ValueError) as exc:
        raise Invalid('invalid sealed route envelope') from exc


def _enqueue(node, obj, chain):
    b = obj['body']; c = config(node)
    if node.db.execute('SELECT 1 FROM route_queue WHERE id=?', (obj['id'],)).fetchone():
        return
    node.db.execute('DELETE FROM route_queue WHERE expires<=?', (int(time.time()),))
    count, size = node.db.execute('SELECT count(*),coalesce(sum(length(wire)+length(chain)),0) FROM route_queue').fetchone()
    wire, history = canonical(obj).decode(), canonical(chain).decode()
    if count >= c['max_pending'] or size+len(wire)+len(history) > c['max_bytes']:
        raise Denied('routing custody budget exhausted')
    if node.db.execute('SELECT count(*) FROM route_queue WHERE origin=?', (b['origin'],)).fetchone()[0] >= 64:
        raise Denied('routing origin budget exhausted')
    node.db.execute('INSERT INTO route_queue VALUES(?,?,?,?,?,?,?,0,?,?,?,?)',
        (obj['id'], b['message'], b['origin'], b['recipient'], wire, history, 'queued', int(time.time()), b['expires'], '', ''))


def _proof(body):
    nonce = body['nonce']; prefix = {k:v for k,v in body.items() if k != 'nonce'}
    return (type(nonce) is int and 0 <= nonce < 2**63 and
        int.from_bytes(hashlib.sha256(HOP.encode()+b'\0'+canonical(prefix)+nonce.to_bytes(8,'big')).digest(),'big') < 2**(256-body['bits']))


def _chain(node, obj, chain, requester):
    b = obj['body']
    if not isinstance(chain, list) or not 1 <= len(chain) <= b['max_hops']:
        raise Invalid('route hop limit exceeded')
    previous = obj['id']; payer = b['origin']; visited = [payer]
    for hop in chain:
        h = verify(hop, node._key(payer), HOP)
        if (set(h) != {'envelope','payer','receiver','previous','expires','bits','nonce'}
                or h['envelope'] != obj['id'] or h['payer'] != payer or h['previous'] != previous
                or type(h['expires']) is not int or h['expires'] != b['expires']
                or not valid_id(h['receiver']) or h['receiver'] in visited
                or type(h['bits']) is not int or not 8 <= h['bits'] <= 28 or not _proof(h)):
            raise Invalid('invalid paid hop chain')
        visited.append(h['receiver']); payer = h['receiver']; previous = hop['id']
    if chain[-1]['body']['payer'] != requester or payer != node.id:
        raise Denied('wrong routing custody sender or recipient')
    if chain[-1]['body']['bits'] < price(node):
        raise Denied('routing toll below current price')
    return visited


def accept(node, requester, envelope, chain):
    node.capability('receive'); c = require(node); node.peer(requester)
    b = _envelope(node, envelope)
    _chain(node, envelope, chain, requester)
    if len(chain) > c['max_hops']:
        raise Denied('owner routing hop limit exceeded')
    if b['recipient'] != node.id:
        require(node, forwarding=True); node.capability('send')
        if len(chain) >= min(b['max_hops'], c['max_hops']):
            raise Denied('routing hop budget exhausted')
    with node.transaction():
        old = node.db.execute('SELECT state FROM route_queue WHERE id=?', (envelope['id'],)).fetchone()
        if not old:
            from .message_work import budget
            budget(node, 'routing:'+requester, 1, len(canonical(envelope)), 128, 4194304)
            budget(node, 'routing:global', 1, len(canonical(envelope)), 512, 16777216)
            _enqueue(node, envelope, chain)
        if b['recipient'] == node.id:
            header = {k:v for k,v in b.items() if k != 'ciphertext'}
            try:
                cipher = _aead(key(node).exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(b['ephemeral']))), header)
                message = decode(cipher.decrypt(bytes.fromhex(b['nonce']), bytes.fromhex(b['ciphertext']), canonical(header)))
            except (ValueError, InvalidTag) as exc:
                raise Invalid('sealed payload authentication failed') from exc
            if (not isinstance(message, dict) or not isinstance(message.get('body'), dict)
                    or message.get('id') != b['message'] or message['body'].get('expires') != b['expires']):
                raise Invalid('sealed message binding mismatch')
            node.receive_message(message, b['origin'], _routed_work=chain[-1]['body']['bits'])
            receipt = sign(node.identity.key, RECEIPT, dict(version=1, envelope=envelope['id'],
                message=b['message'], origin=b['origin'], recipient=node.id, expires=b['expires']))
            ingest_receipt(node, receipt)
        return {'id': envelope['id'], 'custody': True, 'recipient_delivery': b['recipient'] == node.id}


def ingest_receipt(node, receipt):
    try:
        if (not isinstance(receipt, dict) or not isinstance(receipt.get('body'), dict)
                or not valid_id(receipt['body'].get('recipient')) or len(canonical(receipt)) > 2048):
            raise Invalid('invalid route receipt bounds')
        b = receipt['body']; b = verify(receipt, node._key(b['recipient']), RECEIPT)
        if (set(b) != {'version','envelope','message','origin','recipient','expires'}
                or type(b['version']) is not int or b['version'] != 1
                or any(not valid_id(b[k]) for k in ('envelope','message','origin','recipient'))
                or type(b['expires']) is not int or not int(time.time()) < b['expires'] <= int(time.time())+3600):
            raise Invalid('invalid route receipt')
        with node.transaction():
            row = node.db.execute('SELECT * FROM route_queue WHERE id=?', (b['envelope'],)).fetchone()
            if row is None:
                return
            if any(row[k] != b[v] for k,v in [('message','message'),('origin','origin'),('destination','recipient'),('expires','expires')]):
                raise Invalid('route receipt binding mismatch')
            node.db.execute('DELETE FROM route_receipts WHERE expires<=?', (int(time.time()),))
            node.db.execute('INSERT OR REPLACE INTO route_receipts VALUES(?,?,?)', (b['envelope'], canonical(receipt).decode(), b['expires']))
            node.db.execute("UPDATE route_queue SET state='delivered',error='' WHERE id=?", (b['envelope'],))
    except (KeyError, TypeError, ValueError) as exc:
        raise Invalid('invalid route receipt') from exc


def pay(node, obj, chain, peer, bits):
    c = require(node); node.capability('send')
    if bits > c['max_solve_bits']:
        raise Denied('next-hop toll exceeds owner work limit')
    h = dict(envelope=obj['id'], payer=node.id, receiver=peer,
             previous=chain[-1]['id'] if chain else obj['id'], expires=obj['body']['expires'], bits=bits)
    prefix = HOP.encode()+b'\0'+canonical(h); limit = 2**(256-bits)
    hour = int(time.time())//3600
    with node.transaction():
        node.db.execute('DELETE FROM route_work WHERE hour<>?', (hour,))
        node.db.execute('INSERT OR IGNORE INTO route_work VALUES(?,0)', (hour,))
        spent = node.db.execute('SELECT spent FROM route_work WHERE hour=?', (hour,)).fetchone()[0]
        if spent+c['max_solve_ms'] > c['solve_hour_ms']:
            raise Denied('routing hourly work budget exhausted')
        # Reserve before computing; a crash cannot refund spent work.
        node.db.execute('UPDATE route_work SET spent=spent+? WHERE hour=?', (c['max_solve_ms'],hour))
    started = time.monotonic(); nonce = 0
    try:
        while int.from_bytes(hashlib.sha256(prefix+nonce.to_bytes(8,'big')).digest(),'big') >= limit:
            nonce += 1
            if nonce % 1024 == 0 and (time.monotonic()-started)*1000 >= c['max_solve_ms']:
                raise Denied('routing work time limit exceeded')
        return sign(node.identity.key, HOP, {**h, 'nonce': nonce})
    finally:
        used = min(c['max_solve_ms'], max(1, int((time.monotonic()-started)*1000)+1))
        with node.transaction():
            node.db.execute('UPDATE route_work SET spent=spent-? WHERE hour=?', (c['max_solve_ms']-used,hour))


def deliver(node):
    from .network import Client
    require(node); node.capability('send')
    with node.lock:
        node.db.execute("UPDATE route_queue SET state='expired' WHERE expires<=? AND state!='delivered'", (int(time.time()),))
        node.db.execute("UPDATE route_queue SET wire='',chain='[]' WHERE expires<=? AND wire<>''", (int(time.time()),))
        node.db.execute('DELETE FROM route_receipts WHERE expires<=?', (int(time.time()),))
        row = node.db.execute("SELECT * FROM route_queue WHERE state IN ('queued','forwarded') AND next<=? ORDER BY next,id LIMIT 1", (int(time.time()),)).fetchone()
    if row is None:
        return
    obj, chain = decode(row['wire'].encode()), decode(row['chain'].encode())
    if chain:
        require(node, forwarding=True)
    visited = [obj['body']['origin']]+[x['body']['receiver'] for x in chain]
    candidates = routes(node, row['destination'], visited=visited,
                        remaining=obj['body']['max_hops']-len(chain))
    if row['state'] == 'forwarded':
        # A live peer can acknowledge custody then lose or withhold the message.
        # On receipt timeout, prefer a different first hop if one exists.
        candidates.sort(key=lambda path: path[0] == row['next_hop'])
    error = 'no live route within remaining hop budget'; sent = False; peer = ''
    for path in candidates[:3]:
        peer = path[0]
        try:
            proof = pay(node, obj, chain, peer, table(node)[peer]['bits'])
            reply = Client(node, peer, timeout=20).request('route_accept', envelope=obj, chain=chain+[proof])
            if (not isinstance(reply,dict) or reply.get('id') != row['id'] or reply.get('custody') is not True):
                raise Invalid('invalid next-hop custody acknowledgement')
            sent = True; error = ''; break
        except (Denied, Invalid, OSError, KeyError) as exc:
            error = type(exc).__name__+': '+str(exc)[:150]
            node.route_failures[peer] = int(time.time())+30
    with node.transaction():
        node.db.execute("UPDATE route_queue SET state=CASE WHEN state='delivered' THEN state ELSE ? END,attempts=attempts+1,next=?,error=?,next_hop=? WHERE id=?",
            ('forwarded' if sent else 'queued', int(time.time())+(30 if sent else min(30,2**min(row['attempts']+1,5))), error, peer, row['id']))


class Worker:
    def __init__(self, node):
        self.node = node; self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name='mesh-routing', daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        due = 0
        while not self.stop.wait(.5):
            if not config(self.node)['enabled']:
                continue
            try:
                with self.node.route_lock:
                    if time.monotonic() >= due:
                        refresh(self.node); due = time.monotonic()+15
                    deliver(self.node)
                    self.node.routing_error = None
            except Exception as exc:
                self.node.routing_error = type(exc).__name__+': '+str(exc)[:150]

    def close(self):
        self.stop.set(); self.thread.join()
