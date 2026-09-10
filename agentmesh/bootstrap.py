"""Hostable, bounded seed directory. Referrals never modify a node's trust store.

Seed TLS authenticates the server; signed announcements authenticate registrants.
Unlike the data listener, this listener accepts previously unknown identities.
It stores endpoint claims but never dials them (no referral-triggered SSRF).
"""
import ipaddress
import json
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from .crypto import Invalid, Denied, canonical, certificate, public_id, sign, verify, valid_id
from .network import Server, TIMEOUT, receive, transmit
from .pow import Issuer, solve

ANNOUNCE_DOMAIN = 'agentmesh.announcement.v1'
MAX_ENTRIES = 1000
MAX_REQUEST = 16384


def validate_card(card, *, public=False):
    if not isinstance(card, dict) or set(card) != {'id','certificate','host','port'}:
        raise Invalid('invalid discovery card')
    cert = certificate(card['certificate'])
    if public_id(cert.public_key()) != card['id']:
        raise Invalid('card identity mismatch')
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise Invalid('expired or future peer certificate')
    if type(card['port']) is not int or not 1 <= card['port'] <= 65535:
        raise Invalid('invalid discovery port')
    if not isinstance(card['host'],str):
        raise Invalid('discovery host must be a numeric IP string')
    try:
        addr = ipaddress.ip_address(card['host'])
    except (ValueError, TypeError) as exc:
        raise Invalid('discovery currently requires a numeric IP address') from exc
    if addr.is_multicast or addr.is_unspecified or (public and not addr.is_global):
        raise Invalid('endpoint is not allowed by seed address policy')
    return cert


def announcement(node, host, port, network, *, ttl=900):
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise Invalid('announcement lifetime must be 1..3600 seconds')
    now = int(time.time())
    body=dict(network=network,card=node.card(host, port),issued=now,expires=now+ttl)
    from .onboarding import membership
    proof=membership(node,body)
    if proof:body['membership']=proof
    return sign(node.identity.key,ANNOUNCE_DOMAIN,body)


def check_announcement(obj, network, *, public=False):
    try:
        if not isinstance(obj, dict) or len(canonical(obj)) > 8192:
            raise Invalid('oversized announcement')
        body = obj['body']
        if set(body) not in ({'network','card','issued','expires'},{'network','card','issued','expires','membership'}) or body['network'] != network:
            raise Invalid('wrong discovery network or schema')
        if (type(body['issued']) is not int or type(body['expires']) is not int
                or not 0 < body['expires']-body['issued'] <= 3600):
            raise Invalid('invalid announcement lifetime')
        now = int(time.time())
        if body['issued'] > now+30 or not now < body['expires'] <= now+3630:
            raise Invalid('announcement expired or future dated')
        if 'membership' in body and not valid_id(body['membership']):raise Invalid('invalid membership proof')
        cert = validate_card(body['card'], public=public)
        return verify(obj, cert.public_key(), ANNOUNCE_DOMAIN)
    except (KeyError, TypeError) as exc:
        raise Invalid('invalid announcement') from exc


class Directory:
    def __init__(self, node, *, network='agentmesh-demo-v1', bits=None, public=False):
        if not isinstance(network, str) or not 1 <= len(network) <= 100:
            raise Invalid('invalid network name')
        self.node, self.network, self.public = node, network, public
        from .rendezvous import Rendezvous
        self.rendezvous=Rendezvous(self)
        self.issuer = Issuer(node.id, network, (18 if public else 0) if bits is None else bits)
        if public and self.issuer.bits<16:
            raise Invalid('public registration requires at least 16 work bits')
        self.lock = threading.Lock()
        self.db = sqlite3.connect(node.directory/'bootstrap.sqlite', isolation_level=None,
                                  check_same_thread=False)
        self.db.executescript('''PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS announcements(
            peer TEXT PRIMARY KEY, issued INTEGER, expires INTEGER, wire TEXT);
          CREATE TABLE IF NOT EXISTS spent(salt TEXT PRIMARY KEY, expires INTEGER);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE IF NOT EXISTS removals(peer TEXT PRIMARY KEY, request_id TEXT,
            received INTEGER, clear_at INTEGER, suppress_until INTEGER, cleared INTEGER DEFAULT 0);
        ''')
        config = json.dumps([network, public])
        old = self.db.execute("SELECT value FROM settings WHERE key='policy'").fetchone()
        if old is not None and old[0] != config:
            self.db.close()
            raise Invalid('bootstrap directory network/address policy cannot change in place')
        self.db.execute("INSERT OR IGNORE INTO settings VALUES('policy',?)", (config,))

    def close(self):
        self.db.close()

    def purge(self):
        self.rendezvous.purge()
        with self.lock:
            now=int(time.time())
            for peer, in self.db.execute('SELECT peer FROM removals WHERE clear_at<=? AND cleared=0',(now,)).fetchall():
                self.db.execute('DELETE FROM announcements WHERE peer=?',(peer,))
                self.node.defense.erase_routine(peer)
                self.db.execute('UPDATE removals SET cleared=1 WHERE peer=?',(peer,))
            self.db.execute('DELETE FROM removals WHERE suppress_until<=? AND cleared=1',(now,))
            self.db.execute('DELETE FROM announcements WHERE expires<=?',(int(time.time()),))
            self.db.execute('DELETE FROM spent WHERE expires<=?',(int(time.time()),))

    def deregister(self, obj):
        from .erasure import validate, RECEIPT_DOMAIN
        body=validate(obj,self.node.id,self.network)
        peer=body['peer'];now=int(time.time())
        self.rendezvous.remove(peer)
        self.purge()
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                old=self.db.execute('SELECT request_id,received,clear_at,suppress_until,cleared FROM removals WHERE peer=?',(peer,)).fetchone()
                if old is None:
                    # Do not allocate persistent state for arbitrary unregistered identities.
                    if self.db.execute('SELECT 1 FROM announcements WHERE peer=?',(peer,)).fetchone() is None:
                        old=(obj['id'],now,now,now,1)
                    else:
                        if self.db.execute('SELECT count(*) FROM removals').fetchone()[0]>=10000:
                            raise Denied('removal queue full; contact the operator')
                        old=(obj['id'],now,now+60,now+3630,0)
                        self.db.execute('INSERT INTO removals VALUES(?,?,?,?,?,?)',(peer,*old))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK');raise
        if old[4]: self.node.defense.erase_routine(peer)
        return sign(self.node.identity.key,RECEIPT_DOMAIN,dict(seed=self.node.id,network=self.network,
            peer=peer,request_id=obj['id'],original_request_id=old[0],accepted_at=old[1],
            clear_at=old[2],suppression_until=old[3],status='cleared' if old[4] else 'scheduled',
            discovery_removed=True,retained_security_evidence=True,
            scope='seed directory and routine peer-linked audit; security evidence and external copies excluded'))

    def forget(self, peer):
        if not valid_id(peer): raise Invalid('invalid peer ID')
        with self.lock:
            self.db.execute('DELETE FROM announcements WHERE peer=?',(peer,))
        self.node.defense.audit('directory_forget',peer=peer)

    def register(self, obj, ticket, nonce):
        try:
            if len(canonical(obj)) > 8192:
                raise Invalid('oversized announcement')
            peer = obj['body']['card']['id']
            salt, expires = self.issuer.verify(ticket, nonce, peer, obj['id'])
        except (KeyError,TypeError) as exc:
            raise Invalid('invalid registration') from exc
        # Cheap work verification precedes certificate/signature validation.
        body = check_announcement(obj, self.network, public=self.public)
        if self.node.defense.blocked(source=body['card']['host'],peer=peer):
            raise Denied('announcement blocked by local policy')
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                now = int(time.time())
                if self.db.execute('SELECT 1 FROM removals WHERE peer=?',(peer,)).fetchone():
                    raise Denied('de-registration pending or replay-suppression interval active')
                self.db.execute('DELETE FROM announcements WHERE expires<=?', (now,))
                self.db.execute('DELETE FROM spent WHERE expires<=?', (now,))
                if self.db.execute('SELECT 1 FROM spent WHERE salt=?',(salt,)).fetchone():
                    raise Denied('work challenge already spent')
                if not self.node.defense.consume([('registration:peer:'+peer,1/60,2)]):
                    raise Denied('identity registration rate limited')
                old = self.db.execute('SELECT issued,wire FROM announcements WHERE peer=?',(peer,)).fetchone()
                if old and (body['issued'] < old[0] or
                            (body['issued'] == old[0] and canonical(obj).decode() != old[1])):
                    raise Denied('announcement does not advance the stored version')
                if not old and self.db.execute('SELECT count(*) FROM announcements').fetchone()[0] >= MAX_ENTRIES:
                    raise Denied('directory full; retry later or use another seed')
                if self.db.execute('SELECT count(*) FROM spent').fetchone()[0] >= 10000:
                    raise Denied('admission budget exhausted')
                self.db.execute('INSERT INTO spent VALUES(?,?)',(salt,expires))
                self.db.execute('INSERT OR REPLACE INTO announcements VALUES(?,?,?,?)',
                    (peer,body['issued'],body['expires'],canonical(obj).decode()))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise
        self.node.defense.audit('registration',peer=peer)
        return {'registered':peer,'expires':body['expires'],'permissions_granted':[]}

    def dispatch(self, request, source=None):
        if not isinstance(request,dict) or set(request) != {'op','args'} or not isinstance(request['args'],dict):
            raise Invalid('invalid bootstrap request')
        op, args = request['op'], request['args']
        if op=='connectivity' and set(args)=={'envelope'} and source is not None:
            return self.rendezvous.call(args['envelope'],source)
        if op == 'challenge' and set(args) == {'peer','payload'}:
            return self.issuer.issue(**args)
        if op == 'register' and set(args) == {'announcement','ticket','nonce'}:
            return self.register(args['announcement'],args['ticket'],args['nonce'])
        if op == 'deregister' and set(args)=={'request'}:
            return self.deregister(args['request'])
        if op == 'discover' and set(args) <= {'after'}:
            after = args.get('after','')
            if after != '' and not valid_id(after):
                raise Invalid('invalid discovery cursor')
            with self.lock:
                rows = self.db.execute('SELECT peer,wire FROM announcements WHERE peer>? AND expires>? AND peer NOT IN (SELECT peer FROM removals) ORDER BY peer LIMIT 51',
                    (after,int(time.time()))).fetchall()
            candidates=[json.loads(r[1]) for r in rows[:50]]
            candidates=[obj for obj in candidates if not self.node.defense.blocked(
                source=obj['body']['card']['host'],peer=obj['body']['card']['id'])]
            return {'announcements':candidates,
                    'next': rows[49][0] if len(rows)>50 else None,'network':self.network}
        raise Invalid('unsupported bootstrap operation')


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        defense=self.server.defense
        source=self.client_address[0]
        self.request.settimeout(TIMEOUT)
        try:
            with self.server.tls.wrap_socket(self.request,server_side=True) as conn:
                try:
                    request=receive(conn,MAX_REQUEST)
                    op=request.get('op') if isinstance(request,dict) else None
                    defense.operation(source,'',op,'bootstrap')
                    result = self.server.directory.dispatch(request,source)
                    response = {'ok':True,'result':result}
                except Denied as exc:
                    response = {'ok':False,'detail':str(exc)}
                    if hasattr(exc,'retry_after'):response['retry_after']=exc.retry_after
                except (Invalid,TypeError,KeyError) as exc:
                    defense.failure(source,event='invalid_bootstrap')
                    response = {'ok':False,'detail':str(exc)}
                transmit(conn,response)
        except (OSError,Invalid):
            defense.failure(source,event='bootstrap_transport')
            return


class BootstrapServer(Server):
    def __init__(self, directory, host='127.0.0.1', port=0):
        self.directory = directory
        self.defense = directory.node.defense
        self.role = 'bootstrap'
        self._slots = threading.BoundedSemaphore(16)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = self.tls.maximum_version = ssl.TLSVersion.TLSv1_3
        self.tls.load_cert_chain(directory.node.identity.cert_path,directory.node.identity.key_path)
        # This is an explicit public discovery listener, separate from mutual-TLS data RPC.
        self.tls.verify_mode = ssl.CERT_NONE
        socketserver.ThreadingTCPServer.__init__(self,(host,port),_Handler)

    def _allow(self, ip):
        return self.defense.connection(ip,'bootstrap')

    def service_actions(self):
        super().service_actions()
        if time.monotonic()-getattr(self,'_purged',0)>60:
            self.directory.purge()
            self._purged=time.monotonic()


class BootstrapClient:
    def __init__(self, seed_card, network='agentmesh-demo-v1'):
        validate_card(seed_card)
        self.card, self.network = seed_card, network

    def request(self, op, **args):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.load_verify_locations(cadata=self.card['certificate'])
        with socket.create_connection((self.card['host'],self.card['port']),timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw,server_hostname=None) as conn:
                expected = certificate(self.card['certificate']).public_bytes(serialization.Encoding.DER)
                if conn.getpeercert(binary_form=True) != expected:
                    raise Denied('seed certificate pin mismatch')
                transmit(conn,{'op':op,'args':args})
                response = receive(conn,512*1024)
        if not isinstance(response,dict) or type(response.get('ok')) is not bool:
            raise Invalid('invalid seed response')
        if not response['ok']:
            retry=response.get('retry_after')
            if type(retry) in (int,float) and 0<retry<=3600:
                from .defense import RateLimited
                raise RateLimited(response.get('detail','seed denied request'),retry)
            raise Denied(response.get('detail','seed denied request'))
        if 'result' not in response:
            raise Invalid('seed response is missing its result')
        return response['result']

    def register(self, node, host, port):
        node.capability("network")
        obj = announcement(node,host,port,self.network)
        ticket = self.request('challenge',peer=node.id,payload=obj['id'])
        try:
            body = ticket['body']
            if any(body[k] != v for k,v in {'server':self.card['id'],'network':self.network,
                'action':'register','peer':node.id,'payload':obj['id']}.items()):
                raise Invalid('seed returned a mismatched work challenge')
            if type(body['expires']) is not int or not int(time.time()) < body['expires'] <= int(time.time())+120:
                raise Invalid('seed returned an expired challenge')
        except (KeyError,TypeError) as exc:
            raise Invalid('invalid seed challenge') from exc
        result = self.request('register',announcement=obj,ticket=ticket,nonce=solve(ticket))
        if (not isinstance(result,dict) or set(result) != {'registered','expires','permissions_granted'}
                or result['registered'] != node.id or result['expires'] != obj['body']['expires']
                or result['permissions_granted'] != []):
            raise Invalid('invalid registration acknowledgement')
        return result

    def deregister(self, node):
        from .erasure import request, RECEIPT_DOMAIN
        obj=request(node,self.card['id'],self.network)
        receipt=self.request('deregister',request=obj)
        body=verify(receipt,certificate(self.card['certificate']).public_key(),RECEIPT_DOMAIN)
        if any(body.get(k)!=v for k,v in dict(peer=node.id,seed=self.card['id'],network=self.network,
                                           request_id=obj['id'],discovery_removed=True).items()):
            raise Invalid('wrong removal receipt')
        return receipt

    def discover(self):
        after, found = '', {}
        for _ in range(21):
            result = self.discover_page(after)
            for obj in result['announcements']:
                body = obj['body']
                found[body['card']['id']] = obj
            cursor = result['next']
            if cursor is None:
                return list(found.values())
            if not valid_id(cursor) or cursor <= after:
                raise Invalid('non-advancing discovery cursor')
            after = cursor
        raise Invalid('discovery exceeds directory limit')

    def discover_page(self, after=''):
        """One bounded page; runtimes pace and rotate discovery between seeds."""
        result=self.request('discover',after=after)
        if (not isinstance(result,dict) or set(result) != {'announcements','next','network'}
                or result['network'] != self.network or not isinstance(result['announcements'],list)
                or len(result['announcements'])>50):raise Invalid('invalid discovery page')
        previous=after
        for obj in result['announcements']:
            body=check_announcement(obj,self.network)
            if body['card']['id']<=previous:raise Invalid('non-advancing discovery entry')
            previous=body['card']['id']
        cursor=result['next']
        if cursor is not None and (not valid_id(cursor) or cursor<=after or cursor<previous):
            raise Invalid('non-advancing discovery cursor')
        return result
