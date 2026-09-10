"""Short-lived, authenticated signaling only. Never carries data RPC payloads."""
import secrets
import socket
import threading
import time

from .crypto import Invalid, Denied, canonical, certificate, public_id, sign, verify, valid_id

DOMAIN='agentmesh.connectivity-signal.v1'


def envelope(node, seed, network, action, args):
    now=int(time.time())
    return sign(node.identity.key,DOMAIN,dict(origin=node.id,certificate=node.identity.pem,
        seed=seed,network=network,action=action,args=args,issued=now,expires=now+90,
        nonce=secrets.token_hex(16)))


def validate(obj, seed, network):
    try:
        if len(canonical(obj))>14000: raise Invalid('signaling envelope too large')
        b=obj['body']
        if set(b)!={'origin','certificate','seed','network','action','args','issued','expires','nonce'}:
            raise Invalid('invalid signaling schema')
        if b['seed']!=seed or b['network']!=network: raise Invalid('wrong signaling scope')
        if (type(b['issued']) is not int or type(b['expires']) is not int
                or not 0<b['expires']-b['issued']<=90 or b['issued']>time.time()+30
                or not time.time()<b['expires']<=time.time()+120):
            raise Invalid('expired signaling message')
        cert=certificate(b['certificate'])
        if public_id(cert.public_key())!=b['origin']: raise Invalid('signaling identity mismatch')
        if not isinstance(b['args'],dict): raise Invalid('invalid signaling arguments')
        return verify(obj,cert.public_key(),DOMAIN)
    except (KeyError,TypeError) as exc: raise Invalid('malformed signaling envelope') from exc


class Rendezvous:
    def __init__(self, directory):
        self.directory=directory
        self.lock=threading.Lock()
        self.messages={}

    def purge(self):
        with self.lock:
            self.messages={k:v for k,v in self.messages.items() if v['body']['expires']>time.time()}

    def remove(self, peer):
        with self.lock:
            self.messages={k:v for k,v in self.messages.items()
                           if v['body']['origin']!=peer and v['body']['args']['to']!=peer}

    def call(self, obj, source):
        d=self.directory
        b=validate(obj,d.node.id,d.network)
        origin=b['origin'];args=b['args'];action=b['action']
        if d.node.defense.blocked(source=source,peer=origin): raise Denied('signaling identity blocked')
        if not d.node.defense.consume([('signaling:peer:'+origin,2,8)]):
            from .defense import RateLimited
            d.node.defense.failure(source,peer=origin,event='signaling_rate')
            raise RateLimited('signaling identity rate limited',1)
        # Observe is usable before registration, but discloses only the caller's
        # socket address. Other signaling requires live, non-removed registration.
        if action=='observe' and not args:
            return {'observed_ip':source,'tcp_mapping_port_is_not_listener':True}
        with d.lock:
            row=d.db.execute('SELECT wire FROM announcements WHERE peer=? AND expires>? '
                'AND peer NOT IN (SELECT peer FROM removals)',(origin,int(time.time()))).fetchone()
        if row is None: raise Denied('register before using rendezvous')
        self.purge()
        if action=='probe' and set(args)=={'port'}:
            from .crypto import decode
            card=decode(row[0].encode())['body']['card']
            if type(args['port']) is not int or args['port']!=card['port'] or args['port']<1024:
                raise Invalid('probe must target registered unprivileged port')
            if not d.node.defense.consume([('probe:global',.2,2),('probe:'+origin,1/60,1)]):
                raise Denied('probe rate limited')
            # Never dial a supplied hostname or third-party address. A successful
            # TCP connect measures reachability, not remote service identity.
            try:
                with socket.create_connection((source,args['port']),timeout=.5): pass
                reachable=True
            except OSError: reachable=False
            return {'tcp_reachable':reachable,'observed_ip':source,'port':args['port'],
                    'identity_verified':False,'scope':'reachable from this seed only'}
        if action=='poll' and set(args)=={'answers','offers'}:
            if (not isinstance(args['answers'],list) or len(args['answers'])>8
                    or any(not valid_id(x) for x in args['answers']) or type(args['offers']) is not bool):
                raise Invalid('invalid signaling mailbox selection')
            with self.lock:
                found=[v for v in self.messages.values() if v['body']['args']['to']==origin
                       and ((v['body']['args']['type']=='offer' and args['offers']) or
                            (v['body']['args']['type']=='answer' and v['body']['args']['session'] in args['answers']))][:8]
                for v in found: self.messages.pop(v['id'],None)
            return {'messages':found}
        if action=='send' and set(args)=={'to','session','generation','type','sdp'}:
            if (not valid_id(args['to']) or not valid_id(args['session'])
                    or type(args['generation']) is not int or not 1<=args['generation']<2**53
                    or args['type'] not in ('offer','answer') or not isinstance(args['sdp'],str)
                    or len(args['sdp'])>10000): raise Invalid('invalid session description')
            # Only SDP application transports; no search/message/storage payloads.
            if 'm=application ' not in args['sdp'] or 'a=fingerprint:' not in args['sdp']:
                raise Invalid('DTLS data-channel description required')
            with self.lock:
                if obj['id'] in self.messages: return {'queued':True}
                if len(self.messages)>=128 or sum(v['body']['origin']==origin for v in self.messages.values())>=8:
                    raise Denied('rendezvous capacity full')
                self.messages[obj['id']]=obj
            return {'queued':True}
        raise Invalid('unsupported signaling action')
