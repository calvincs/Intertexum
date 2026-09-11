"""Receiver-priced admission and one-use return permits. No model invocation.

Admission runs inside the caller's insertion transaction. Solver budgets are
reserved durably before computation, outside that transaction and node lock.
"""
import hashlib
import hmac
import secrets
import threading
import time

from .crypto import Invalid, Denied, canonical, decode, digest, sign, verify, valid_id

DOMAIN = b'agentmesh.message-work.v1\x00'
OFFER_DOMAIN = 'agentmesh.reply-offer.v1'
REQUIRED = 'message work required'
DEFAULTS = dict(bits=0, peer_pending=256, peer_bytes=8388608, total_bytes=67108864,
                peer_hour=1000, total_hour=5000, peer_hour_bytes=33554432,
                total_hour_bytes=134217728, max_solve_bits=22, max_solve_ms=10000,
                peer_solve_hour_ms=60000, total_solve_hour_ms=120000,
                reply_seconds=86400, reply_bytes=32768)
BOUNDS = dict(bits=(0,28), peer_pending=(1,10000), peer_bytes=(1,268435456),
              total_bytes=(1,1073741824), peer_hour=(1,100000), total_hour=(1,100000),
              peer_hour_bytes=(1,1073741824), total_hour_bytes=(1,1073741824),
              max_solve_bits=(0,28), max_solve_ms=(100,60000),
              peer_solve_hour_ms=(100,3600000), total_solve_hour_ms=(100,3600000),
              reply_seconds=(60,604800), reply_bytes=(1,32768))


class WorkBudget(Denied):
    """A durable per-message computation limit needs an owner decision."""


def config(node):
    path = node.directory/'message-policy.json'
    values = decode(path.read_bytes()) if path.exists() else {}
    return validate_config(values)


def validate_config(values):
    if not isinstance(values, dict) or set(values)-set(DEFAULTS):
        raise Invalid('invalid message policy fields')
    for key, value in values.items():
        lo, hi = BOUNDS[key]
        if type(value) is not int or not lo <= value <= hi:
            raise Invalid('invalid message policy: '+key)
    return {**DEFAULTS, **values}


def schema(node):
    node._message_secret = secrets.token_bytes(32)
    node._message_solver = threading.BoundedSemaphore(1)
    node.db.executescript('''
      CREATE TABLE IF NOT EXISTS message_budget(key TEXT PRIMARY KEY,window INTEGER,n INTEGER,bytes INTEGER);
      CREATE TABLE IF NOT EXISTS message_storage(id TEXT PRIMARY KEY,peer TEXT,bytes INTEGER);
      CREATE INDEX IF NOT EXISTS message_storage_peer ON message_storage(peer);
      CREATE TABLE IF NOT EXISTS message_admitted(id TEXT PRIMARY KEY,peer TEXT,offer TEXT,expires INTEGER);
      CREATE TABLE IF NOT EXISTS message_reply_sent(request TEXT PRIMARY KEY,reply TEXT,expires INTEGER);
      CREATE TABLE IF NOT EXISTS message_work_out(id TEXT PRIMARY KEY,peer TEXT,op TEXT,
        offer TEXT,ticket TEXT,nonce INTEGER,spent INTEGER,expires INTEGER,active INTEGER,consumed TEXT);
      CREATE TRIGGER IF NOT EXISTS message_storage_delete AFTER DELETE ON messages BEGIN
        DELETE FROM message_storage WHERE id=OLD.id;
      END;
      CREATE TRIGGER IF NOT EXISTS post_storage_delete AFTER DELETE ON posts BEGIN
        DELETE FROM message_storage WHERE id=OLD.id;
      END;
    ''')
    for table in ('messages','posts'):
        node.db.execute('INSERT OR IGNORE INTO message_storage SELECT id,json_extract(wire,\'$.body.origin\'),length(CAST(wire AS BLOB)) FROM '+table)


def sweep(node):
    now = int(time.time())
    node.db.execute('DELETE FROM message_budget WHERE window<?', (now//3600,))
    node.db.execute('DELETE FROM message_reply_sent WHERE expires<=?', (now,))
    node.db.execute('DELETE FROM message_admitted WHERE expires<=?', (now,))
    node.db.execute('DELETE FROM message_work_out WHERE expires<=?', (now,))


def budget(node, key, n, size, nlimit, blimit, *, consume=True):
    window = int(time.time())//3600
    row = node.db.execute('SELECT * FROM message_budget WHERE key=?', (key,)).fetchone()
    used, used_bytes = (row['n'],row['bytes']) if row and row['window']==window else (0,0)
    if used+n > nlimit or used_bytes+size > blimit:
        raise Denied('message hourly budget exhausted')
    if not row and node.db.execute('SELECT count(*) FROM message_budget').fetchone()[0]>=4096:
        raise Denied('message budget accounting full')
    if not consume: return
    node.db.execute('INSERT OR REPLACE INTO message_budget VALUES(?,?,?,?)',
                    (key,window,used+n,used_bytes+size))


def network(node):
    from .onboarding import load
    profile = load(node)
    if profile:return profile['connectivity']['network']
    from .connectivity import load_config
    cfg=load_config(node)
    return (cfg or {}).get('network','agentmesh-demo-v1')


def scope(node, peer, op, thread):
    node.capability('receive'); node.peer(peer)
    if node.defense.blocked(peer=peer): raise Denied('peer blocked')
    if op=='message' and thread is None:
        node.require(peer,'message')
    elif op=='thread_post' and valid_id(thread):
        from .conversations import _root, _access
        node.capability('threads')
        root = _root(node,thread); _access(node,root,peer)
        if root['body']['audience']!=['@public']: node.require(peer,'message')
    else: raise Invalid('invalid message work scope')


def check_capacity(node, peer, size, cfg):
    count, used = node.db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM message_storage WHERE peer=?',(peer,)).fetchone()
    total = node.db.execute('SELECT coalesce(sum(bytes),0) FROM message_storage').fetchone()[0]
    if count >= cfg['peer_pending'] or used+size > cfg['peer_bytes'] or total+size > cfg['total_bytes']:
        raise Denied('message storage budget exhausted')


def challenge(node, peer, *, operation, id, thread=None, offer=None):
    if not valid_id(id): raise Invalid('invalid work message ID')
    with node.transaction():
        scope(node,peer,operation,thread)
        cfg=config(node); sweep(node); check_capacity(node,peer,0,cfg)
        budget(node,'receive:'+peer,1,0,cfg['peer_hour'],cfg['peer_hour_bytes'],consume=False)
        budget(node,'receive:global',1,0,cfg['total_hour'],cfg['total_hour_bytes'],consume=False)
        budget(node,'challenge:'+peer,1,0,60,0)
        budget(node,'challenge:global',1,0,240,0)
        if offer is not None: check_offer(node,offer,peer,node.id,id)
        now=int(time.time())
        body=dict(version=1,server=node.id,peer=peer,network=network(node),operation=operation,
                  message=id,thread=thread,offer=digest(canonical(offer)),bits=cfg['bits'],
                  expires=now+120,salt=secrets.token_hex(16))
        return {'body':body,'mac':hmac.digest(node._message_secret,canonical(body),'sha256').hex()}


def check_offer(node, offer, issuer, responder, request):
    b=verify(offer,node.identity.key.public_key() if issuer==node.id else node._key(issuer),OFFER_DOMAIN)
    if (set(b)!={'version','issuer','responder','request','expires','max_bytes','nonce','network'}
        or type(b['version']) is not int or b['version']!=1 or b['issuer']!=issuer
        or b['responder']!=responder or b['request']!=request or b['network']!=network(node)
        or type(b['expires']) is not int or not int(time.time())<b['expires']<=int(time.time())+604800
        or type(b['max_bytes']) is not int or not 1<=b['max_bytes']<=32768
        or not valid_id(b['nonce'])):
        raise Invalid('invalid reply offer')
    return b


def valid_work(ticket, nonce):
    return (type(nonce) is int and 0<=nonce<2**63 and
            int.from_bytes(hashlib.sha256(DOMAIN+canonical(ticket)+nonce.to_bytes(8,'big')).digest(),'big')
            < 2**(256-ticket['body']['bits']))


def admit(node, obj, peer, op, admission=None, *, _routed_work=None):
    """Call after object verification/deduplication, inside insertion transaction."""
    cfg=config(node); sweep(node)
    if node.defense.blocked(peer=peer): raise Denied('peer blocked')
    offer=None; body=obj['body']; thread=body.get('thread') if op=='thread_post' else None
    if _routed_work is not None:
        # Internal-only admission after routing verifies the complete paid hop
        # chain. The peer RPC schema never accepts this keyword.
        if (op != 'message' or body.get('version') != 2 or admission is not None
                or type(_routed_work) is not int or _routed_work < cfg['bits']):
            raise Denied('insufficient routed message work')
    elif op=='message' and body.get('version')==3:
        if admission is not None: raise Invalid('free reply cannot offer work or another reply')
        row=node.db.execute('SELECT * FROM message_work_out WHERE id=?',(body['reply_to'],)).fetchone()
        if not row or not row['active'] or row['peer']!=peer or not row['offer']:
            raise Denied('reply permit unavailable')
        permit=decode(row['offer'].encode())
        b=check_offer(node,permit,node.id,peer,body['reply_to'])
        if permit['id']!=body['permit'] or row['consumed'] is not None:
            raise Denied('reply permit already used or mismatched')
        if len(body['text'].encode())>b['max_bytes']: raise Denied('reply exceeds permit size')
        node.db.execute('UPDATE message_work_out SET consumed=? WHERE id=?',(obj['id'],body['reply_to']))
    elif admission is None:
        if cfg['bits']: raise Denied(REQUIRED)
    else:
        if not isinstance(admission,dict) or set(admission)!={'ticket','nonce','offer'}:
            raise Invalid('invalid message admission envelope')
        ticket=admission['ticket']; offer=admission['offer']
        try:
            b=ticket['body']
            expected={'version','server','peer','network','operation','message','thread','offer','bits','expires','salt'}
            if (not isinstance(ticket,dict) or set(ticket)!={'body','mac'} or set(b)!=expected
                or not isinstance(ticket['mac'],str) or not hmac.compare_digest(ticket['mac'],hmac.digest(node._message_secret,canonical(b),'sha256').hex())
                or b['version']!=1 or b['server']!=node.id or b['peer']!=peer or b['network']!=network(node)
                or b['operation']!=op or b['message']!=obj['id'] or b['thread']!=thread
                or b['offer']!=digest(canonical(offer)) or type(b['bits']) is not int or b['bits']!=cfg['bits']
                or type(b['expires']) is not int or not int(time.time())<b['expires']<=int(time.time())+120
                or not valid_work(ticket,admission['nonce'])):
                raise Denied('invalid or expired message work')
        except (KeyError,TypeError,ValueError) as exc: raise Denied('invalid or expired message work') from exc
        if offer is not None:
            offer_body=check_offer(node,offer,peer,node.id,obj['id'])
            if offer_body['expires']>body.get('expires',int(time.time())+604800):
                raise Invalid('reply offer outlives request')
            if not b['bits']: offer=None
    size=len(canonical(obj)); check_capacity(node,peer,size,cfg)
    budget(node,'receive:'+peer,1,size,cfg['peer_hour'],cfg['peer_hour_bytes'])
    budget(node,'receive:global',1,size,cfg['total_hour'],cfg['total_hour_bytes'])
    node.db.execute('INSERT INTO message_storage VALUES(?,?,?)',(obj['id'],peer,size))
    if offer is not None:
        if node.db.execute('SELECT count(*) FROM message_admitted').fetchone()[0]>=10000: raise Denied('reply offer storage full')
        node.db.execute('INSERT INTO message_admitted VALUES(?,?,?,?)',
                        (obj['id'],peer,canonical(offer).decode(),offer['body']['expires']))


def outbound(node,peer,obj,op):
    with node.transaction():
        sweep(node)
        row=node.db.execute('SELECT * FROM message_work_out WHERE id=?',(obj['id'],)).fetchone()
        if row:
            if row['peer']!=peer or row['op']!=op: raise Invalid('work ID reused for different destination')
            # Renew an expired, unspent offer without creating a second slot.
            # The original request key and cumulative charge remain unchanged.
            old_offer=decode(row['offer'].encode()) if row['offer'] else None
            if old_offer and old_offer['body']['expires']<=int(time.time()) and row['consumed'] is None:
                offer=None; cfg=config(node)
                try:
                    node.capability('receive'); node.require(peer,'message')
                except Denied: pass
                else:
                    offer=sign(node.identity.key,OFFER_DOMAIN,{**old_offer['body'],
                        'expires':min(row['expires'],int(time.time())+cfg['reply_seconds']),
                        'max_bytes':cfg['reply_bytes'],'nonce':secrets.token_hex(32)})
                node.db.execute('UPDATE message_work_out SET offer=?,ticket=NULL,nonce=NULL,active=0 WHERE id=?',
                    (canonical(offer).decode() if offer else None,obj['id']))
                row=node.db.execute('SELECT * FROM message_work_out WHERE id=?',(obj['id'],)).fetchone()
            return dict(row)
        if node.db.execute('SELECT count(*) FROM message_work_out').fetchone()[0]>=10000: raise Denied('outgoing work storage full')
        cfg=config(node); now=int(time.time()); expires=min(obj['body'].get('expires',now+604800),now+604800)
        offer=None
        try:
            node.capability('receive'); node.require(peer,'message')
        except Denied: pass
        else:
            offer=sign(node.identity.key,OFFER_DOMAIN,dict(version=1,issuer=node.id,responder=peer,network=network(node),
                request=obj['id'],expires=min(expires,now+cfg['reply_seconds']),max_bytes=cfg['reply_bytes'],nonce=secrets.token_hex(32)))
        node.db.execute('INSERT INTO message_work_out VALUES(?,?,?,?,NULL,NULL,0,?,0,NULL)',
                        (obj['id'],peer,op,canonical(offer).decode() if offer else None,expires))
        return dict(node.db.execute('SELECT * FROM message_work_out WHERE id=?',(obj['id'],)).fetchone())


def solve_for(client,op,obj):
    node=client.node; cfg=config(node)
    if not node._message_solver.acquire(blocking=False): raise Denied('message solver busy; retry later')
    try:
        row=outbound(node,client.peer_id,obj,op)
        offer=decode(row['offer'].encode()) if row['offer'] else None
        ticket=decode(row['ticket'].encode()) if row['ticket'] else None
        if ticket is None or ticket['body']['expires']<=int(time.time()):
            ticket=client._request('message_challenge',operation=op,id=obj['id'],thread=obj['body'].get('thread'),offer=offer)
            # The channel authenticates the issuer; clients cannot verify its MAC.
            try:
                b=ticket['body']
                if (len(canonical(ticket))>4096 or set(ticket)!={'body','mac'}
                    or set(b)!={'version','server','peer','network','operation','message','thread','offer','bits','expires','salt'}
                    or type(b['version']) is not int or b['version']!=1 or b['server']!=client.peer_id or b['peer']!=node.id or b['network']!=network(node)
                    or b['operation']!=op or b['message']!=obj['id'] or b['thread']!=obj['body'].get('thread')
                    or b['offer']!=digest(canonical(offer)) or type(b['bits']) is not int or not 0<=b['bits']<=cfg['max_solve_bits']
                    or type(b['expires']) is not int or not int(time.time())<b['expires']<=int(time.time())+120
                    or not valid_id(ticket['mac']) or not isinstance(b['salt'],str) or len(b['salt'])!=32):
                    raise WorkBudget('receiver challenge exceeds local policy or has invalid bindings')
            except (KeyError,TypeError,ValueError) as exc: raise WorkBudget('invalid receiver challenge') from exc
            with node.transaction():
                node.db.execute('UPDATE message_work_out SET ticket=?,nonce=NULL WHERE id=?',(canonical(ticket).decode(),obj['id']))
            row['nonce']=None
        if ticket['body']['bits']>cfg['max_solve_bits']: raise WorkBudget('receiver work exceeds local limit')
        nonce=row['nonce']
        if nonce is None:
            prefix=DOMAIN+canonical(ticket); target=2**(256-ticket['body']['bits']); nonce=0
            while True:
                node.capability('send');node.capability('network');node.peer(client.peer_id)
                if op=='thread_post':node.capability('threads')
                cfg=config(node)
                if ticket['body']['bits']>cfg['max_solve_bits']:
                    raise WorkBudget('receiver work exceeds updated local limit')
                if node.defense.blocked(peer=client.peer_id): raise Denied('peer blocked')
                with node.transaction():
                    current=node.db.execute('SELECT spent FROM message_work_out WHERE id=?',(obj['id'],)).fetchone()
                    if not current or current[0]+100>cfg['max_solve_ms']: raise WorkBudget('message work budget exhausted')
                    budget(node,'solve:'+client.peer_id,100,0,cfg['peer_solve_hour_ms'],0)
                    budget(node,'solve:global',100,0,cfg['total_solve_hour_ms'],0)
                    node.db.execute('UPDATE message_work_out SET spent=spent+100 WHERE id=?',(obj['id'],))
                deadline=time.monotonic()+.1; found=False
                while time.monotonic()<deadline:
                    if int.from_bytes(hashlib.sha256(prefix+nonce.to_bytes(8,'big')).digest(),'big')<target:
                        found=True;break
                    nonce+=1
                if found: break
                if ticket['body']['expires']<=int(time.time()): raise Denied('message work expired during solve')
            with node.transaction():
                node.db.execute('UPDATE message_work_out SET nonce=?,active=? WHERE id=?',
                                (nonce,int(ticket['body']['bits']>0),obj['id']))
        node.capability('send');node.capability('network')
        return dict(ticket=ticket,nonce=nonce,offer=offer)
    finally: node._message_solver.release()


def reply_message(node,peer,request,content,ttl=604800,paid_fallback=False):
    from .conversations import enqueue
    if type(paid_fallback) is not bool: raise Invalid('paid_fallback must be boolean')
    if not valid_id(request): raise Invalid('invalid original request ID')
    if type(ttl) is not int or not 60<=ttl<=604800: raise Invalid('invalid reply lifetime')
    from .records import text
    text(content)
    with node.transaction():
        row=node.db.execute('SELECT * FROM message_admitted WHERE id=?',(request,)).fetchone()
        if row and row['peer']!=peer: raise Denied('reply request peer mismatch')
        if not row or row['expires']<=int(time.time()):
            if not paid_fallback:
                reason='reply permit expired' if row else 'no paid request with a reply offer'
                raise Denied(reason+'; use paid_fallback=true for normal admission within owner work limits')
            # Keep v2 wire compatibility: the original ID is part of signed text.
            original=None
            for table in ('messages','posts'):
                stored=node.db.execute('SELECT wire FROM '+table+' WHERE id=?',(request,)).fetchone()
                if stored:
                    original=decode(stored['wire'].encode())['body']; break
            if not original or original['origin']!=peer:
                raise Denied('original request unavailable or peer mismatch; inspect inbox or thread')
            old=node.db.execute('SELECT reply FROM message_reply_sent WHERE request=?',(request,)).fetchone()
            if not old:
                # Permit accounting may have been swept; retained outbox evidence
                # must still prevent replacing a possibly delivered free reply.
                old=node.db.execute("SELECT id AS reply FROM outbox WHERE json_extract(args,'$.message.body.reply_to')=? LIMIT 1",(request,)).fetchone()
            if old:
                delivery=node.db.execute('SELECT state,expires FROM outbox WHERE id=?',(old['reply'],)).fetchone()
                if not delivery or delivery['state']=='delivered' or delivery['expires']>int(time.time()):
                    raise Denied('reply already queued or delivered; inspect outbox')
                # A lost receipt may conceal delivery. Require a separate decision.
                raise Denied('prior reply delivery uncertain; inspect recipient before queueing a new message')
            from .conversations import queue_message
            result=queue_message(node,peer,'In reply to '+request+'\n\n'+content,ttl=ttl)
            node.db.execute('INSERT INTO message_reply_sent VALUES(?,?,?)',(request,result['id'],result['expires']))
            result.update(reply_to=request,admission='normal',free_reply=False)
            return result
        offer=decode(row['offer'].encode()); b=check_offer(node,offer,peer,node.id,request)
        if len(content.encode())>b['max_bytes']: raise Denied('reply exceeds permit size')
        expires=min(int(time.time())+ttl,b['expires'])
        obj=node.make_message(peer,content,expires=expires,reply_to=request,permit=offer['id'])
        # One local reply object per permit, including across receipt epochs.
        old=node.db.execute('SELECT reply FROM message_reply_sent WHERE request=?',(request,)).fetchone()
        if old: raise Denied('reply already queued; inspect outbox')
        result=enqueue(node,peer,'message',{'message':obj},ttl=ttl)
        node.db.execute('INSERT INTO message_reply_sent VALUES(?,?,?)',(request,obj['id'],b['expires']))
        node.db.execute('UPDATE outbox SET expires=? WHERE id=?',(expires,obj['id']))
        result['expires']=expires
        return result


def reply_info(node, request):
    row=node.db.execute('SELECT offer,expires FROM message_admitted WHERE id=?',(request,)).fetchone()
    if not row or row['expires']<=int(time.time()): return None
    if node.db.execute('SELECT 1 FROM message_reply_sent WHERE request=?',(request,)).fetchone(): return None
    b=decode(row['offer'].encode())['body']
    return {'request':request,'expires':b['expires'],'max_bytes':b['max_bytes'],
            'uses':1,'tool':'mesh_reply_message','waives':'proof_of_work_only'}


def configure(node, values):
    from .onboarding import private_write
    cfg=validate_config(values)
    private_write(node.directory/'message-policy.json',cfg)
    return cfg


def resume(node, id):
    if not valid_id(id): raise Invalid('invalid delivery ID')
    with node.transaction():
        row=node.db.execute('SELECT state FROM outbox WHERE id=?',(id,)).fetchone()
        if not row or row['state']!='paused': raise Denied('delivery is not paused')
        node.db.execute('UPDATE message_work_out SET spent=0,ticket=NULL,nonce=NULL WHERE id=?',(id,))
        node.db.execute("UPDATE outbox SET state='queued',next=?,error='' WHERE id=?",(int(time.time()),id))
    return {'id':id,'state':'queued','hourly_work_budgets_reset':False}
