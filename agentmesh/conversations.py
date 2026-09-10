"""Signed, host-local threads and durable delivery. Remote text is always untrusted."""
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from .crypto import Invalid,Denied,canonical,decode,sign,verify,certificate,public_id,valid_id
from .records import text,audience

DOMAIN='agentmesh.thread.v1'
PAGE_BYTES=512*1024
DELIVERY_CONCURRENCY=4
DELIVERY_PEER_INTERVAL=.5
DELIVERY_DISPATCH_INTERVAL=.125


def schema(node):
    node.db.executescript('''CREATE TABLE IF NOT EXISTS threads(id TEXT PRIMARY KEY,wire TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS posts(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE,thread TEXT,received INTEGER,wire TEXT);
      CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,peer TEXT,op TEXT,args TEXT,state TEXT,attempts INTEGER,next INTEGER,expires INTEGER,error TEXT);
      CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,next);
      CREATE INDEX IF NOT EXISTS outbox_expiry ON outbox(state,expires);
      CREATE INDEX IF NOT EXISTS outbox_peer_state ON outbox(peer,state);
      CREATE TABLE IF NOT EXISTS received_ids(id TEXT PRIMARY KEY,expires INTEGER);
    ''')
    node.db.execute("INSERT OR IGNORE INTO received_ids SELECT id,coalesce(json_extract(wire,'$.body.expires'),0) FROM messages")


def _body(node,kind,content,**fields):
    text(content)
    return sign(node.identity.key,DOMAIN,{'version':1,'kind':kind,'origin':node.id,
        'certificate':node.identity.pem,'text':content,'created_ms':int(time.time()*1000),'nonce':uuid.uuid4().hex,**fields})


def checked(obj):
    try:
        b=obj['body'];key=certificate(b['certificate']).public_key()
        b=verify(obj,key,DOMAIN)
        if b['origin']!=public_id(key) or type(b['version']) is not int or b['version']!=1:raise Invalid('thread identity mismatch')
        if type(b['created_ms']) is not int or b['created_ms']<0 or b['created_ms']>int(time.time()*1000)+300000:raise Invalid('invalid thread timestamp')
        if not isinstance(b['nonce'],str) or len(b['nonce'])!=32:raise Invalid('invalid thread nonce')
        text(b['text'])
        base={'version','kind','origin','certificate','text','created_ms','nonce'}
        if b['kind']=='root':
            if set(b)!=base|{'audience'}:raise Invalid('invalid root fields')
            audience(b['audience'])
            if b['audience']==['*']:raise Invalid('threads require @public or named members')
        elif b['kind']=='reply':
            if set(b)!=base|{'thread','parent'} or not valid_id(b['thread']) or not valid_id(b['parent']):raise Invalid('invalid reply fields')
        else:raise Invalid('unknown thread kind')
        return b
    except (KeyError,TypeError) as exc:raise Invalid('invalid thread object') from exc


def _root(node,tid):
    row=node.db.execute('SELECT wire FROM threads WHERE id=?',(tid,)).fetchone()
    if not row:raise Denied('thread unavailable')
    return decode(row[0].encode())


def _access(node,root,requester):
    body=root['body']
    if requester==node.id:return
    node.require(requester,'read')
    if body['audience']!=['@public']:
        if requester not in body['audience'] or 'read' not in node.peer(requester)['permissions']:raise Denied('thread unavailable')


def create(node,content,members):
    node.capability('threads');node.capability('publish')
    if not isinstance(members,list):raise Invalid('members must be an explicit audience')
    members=sorted(set(members));audience(members)
    if members==['*']:raise Invalid('use @public or named members')
    obj=_body(node,'root',content,audience=members);checked(obj)
    with node.transaction():
        if node.db.execute('SELECT count(*) FROM threads').fetchone()[0]>=1000:raise Denied('thread quota reached')
        seq=node.db.execute("SELECT coalesce(max(rowid),0) FROM threads").fetchone()[0]
        node.db.execute("INSERT OR IGNORE INTO lifecycle VALUES('thread_seq',?)",(seq,))
        node.db.execute("UPDATE lifecycle SET value=max(value,?)+1 WHERE key='thread_seq'",(seq,))
        seq=node.db.execute("SELECT value FROM lifecycle WHERE key='thread_seq'").fetchone()[0]
        node.db.execute('INSERT INTO threads(rowid,id,wire) VALUES(?,?,?)',(seq,obj['id'],canonical(obj).decode()))
    return {'id':obj['id'],'host':node.id,'root':obj,'untrusted_data':True}


def accept(node,obj,requester,admission=None):
    node.capability('threads');node.capability('receive')
    b=checked(obj)
    if b['kind']!='reply' or b['origin']!=requester:raise Invalid('reply sender mismatch')
    if requester!=node.id:
        # The transport authenticates the current pin. A durable signed reply
        # may contain the previous self-issued certificate after same-key
        # renewal; certificates are key containers, not new identities.
        pinned=node.peer(requester)['card']['certificate']
        if public_id(certificate(pinned).public_key())!=b['origin']:
            raise Denied('reply key is not pinned')
    with node.transaction():
        root=_root(node,b['thread']);_access(node,root,requester)
        if root['body']['audience']!=['@public'] and requester!=node.id:node.require(requester,'message')
        if b['parent']!=b['thread'] and not node.db.execute('SELECT 1 FROM posts WHERE id=? AND thread=?',(b['parent'],b['thread'])).fetchone():raise Invalid('parent not in this thread')
        if node.db.execute('SELECT 1 FROM posts WHERE id=?',(obj['id'],)).fetchone():return {'id':obj['id']}
        if node.db.execute('SELECT count(*) FROM posts').fetchone()[0]>=10000:raise Denied('post quota reached')
        if requester!=node.id:
            from .message_work import admit
            admit(node,obj,requester,'thread_post',admission)
        node.db.execute('INSERT INTO posts(id,thread,received,wire) VALUES(?,?,?,?)',(obj['id'],b['thread'],int(time.time()*1000),canonical(obj).decode()))
    return {'id':obj['id']}


def page(node,requester,*,thread=None,after=0,since_ms=0,until_ms=2**63-1,limit=50):
    node.capability('threads')
    if any(type(x) is not int or not 0<=x<=2**63-1 for x in (after,since_ms,until_ms,limit)) or not 1<=limit<=100 or until_ms<since_ms:raise Invalid('invalid thread page')
    with node.lock:
        if thread is not None:
            if not valid_id(thread):raise Invalid('invalid thread ID')
            root=_root(node,thread);_access(node,root,requester)
            rows=node.db.execute('SELECT seq,received,wire FROM posts WHERE thread=? AND seq>? AND received>=? AND received<=? ORDER BY seq LIMIT ?', (thread,after,since_ms,until_ms,limit+1)).fetchall()
        else:
            if requester!=node.id:node.require(requester,'read')
            root=None
            # Root list cursors are stable rowids: roots are retained until explicit retirement.
            rows=node.db.execute('SELECT rowid AS seq,wire FROM threads WHERE rowid>? ORDER BY rowid LIMIT ?', (after,limit+1)).fetchall()
        entries=[];cursor=after;size=len(canonical(root))
        for row in rows[:limit]:
            obj=decode(row['wire'].encode())
            if thread is None:
                try:_access(node,obj,requester)
                except Denied:cursor=row['seq'];continue
                if not since_ms<=obj['body']['created_ms']<=until_ms:cursor=row['seq'];continue
            entry={'object':obj,'cursor':row['seq'],'untrusted_data':True}
            if thread is not None:entry['received_ms']=row['received']
            if requester==node.id:
                from .message_work import reply_info
                offered=reply_info(node,obj['id'])
                if offered:entry['reply_offer']=offered
            cost=len(canonical(entry))
            if size+cost>PAGE_BYTES:break
            entries.append(entry);cursor=row['seq'];size+=cost
        more=bool(rows and (len(rows)>limit or cursor<rows[-1]['seq']))
    return {'root':root,'items':entries,'next':cursor if more else None,'untrusted_data':True,'host':node.id}


def read(node,peer=None,**filters):
    node.capability('threads')
    if peer is None or peer==node.id:return page(node,node.id,**filters)
    from .network import Client
    result=Client(node,peer).request('threads',**filters)
    root=result.get('root')
    if filters.get('thread'):
        if not root or root['id']!=filters['thread']:raise Invalid('wrong thread root')
        body=checked(root)
        if body['kind']!='root' or body['origin']!=peer:raise Invalid('wrong thread host')
        if body['audience']!=['@public'] and node.id not in body['audience']:raise Denied('outside thread audience')
    for entry in result['items']:
        b=checked(entry['object'])
        if root:
            if b['kind']!='reply' or b['thread']!=root['id']:raise Invalid('wrong reply thread')
            if root['body']['audience']!=['@public'] and b['origin'] not in root['body']['audience']+[peer]:raise Denied('unauthorized reply author')
        elif b['kind']!='root' or b['origin']!=peer or (b['audience']!=['@public'] and node.id not in b['audience']):raise Invalid('invalid listed root')
        entry['untrusted_data']=True
    result['untrusted_data']=True
    return result


def enqueue(node,peer,op,args,*,ttl=604800):
    node.capability('send');node.peer(peer)
    if type(ttl) is not int or not 60<=ttl<=604800:raise Invalid('delivery ttl must be 60 seconds..7 days')
    obj=args['message'] if op=='message' else args['post']
    now=int(time.time())
    with node.transaction():
        if node.db.execute('SELECT count(*) FROM outbox').fetchone()[0]>=10000:raise Denied('outbox quota reached; acknowledge completed deliveries')
        node.db.execute('INSERT OR IGNORE INTO outbox VALUES(?,?,?,?,?,0,?,?,?)',(obj['id'],peer,op,canonical(args).decode(),'queued',now,now+ttl,''))
    return {'id':obj['id'],'state':'queued','expires':now+ttl,'acknowledgement':'remote receipt only; not agent processing'}


def queue_message(node,peer,content,ttl=604800):
    # The signed expiry bounds receiver replay suppression after inbox acknowledgement.
    obj=node.make_message(peer,content,expires=int(time.time())+ttl)
    return enqueue(node,peer,'message',{'message':obj},ttl=ttl)


def reply(node,peer,thread,content,parent=None,ttl=604800):
    node.capability('threads');node.capability('send')
    if not valid_id(thread) or (parent is not None and not valid_id(parent)):raise Invalid('invalid thread or parent')
    obj=_body(node,'reply',content,thread=thread,parent=parent or thread)
    if peer==node.id:return accept(node,obj,node.id)
    return enqueue(node,peer,'thread_post',{'post':obj},ttl=ttl)


def deliveries(node,*,after='',limit=50,ack=None):
    node.capability('send')
    if not isinstance(after,str) or (after and not valid_id(after)) or type(limit) is not int or not 1<=limit<=100:raise Invalid('invalid outbox page')
    with node.transaction():
        if ack is not None:
            if not valid_id(ack):raise Invalid('invalid delivery ID')
            node.db.execute("DELETE FROM outbox WHERE id=? AND state IN ('delivered','expired')",(ack,))
        rows=node.db.execute('SELECT id,peer,op,state,attempts,next,expires,error FROM outbox WHERE id>? ORDER BY id LIMIT ?',(after,limit+1)).fetchall()
    return {'items':[dict(r) for r in rows[:limit]],'next':rows[limit-1]['id'] if len(rows)>limit else None}


def _claim_delivery(node, *, paced=False):
    """Claim the oldest queued entry for one idle peer, respecting retry delay."""
    node.capability('send');node.capability('network')
    now=int(time.time())
    with node.transaction():
        node.db.execute("UPDATE outbox SET state='expired' WHERE state IN ('queued','paused') AND expires<=?",(now,))
        active=getattr(node,'_delivery_peers',None)
        if active is None:
            active=node._delivery_peers=set()
        # Only a peer's enqueue-order head can run. A predecessor in backoff
        # still blocks its successors, including replies with causal parents.
        excluded_peers=set(active)
        if paced:
            excluded_peers.update(peer for peer,ready in getattr(node,'_delivery_ready',{}).items()
                                  if ready>time.monotonic())
        excluded=' AND q.peer NOT IN ('+','.join('?' for _ in excluded_peers)+')' if excluded_peers else ''
        row=node.db.execute("""SELECT q.* FROM outbox q
            WHERE q.state='queued' AND q.next<=?
            AND NOT EXISTS (SELECT 1 FROM outbox prior WHERE prior.peer=q.peer
                AND prior.state IN ('queued','paused') AND prior.rowid<q.rowid)
            """+excluded+' ORDER BY q.next,q.rowid LIMIT 1',(now,*excluded_peers)).fetchone()
        if row is not None:
            active.add(row['peer'])
            return row
    return None


def _deliver_claimed(node,row):
    from .network import Client
    try:
        # Policy may have changed after the scheduler claimed this entry.
        node.capability('send');node.capability('network')
        try:
            result=Client(node,row['peer']).request(row['op'],**decode(row['args'].encode()))
            if result.get('id')!=row['id']:raise Invalid('delivery acknowledgement mismatch')
            state='delivered';error=''
        except Exception as exc:
            from .message_work import WorkBudget
            state='paused' if isinstance(exc,WorkBudget) else 'queued'
            error=type(exc).__name__+': '+str(exc)[:150]
        with node.transaction():
            node.db.execute('UPDATE outbox SET state=?,attempts=attempts+1,next=?,error=? WHERE id=?',(state,int(time.time())+min(300,2**min(row['attempts']+1,9)),error,row['id']))
            if state=='delivered':
                if not hasattr(node,'_delivery_ready'):node._delivery_ready={}
                paid=node.db.execute('SELECT 1 FROM message_work_out WHERE id=?',(row['id'],)).fetchone()
                node._delivery_ready[row['peer']]=time.monotonic()+(1.0 if paid else DELIVERY_PEER_INTERVAL)
    finally:
        with node.lock:
            node._delivery_peers.discard(row['peer'])


def deliver(node):
    """Synchronous single attempt, also safe alongside the managed worker."""
    row=_claim_delivery(node)
    if row is not None:
        _deliver_claimed(node,row)


class DeliveryWorker:
    def __init__(self,node):
        self.node=node
        self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)
        node.delivery_worker=self
        node.delivery_error=None

    def run(self):
        last_sweep=0
        next_dispatch=0
        active=set()
        # Joining the executor on close prevents a request from accessing a
        # closed node database. Requests retain the transport's bounded timeout.
        with ThreadPoolExecutor(max_workers=DELIVERY_CONCURRENCY,thread_name_prefix='mesh-delivery') as pool:
            while not self.stop.is_set():
                try:
                    completed={future for future in active if future.done()}
                    active.difference_update(completed)
                    for future in completed:future.result()
                    if time.monotonic()-last_sweep>60:
                        from .cache import sweep
                        sweep(self.node);last_sweep=time.monotonic()
                    while len(active)<DELIVERY_CONCURRENCY and not self.stop.is_set():
                        if time.monotonic()<next_dispatch:break
                        row=_claim_delivery(self.node,paced=True)
                        if row is None:break
                        try:active.add(pool.submit(_deliver_claimed,self.node,row))
                        except BaseException:
                            with self.node.lock:self.node._delivery_peers.discard(row['peer'])
                            raise
                        # Leave room in normal receiver quotas for interactive
                        # traffic while draining a backlog without source bans.
                        next_dispatch=time.monotonic()+DELIVERY_DISPATCH_INTERVAL
                except Exception as exc:self.node.delivery_error=type(exc).__name__
                else:self.node.delivery_error=None
                self.stop.wait(.05 if active else .5)
    def start(self):self.thread.start()
    def close(self):self.stop.set();self.thread.join()


def retire_thread(node,thread):
    node.capability('threads');node.capability('retain')
    if not valid_id(thread):raise Invalid('invalid thread ID')
    with node.transaction():
        node.db.execute('DELETE FROM posts WHERE thread=?',(thread,))
        node.db.execute('DELETE FROM threads WHERE id=?',(thread,))
    return {'retired':thread,'remote_copies_deleted':False}
