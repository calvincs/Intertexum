"""Bounded reads, agent-selected retention and non-replayable receipt retirement."""
import time
from .crypto import canonical,decode,Invalid,Denied,valid_id

PAGE_BYTES=512*1024


def schema(node):
    node.db.executescript('''CREATE TABLE IF NOT EXISTS lifecycle(key TEXT PRIMARY KEY,value INTEGER);
      INSERT OR IGNORE INTO lifecycle VALUES('receipt_epoch',0);
      CREATE TABLE IF NOT EXISTS retention(id TEXT PRIMARY KEY,priority INTEGER,pinned INTEGER,expires INTEGER);
      CREATE TABLE IF NOT EXISTS rejected(id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS public_tombstones(id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS message_clock(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE);
    ''')
    node.db.execute('INSERT OR IGNORE INTO message_clock(id) SELECT id FROM messages ORDER BY rowid')


def receipt_guard(node,rid):
    # Run in the caller's transaction, without executescript (which commits).
    node.db.execute('CREATE TABLE IF NOT EXISTS lifecycle(key TEXT PRIMARY KEY,value INTEGER)')
    node.db.execute("INSERT OR IGNORE INTO lifecycle VALUES('receipt_epoch',0)")
    epoch=node.db.execute("SELECT value FROM lifecycle WHERE key='receipt_epoch'").fetchone()[0]
    key=rid[4:] if rid.startswith('mcp:') else rid
    if key.startswith('e') and ':' in key and key[1:key.index(':')].isdigit():
        if int(key[1:key.index(':')])!=epoch:raise Denied('retired or future receipt epoch; never replay retired operations')
    elif epoch:raise Denied(f'legacy keys retired; NEW operations must use e{epoch}:unique-key')


def message_page(node,*,after=0,limit=50):
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=100:raise Invalid('invalid inbox page')
    with node.lock:
        node.db.execute('INSERT OR IGNORE INTO message_clock(id) SELECT id FROM messages ORDER BY rowid')
        rows=node.db.execute('SELECT c.seq,m.wire FROM message_clock c JOIN messages m USING(id) WHERE c.seq>? ORDER BY c.seq LIMIT ?', (after,limit+1)).fetchall()
        items=[];size=0;cursor=after
        for row in rows[:limit]:
            entry={'message':decode(row['wire'].encode()),'cursor':row['seq'],'untrusted_data':True}
            from .message_work import reply_info
            offered=reply_info(node,entry['message']['id'])
            if offered:entry['reply_offer']=offered
            cost=len(canonical(entry))
            if size+cost>PAGE_BYTES:break
            items.append(entry);size+=cost;cursor=row['seq']
        return {'messages':items,'next':cursor if len(rows)>len(items) else None,'untrusted_data':True}


def retain(node,rid,*,priority=50,pinned=False,ttl=0,reject=False):
    node.capability('retain')
    if not valid_id(rid) or type(priority) is not int or not 0<=priority<=100 or type(pinned) is not bool or type(reject) is not bool or type(ttl) is not int or not 0<=ttl<=31536000:raise Invalid('invalid retention choice')
    with node.lock:
        with node.transaction():
            row=node._row(rid)
            if not row:raise Invalid('unknown record')
            if reject:
                if row['state']=='private' or decode(row['wire'].encode())['body']['origin']==node.id:raise Denied('retract own shared content before disposal; reject applies to imports')
                if node.db.execute('SELECT count(*) FROM rejected').fetchone()[0]>=10000 and not node.db.execute('SELECT 1 FROM rejected WHERE id=?',(rid,)).fetchone():raise Denied('rejection budget reached')
                node.db.execute('INSERT OR IGNORE INTO rejected VALUES(?)',(rid,))
                node.db.execute('DELETE FROM records WHERE id=?',(rid,));node.db.execute('DELETE FROM retention WHERE id=?',(rid,))
            else:node.db.execute('INSERT OR REPLACE INTO retention VALUES(?,?,?,?)',(rid,priority,int(pinned),int(time.time())+ttl if ttl else 0))
    return {'id':rid,'rejected':reject,'priority':priority,'pinned':pinned,'ttl':ttl}


def maintain(node,*,ack_before=0,evict_to=None):
    node.capability('retain')
    if type(ack_before) is not int or ack_before<0 or (evict_to is not None and (type(evict_to) is not int or not 0<=evict_to<=10000)):raise Invalid('invalid maintenance request')
    with node.lock:
        node.db.execute('INSERT OR IGNORE INTO message_clock(id) SELECT id FROM messages ORDER BY rowid')
        with node.transaction():
            removed=0
            # Only explicitly eligible, unpinned imported caches can be evicted.
            now=int(time.time())
            rows=node.db.execute('SELECT r.id,r.wire,t.priority,t.expires FROM records r JOIN retention t USING(id) WHERE t.pinned=0 ORDER BY t.priority,r.id').fetchall()
            count=node.db.execute('SELECT count(*) FROM records').fetchone()[0]
            for row in rows:
                if decode(row['wire'].encode())['body']['origin']==node.id:continue
                if (row['expires'] and row['expires']<=now) or (evict_to is not None and count>evict_to):
                    node.db.execute('DELETE FROM records WHERE id=?',(row['id'],));node.db.execute('DELETE FROM retention WHERE id=?',(row['id'],));removed+=1;count-=1
            acknowledged=node.db.execute('DELETE FROM messages WHERE id IN (SELECT id FROM message_clock WHERE seq<=?)',(ack_before,)).rowcount
            node.db.execute('DELETE FROM message_clock WHERE seq<=?',(ack_before,))
            epoch=node.db.execute("SELECT value FROM lifecycle WHERE key='receipt_epoch'").fetchone()[0]
    from .cache import sweep
    removed+=sweep(node)
    return {'records_evicted':removed,'messages_acknowledged':acknowledged,'receipt_epoch':epoch,'new_mutation_key_prefix':f'e{epoch}:'}


def retire_epoch(node,expected_epoch):
    node.capability('retain')
    if type(expected_epoch) is not int or expected_epoch<0:raise Invalid('expected_epoch must be nonnegative')
    with node.transaction():
        epoch=node.db.execute("SELECT value FROM lifecycle WHERE key='receipt_epoch'").fetchone()[0]
        if expected_epoch>epoch:raise Invalid('future receipt epoch')
        if expected_epoch==epoch:
            exists=node.db.execute("SELECT 1 FROM sqlite_master WHERE name='tool_receipts'").fetchone()
            if exists and node.db.execute('SELECT 1 FROM tool_receipts WHERE response IS NULL').fetchone():raise Denied('incomplete mutations require reconciliation before retirement')
            epoch+=1
            node.db.execute("UPDATE lifecycle SET value=? WHERE key='receipt_epoch'",(epoch,))
            if exists:node.db.execute('DELETE FROM tool_receipts')
    return {'receipt_epoch':epoch,'new_mutation_key_prefix':f'e{epoch}:','retired_through':epoch-1}


def capacity(node):
    from .node import MAX_EVENTS, MAX_UNKNOWN_RETRACTIONS_PER_ORIGIN, MAX_UNKNOWN_RETRACTIONS_PER_SUPPLIER
    with node.lock:
        tables={r[0] for r in node.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        sizes={name:node.db.execute('SELECT count(*) FROM '+name).fetchone()[0] for name in ('records','messages','threads','posts','outbox','received_ids','tool_receipts','rejected','retractions') if name in tables}
        epoch=node.db.execute("SELECT value FROM lifecycle WHERE key='receipt_epoch'").fetchone()[0]
        allocations = dict(node.db.execute('SELECT allocation,count(*) FROM retraction_sources GROUP BY allocation'))
    return {'database_bytes':(node.directory/'mesh.sqlite').stat().st_size,'wal_bytes':(node.directory/'mesh.sqlite-wal').stat().st_size if (node.directory/'mesh.sqlite-wal').exists() else 0,'counts':sizes,'limits':{'records':10000,'messages':10000,'threads':1000,'posts':10000,'outbox':10000,'received_ids':20000,'tool_receipts':10000,'rejected':10000},'receipt_epoch':epoch,'new_mutation_key_prefix':f'e{epoch}:',
        'retractions': {'counts': {name: allocations.get(name, 0) for name in ('local','stored','unknown')},
                        'limit_per_pool': MAX_EVENTS,
                        'unknown_per_origin': MAX_UNKNOWN_RETRACTIONS_PER_ORIGIN,
                        'unknown_per_supplier': MAX_UNKNOWN_RETRACTIONS_PER_SUPPLIER,
                        'recovery': 'Keep all tombstones. Inspect or block an abusive source; blocking does not erase withdrawals. Local and stored-target pools are reserved independently.'}}


def forget(node,rid):
    node.capability('retain')
    if not valid_id(rid):raise Invalid('invalid record ID')
    with node.transaction():
        row=node._row(rid)
        if not row:return {'forgotten':rid}
        obj=decode(row['wire'].encode())
        if obj['body']['origin']!=node.id:raise Denied('use retain reject=true for imported content')
        if row['state']!='private' and not node._withdrawn(rid,node.id):raise Denied('retract shared content before forgetting it')
        if obj['body']['audience']==['@public']:
            node.db.execute('INSERT OR IGNORE INTO public_tombstones VALUES(?)',(rid,))
        node.db.execute('DELETE FROM records WHERE id=?',(rid,))
        node.db.execute('DELETE FROM retention WHERE id=?',(rid,))
    return {'forgotten':rid,'remote_copies_deleted':False,'note':'dependent records become unavailable if a required ancestor is removed'}


def receipt(node,key,*,expected_fingerprint=None):
    node.capability('retain')
    if not isinstance(key,str) or not 1<=len(key)<=128:raise Invalid('invalid receipt key; include mcp: for MCP keys')
    with node.transaction():
        if not node.db.execute("SELECT 1 FROM sqlite_master WHERE name='tool_receipts'").fetchone():raise Invalid('unknown receipt')
        row=node.db.execute('SELECT fingerprint,response FROM tool_receipts WHERE id=?',(key,)).fetchone()
        if not row:raise Invalid('unknown or retired receipt')
        if expected_fingerprint is not None:
            if key in node.active_mutations:raise Denied('mutation is still running; cannot abandon it')
            if expected_fingerprint!=row['fingerprint']:raise Invalid('receipt fingerprint mismatch')
            if row['response'] is None:
                response={'id':key,'ok':False,'error':{'code':'delivery_unknown','detail':'Abandoned after local reconciliation. The operation may have completed; never replay with another key.','retryable':False,'next_action':'continue from inspected durable state'}}
                node.db.execute('UPDATE tool_receipts SET response=? WHERE id=? AND response IS NULL',(canonical(response).decode(),key))
                return {'key':key,'fingerprint':row['fingerprint'],'state':'settled','execution_repeated':False}
        return {'key':key,'fingerprint':row['fingerprint'],'state':'incomplete' if row['response'] is None else 'settled','execution_repeated':False}
