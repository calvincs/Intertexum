"""Expiring public transit copies and local, observation-based provider preference.

Transit copies remain untrusted/pending. They never gain private audiences or
local approval, and rewards never change permissions or abuse budgets.
"""
import random
import time
from .crypto import canonical, Invalid, Denied

DEFAULTS={'ttl':3600,'max_records':256,'max_bytes':16*1024*1024}


def schema(node):
    node.db.executescript('''
      CREATE TABLE IF NOT EXISTS transit_cache(id TEXT PRIMARY KEY,expires INTEGER,used INTEGER,bytes INTEGER);
      CREATE TABLE IF NOT EXISTS cache_settings(key TEXT PRIMARY KEY,value INTEGER);
      CREATE TABLE IF NOT EXISTS relay_observations(id TEXT PRIMARY KEY,peer TEXT,expires INTEGER);
    ''')


def settings(node):
    with node.lock:
        return {**DEFAULTS,**dict(node.db.execute('SELECT key,value FROM cache_settings'))}


def configure(node,**values):
    node.capability('cache');node.capability('retain')
    bounds={'ttl':(60,86400),'max_records':(1,2048),'max_bytes':(65536,256*1024*1024)}
    if not values or set(values)-set(bounds):raise Invalid('invalid cache settings')
    for key,value in values.items():
        if type(value) is not int or not bounds[key][0]<=value<=bounds[key][1]:raise Invalid('cache setting outside allowed range: '+key)
    with node.transaction():
        for key,value in values.items():node.db.execute('INSERT OR REPLACE INTO cache_settings VALUES(?,?)',(key,value))
        if 'ttl' in values:node.db.execute('UPDATE transit_cache SET expires=min(expires,?)',(int(time.time())+values['ttl'],))
        sweep(node)
    return status(node)


def discard(node,rid):
    # An explicit local retention decision or approval takes ownership of storage.
    removed=node.db.execute("DELETE FROM records WHERE id=? AND state='pending' AND NOT EXISTS (SELECT 1 FROM retention WHERE id=?)",(rid,rid)).rowcount
    node.db.execute('DELETE FROM transit_cache WHERE id=?',(rid,))
    return removed


def sweep(node):
    with node.transaction():
        now=int(time.time());opts=settings(node);removed=0
        node.db.execute('DELETE FROM relay_observations WHERE expires<=?',(now,))
        rows=node.db.execute('SELECT c.id,c.expires,c.used,c.bytes,r.state FROM transit_cache c LEFT JOIN records r USING(id) ORDER BY c.used,c.id').fetchall()
        for row in rows:
            if row['state'] is None or row['state']!='pending' or row['expires']<=now:
                removed+=discard(node,row['id'])
        rows=node.db.execute('SELECT id,bytes FROM transit_cache ORDER BY used,id').fetchall()
        count=len(rows);size=sum(r['bytes'] for r in rows)
        for row in rows:
            if count<=opts['max_records'] and size<=opts['max_bytes']:break
            removed+=discard(node,row['id']);count-=1;size-=row['bytes']
        return removed


def eligible(node,rid,*,reshare=True):
    """Eligibility is checked at read time, even while the runtime is stopped."""
    from .onboarding import policy
    caps=policy(node)
    if not caps['cache'] or (reshare and not caps['reshare']):return False
    row=node.db.execute('SELECT expires FROM transit_cache WHERE id=?',(rid,)).fetchone()
    return bool(row and row[0]>time.time())


def remember(node,obj,*,source=None):
    from .onboarding import policy
    caps=policy(node)
    if not all(caps[k] for k in ('cache','fetch','retain')):return False
    with node.transaction():
        body=node._verified_record(obj)
        from .source_policy import require, require_record
        require(node, 'authors', body['origin'])
        if source is None:require_record(node, obj)
        else:require(node, 'sources', source)
        rid=obj['id']
        if body['origin']==node.id or body['audience']!=['@public']:return False
        if node._withdrawn(rid,body['origin']) or node.db.execute('SELECT 1 FROM rejected WHERE id=?',(rid,)).fetchone():return False
        sweep(node)
        previous=node._row(rid)
        managed=node.db.execute('SELECT 1 FROM transit_cache WHERE id=?',(rid,)).fetchone()
        if previous and (previous['state']!='pending' or not managed):return False
        if node.db.execute('SELECT 1 FROM retention WHERE id=?',(rid,)).fetchone():return False
        wire=canonical(obj);opts=settings(node)
        if len(wire)>opts['max_bytes']:return False
        if not previous and node.db.execute('SELECT count(*) FROM records').fetchone()[0]>=10000:return False
        node._save(obj,'pending')
        if source is not None:
            from .source_policy import remember_source
            remember_source(node, obj, source)
        now=int(time.time())
        node.db.execute('INSERT OR REPLACE INTO transit_cache VALUES(?,?,?,?)',(rid,now+opts['ttl'],time.time_ns(),len(wire)))
        sweep(node)
        return bool(node.db.execute('SELECT 1 FROM transit_cache WHERE id=?',(rid,)).fetchone())


def hit(node,rid):
    from .onboarding import policy
    if not policy(node)['cache']:return False
    with node.lock:
        row=node.db.execute('SELECT expires FROM transit_cache WHERE id=?',(rid,)).fetchone()
        if not row or row[0]<=time.time():return False
        obj=node._active(rid,node.id,transit=True)
        if not obj or obj['body']['audience']!=['@public']:return False
        node.db.execute('UPDATE transit_cache SET used=? WHERE id=?',(time.time_ns(),rid))
        return True


def credit(node,peer,obj):
    """One local credit per distinct requested third-party record per day.

Called only after a successful fetch and verification, never for advertisements,
search hits, cache hits or a peer's self-reported service counts.
"""
    from .onboarding import policy
    if not policy(node)['reward_relays']:return
    with node.transaction():
        body=node._verified_record(obj)
        if body['origin'] in (peer,node.id) or body['audience']!=['@public']:return
        if node._withdrawn(obj['id'],body['origin']):return
        node.peer(peer)
        if node.defense.blocked(peer=peer):return
        now=int(time.time());node.db.execute('DELETE FROM relay_observations WHERE expires<=?',(now,))
        if node.db.execute('SELECT count(*) FROM relay_observations').fetchone()[0]>=2048:return
        node.db.execute('INSERT OR IGNORE INTO relay_observations VALUES(?,?,?)',(obj['id'],peer,now+86400))


def select_peers(node,limit=8):
    from .onboarding import policy
    with node.lock:
        candidates=[]
        for p in node.peers():
            peer=p['card']['id']
            try:node.peer(peer)
            except Denied:continue
            from .source_policy import allowed
            if not node.defense.blocked(peer=peer) and allowed(node,'sources',peer):candidates.append(peer)
        scores=dict(node.db.execute('SELECT peer,count(*) FROM relay_observations WHERE expires>? GROUP BY peer',(int(time.time()),)))
    rng=random.SystemRandom();rng.shuffle(candidates)
    preferred=[]
    if policy(node)['reward_relays']:
        preferred=sorted((p for p in candidates if scores.get(p,0)),key=lambda p:-min(scores[p],16))[:min(3,limit)]
    remaining=[p for p in candidates if p not in preferred]
    return preferred+remaining[:max(0,limit-len(preferred))]


def status(node):
    from .onboarding import policy
    with node.lock:
        count,size=node.db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM transit_cache').fetchone()
        active=node.db.execute('SELECT count(*) FROM transit_cache WHERE expires>?',(int(time.time()),)).fetchone()[0]
        scores=[{'peer':r[0],'distinct_records':r[1],'selection_score':min(r[1],16)} for r in node.db.execute('SELECT peer,count(*) FROM relay_observations WHERE expires>? GROUP BY peer ORDER BY count(*) DESC,peer LIMIT 20',(int(time.time()),))]
    caps=policy(node)
    return {'settings':settings(node),'stored_records':count,'active_records':active,'wire_bytes':size,
            'enabled':caps['cache'],'reshare':caps['reshare'] and caps['serve_memory'] and caps['cache'],
            'reward_relays':caps['reward_relays'],'providers':scores,'reward_scope':'local peer-selection preference only; no permissions, quota exemptions or currency'}
