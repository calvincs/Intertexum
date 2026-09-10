"""Open discovery grants public access only; private rights are receiver-controlled."""
import time
from .crypto import canonical,decode,Invalid,Denied,valid_id

PUBLIC='@public'


def schema(node):
    node.db.executescript('''CREATE TABLE IF NOT EXISTS lan_peers(peer TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS grants(peer TEXT PRIMARY KEY,permissions TEXT,expires INTEGER);
      CREATE TABLE IF NOT EXISTS public_peers(peer TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS referrals(peer TEXT PRIMARY KEY,source TEXT);
      CREATE TABLE IF NOT EXISTS peer_announcements(peer TEXT PRIMARY KEY,issued INTEGER,expires INTEGER,wire TEXT);
    ''')


def is_open(node):
    from .onboarding import load
    value=load(node)
    return bool(value and value['admission'].get('mode')=='public')


def effective(node,peer,base):
    row=node.db.execute('SELECT permissions,expires FROM grants WHERE peer=?',(peer,)).fetchone()
    return set(base) | (set(decode(row['permissions'].encode())) if row and row['expires']>time.time() else set())


def authorize(node,peer,*,permissions=(),ttl=86400):
    node.capability('manage_access')
    if not valid_id(peer) or not isinstance(permissions,(list,tuple)) or any(p not in ('read','publish','message') for p in permissions) or type(ttl) is not int or not 60<=ttl<=604800:raise Invalid('invalid private grant; maximum lifetime is 7 days')
    with node.transaction():
        node.peer(peer)
        if permissions:node.db.execute('INSERT OR REPLACE INTO grants VALUES(?,?,?)',(peer,canonical(sorted(set(permissions))).decode(),int(time.time())+ttl))
        else:node.db.execute('DELETE FROM grants WHERE peer=?',(peer,))
    return {'peer':peer,'permissions':list(permissions),'expires_in':ttl if permissions else 0}


def learn(node,obj,network,*,source=None,lan=False):
    from .bootstrap import check_announcement
    from .onboarding import admit
    import ipaddress
    from .onboarding import load
    value=load(node)
    public_addresses=bool(not lan and value and is_open(node) and value['connectivity']['seeds'] and all(ipaddress.ip_address(c['host']).is_global for c in value['connectivity']['seeds']))
    body=check_announcement(obj,network,public=public_addresses);peer=body['card']['id']
    if peer==node.id or node.defense.blocked(peer=peer):return False
    if lan:
        from .discovery import local_address
        node.capability('network');node.capability('mdns')
        if not local_address(body['card']['host']) or node.defense.blocked(source=body['card']['host'],peer=peer):return False
    with node.transaction():
        if lan and not node.db.execute('SELECT 1 FROM lan_peers WHERE peer=?',(peer,)).fetchone():
            if node.db.execute('SELECT count(*) FROM lan_peers').fetchone()[0]>=128:return False
        old=node.db.execute('SELECT issued,wire FROM peer_announcements WHERE peer=?',(peer,)).fetchone()
        if old and (body['issued']<old['issued'] or (body['issued']==old['issued'] and canonical(obj).decode()!=old['wire'])):return False
        if is_open(node):
            existing=node.db.execute('SELECT blocked FROM peers WHERE id=?',(peer,)).fetchone()
            if existing and existing['blocked']:return False
            if not existing:
                if source is not None:
                    node.peer(source)
                    if node.db.execute('SELECT count(*) FROM referrals').fetchone()[0]>=128 or node.db.execute('SELECT count(*) FROM referrals WHERE source=?',(source,)).fetchone()[0]>=8:return False
                    node.db.execute('INSERT INTO referrals VALUES(?,?)',(peer,source))
                if node.db.execute('SELECT count(*) FROM peers').fetchone()[0]>=1000:raise Denied('peer budget reached')
                node.db.execute('INSERT INTO peers VALUES(?,?,?,0)',(peer,canonical(body['card']).decode(),'["public"]'))
                node.db.execute('INSERT INTO public_peers VALUES(?)',(peer,))
        else:admit(node,body)
        try:known=node.peer(peer)
        except Denied:return False
        # check_announcement already verifies the self-signature and certificate key -> peer ID.
        # A fresh signed endpoint may renew its certificate, but cannot change its identity key.
        if lan:node.db.execute('INSERT OR IGNORE INTO lan_peers VALUES(?)',(peer,))
        node.db.execute('UPDATE peers SET card=? WHERE id=?',(canonical(body['card']).decode(),peer))
        node.db.execute('INSERT OR REPLACE INTO peer_announcements VALUES(?,?,?,?)',(peer,body['issued'],body['expires'],canonical(obj).decode()))
    return True


def peer_view(node,requester,*,after='',limit=20):
    node.require(requester,'read')
    if not isinstance(after,str) or (after and not valid_id(after)) or type(limit) is not int or not 1<=limit<=20:raise Invalid('invalid peer-view page')
    from .onboarding import load
    from .bootstrap import announcement
    value=load(node)
    with node.lock:
        if value and node.connectivity:
            host=node.connectivity.config.get('advertise_host',node.connectivity.state.get('observed_ip'))
            if host:
                obj=announcement(node,host,node.connectivity.port,value['connectivity']['network'])
                body=obj['body']
                node.db.execute('INSERT OR REPLACE INTO peer_announcements VALUES(?,?,?,?)',(node.id,body['issued'],body['expires'],canonical(obj).decode()))
        rows=node.db.execute('SELECT peer,wire FROM peer_announcements WHERE peer>? AND expires>? ORDER BY peer LIMIT ?',(after,int(time.time()),limit+1)).fetchall()
        entries=[decode(r['wire'].encode()) for r in rows[:limit] if not node.defense.blocked(peer=r['peer'])]
    return {'announcements':entries,'next':rows[limit-1]['peer'] if len(rows)>limit else None,'network_complete':False}


def federated_search(node,query,*,peers=None,k=10):
    from concurrent.futures import ThreadPoolExecutor,as_completed
    from .network import Client
    from .embedding import encode_for
    node.capability('search');node.capability('network')
    if type(k) is not int or not 1<=k<=20:raise Invalid('k must be 1..20')
    from .cache import select_peers
    targets=peers if peers is not None else select_peers(node)
    if not isinstance(targets,list) or len(targets)>8 or any(not valid_id(p) for p in targets) or len(set(targets))!=len(targets):raise Invalid('select at most 8 distinct peer IDs')
    vec=encode_for(node,query,query=True)
    hits={};failed={};responded=[]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures={pool.submit(Client(node,p).search,query_text=query,query_vector=vec,k=k):p for p in targets}
        for f in as_completed(futures):
            peer=futures[f]
            try:result=f.result()
            except Exception as exc:failed[peer]=type(exc).__name__;continue
            responded.append(peer)
            for rank,hit in enumerate(result['results'],1):
                rid=hit['record']['id']
                if rid not in hits:hits[rid]={'record':hit['record'],'score':0,'holders':[],'untrusted_data':True}
                hits[rid]['score']+=1/(60+rank);hits[rid]['holders'].append(peer)
    selected=[];size=0
    for hit in sorted(hits.values(),key=lambda h:(-h['score'],h['record']['id']))[:k]:
        cost=len(canonical(hit))
        if size+cost>512*1024:break
        selected.append(hit);size+=cost
    return {'results':selected,'byte_limited':len(selected)<min(k,len(hits)),
        'coverage':{'requested':targets,'responded':responded,'failed':failed,'network_complete':False}}
