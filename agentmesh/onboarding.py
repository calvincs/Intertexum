"""Owner-provisioned private-network onboarding and bounded automatic admission."""
import hashlib
import hmac
import os
import secrets
import time
from .crypto import Invalid, Denied, canonical, decode

CAPABILITIES=('network','mdns','cache','reshare','reward_relays','write','publish','search','fetch','approve','send','receive','serve_memory','retain','manage_access','threads')


def policy(node):
    path=node.directory/'policy.json'
    value=decode(path.read_bytes()) if path.exists() else {}
    if not isinstance(value,dict) or set(value)-set(CAPABILITIES) or any(type(v) is not bool for v in value.values()):
        raise Invalid('policy must map known capabilities to booleans')
    from .source_policy import config, PROVIDER_DISABLED
    caps = {k:value.get(k,True) for k in CAPABILITIES}
    if config(node)['mode'] == 'provider':
        caps.update({k:False for k in PROVIDER_DISABLED})
    return caps


def require(node, capability):
    if not policy(node)[capability]:raise Denied('capability_disabled:'+capability)
    if capability=='network' and (node.directory/'connectivity-suspended').exists():raise Denied('network suspended; owner must resume explicitly')


def profile(value):
    from .connectivity import configuration
    if not isinstance(value,dict) or set(value)!={'version','connectivity','admission'} or value['version']!=1:
        raise Invalid('unsupported network profile')
    config=configuration(value['connectivity'])
    admission=value['admission']
    if admission=={'mode':'public'}:
        return {'version':1,'connectivity':config,'admission':admission}
    if not isinstance(admission,dict) or set(admission)!={'key','permissions'}:
        raise Invalid('admission key and permissions required')
    try:
        if len(admission['key'])!=64 or len(bytes.fromhex(admission['key']))!=32:raise ValueError()
    except (TypeError,ValueError):raise Invalid('admission key must be 32 random bytes in hex')
    permissions=admission['permissions']
    if not isinstance(permissions,list) or not permissions or any(x not in ('read','publish','message') for x in permissions):
        raise Invalid('invalid profile permission ceiling')
    return {'version':1,'connectivity':config,'admission':admission}


def private_write(path, value):
    temp=path.with_name(path.name+'.tmp-'+secrets.token_hex(8))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as f:f.write(canonical(value)+b'\n')
        temp.replace(path)
    finally:temp.unlink(missing_ok=True)


def load(node):
    path=node.directory/'network-profile.json'
    return profile(decode(path.read_bytes())) if path.exists() else None


def setup(directory, value):
    from .node import Node
    value=profile(value)  # Validate before creating keys or changing files.
    node=Node(directory) if (directory/'config.json').exists() else Node.create(directory)
    try:
        old=load(node)
        if old is not None and canonical(old)!=canonical(value):
            raise Denied('profile_changed: refuse implicit network/key migration')
        if (directory/'connectivity-suspended').exists():
            raise Denied('connectivity_suspended: explicitly resume before onboarding again')
        require(node,'network')
        existing=directory/'connectivity.json'
        if existing.exists() and canonical(decode(existing.read_bytes()))!=canonical(value['connectivity']):
            raise Denied('connectivity_changed: reconcile existing configuration explicitly')
        private_write(directory/'network-profile.json',value)
        private_write(existing,value['connectivity'])
        return {'id':node.id,'configured':True,'resumed':old is not None,
                'next_action':'run intertexum --data '+str(directory)+' mcp',
                'capabilities':policy(node)}
    finally:node.close()


def membership(node, body):
    value=load(node)
    if not value or value['admission'].get('mode')=='public' or value['connectivity']['network']!=body['network']:return None
    return hmac.new(bytes.fromhex(value['admission']['key']),
        b'agentmesh.membership.v1\0'+canonical(body),hashlib.sha256).hexdigest()


def admit(node, body):
    """Call only after validating the announcement's identity signature and TTL."""
    value=load(node)
    if not value:return False
    expected=membership(node,{k:v for k,v in body.items() if k!='membership'})
    proof=body.get('membership')
    if not expected or not isinstance(proof,str) or not hmac.compare_digest(expected,proof):return False
    card=body['card'];peer=card['id']
    if peer==node.id or node.defense.blocked(peer=peer):return False
    with node.transaction():
        row=node.db.execute('SELECT blocked FROM peers WHERE id=?',(peer,)).fetchone()
        managed=node.db.execute('SELECT expires FROM admissions WHERE peer=?',(peer,)).fetchone()
        # Explicit blocks and manually set permissions override automatic enrollment.
        if row and (row[0] or not managed):return False
        if not row and node.db.execute('SELECT count(*) FROM peers').fetchone()[0]>=1000:
            raise Denied('automatic peer admission capacity reached')
        node.db.execute('INSERT INTO peers VALUES(?,?,?,0) ON CONFLICT(id) DO UPDATE SET permissions=excluded.permissions',
            (peer,canonical(card).decode(),canonical(value['admission']['permissions']).decode()))
        node.db.execute('INSERT INTO admissions VALUES(?,?) ON CONFLICT(peer) DO UPDATE SET expires=max(expires,excluded.expires)',
            (peer,body['expires']))
    return True


def status(node):
    from .source_policy import config as source_config
    from .embedding import profile as embedding_profile
    caps=policy(node)
    state=node.connectivity.state if node.connectivity else {}
    if not state:
        path=node.directory/'connectivity-status.json'
        if path.exists():state=decode(path.read_bytes())
    fresh=bool(state.get('updated_at',0)>time.time()-15)
    peers=[]
    for p in node.peers():
        try:node.peer(p['card']['id'])
        except Denied:continue
        if not node.defense.blocked(peer=p['card']['id']):peers.append(p['card']['id'])
    connected=fresh and (any(x=='connected' for x in state.get('seeds',{}).values()) or state.get('mdns',{}).get('status')=='running')
    suspended=(node.directory/'connectivity-suspended').exists() or not caps['network']
    readiness='disabled' if suspended else ('ready' if connected and peers else ('waiting_for_peers' if connected else 'not_connected'))
    from .lifecycle import capacity
    from .crypto import certificate
    from datetime import datetime,timezone
    expiry=certificate(node.identity.pem).not_valid_after_utc
    storage=capacity(node)
    return {'delivery_worker_running':bool(getattr(node,'delivery_worker',None) and node.delivery_worker.thread.is_alive()),'delivery_worker_error':getattr(node,'delivery_error',None),'certificate_expires':expiry.isoformat(),'certificate_renewal_due':(expiry-datetime.now(timezone.utc)).days<30,'storage':storage,'new_mutation_key_prefix':storage['new_mutation_key_prefix'],'id':node.id,'readiness':readiness,'capabilities':caps,'source_policy':source_config(node),'peers':peers,
            'connectivity_fresh':fresh,'connectivity':state,'model':node.model,
            'transport_paths':__import__('agentmesh.network',fromlist=['paths']).paths(node),
            'text_token_limit':128 if node.model==embedding_profile()['id'] else None,
            'remote_operations_verified':False,
            'next_action':{'ready':'use search/send; remote permission checks still apply',
                'waiting_for_peers':'start another node with the same authorized profile',
                'not_connected':'local memory is available under owner policy; for discovery start the runtime and check the profile/seeds. Known peers may still be reachable; inspect peer_status',
                'disabled':'network is disabled; use permitted local memory tools. Network resumption requires owner authorization'}[readiness]}
