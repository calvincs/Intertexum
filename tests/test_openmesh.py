import sqlite3
import time
import pytest
from agentmesh.crypto import Denied,Invalid,canonical,sign
from agentmesh.node import Node
from agentmesh.agent import call,DEFINITIONS
from agentmesh import conversations as c
from agentmesh.lifecycle import retain,maintain,retire_epoch
from agentmesh.openmesh import authorize,learn
from agentmesh.onboarding import profile,private_write,admit
from agentmesh.bootstrap import announcement,check_announcement
from agentmesh.network import Server,Client
from conftest import publish


def tool(n,rid,name,**args):return call(n,{'id':rid,'tool':name,'arguments':args})


def test_atomic_admission_and_manual_conversion(mesh):
    a,b,seed=mesh
    p=profile({'version':1,'connectivity':{'seeds':[seed.card(port=7443)]},'admission':{'key':'ab'*32,'permissions':['read']}})
    for n in (a,b):private_write(n.directory/'network-profile.json',p)
    a.db.execute('DELETE FROM peers WHERE id=?',(b.id,))
    body=check_announcement(announcement(b,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1')
    a.db.execute("CREATE TRIGGER fail BEFORE INSERT ON admissions BEGIN SELECT RAISE(ABORT,'injected'); END")
    with pytest.raises(sqlite3.IntegrityError):admit(a,body)
    assert not a.db.execute('SELECT 1 FROM peers WHERE id=?',(b.id,)).fetchone()
    a.db.execute('DROP TRIGGER fail');assert admit(a,body)
    a.db.execute("CREATE TRIGGER fail BEFORE UPDATE ON peers BEGIN SELECT RAISE(ABORT,'injected'); END")
    with pytest.raises(sqlite3.IntegrityError):a.trust(b.card(port=7443),['message'])
    assert a.db.execute('SELECT 1 FROM admissions WHERE peer=?',(b.id,)).fetchone()
    assert a.peer(b.id)['permissions']==['read']


def test_public_discovery_private_grants_and_no_implicit_migration(mesh):
    a,b,seed=mesh
    p=profile({'version':1,'connectivity':{'seeds':[seed.card(port=7443)]},'admission':{'mode':'public'}})
    for n in (a,b):private_write(n.directory/'network-profile.json',p)
    a.db.execute('DELETE FROM peers WHERE id=?',(b.id,));b.db.execute('DELETE FROM peers WHERE id=?',(a.id,))
    assert learn(a,announcement(b,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1')
    assert learn(b,announcement(a,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1')
    assert a.peer(b.id)['permissions']==['public']
    pub=publish(a,'open knowledge',audience=['@public']);old=publish(a,'legacy');private=publish(a,'secret',audience=[b.id])
    assert a.get(pub,b.id)['id']==pub
    for rid in (old,private):
        with pytest.raises(Denied):a.get(rid,b.id)
    authorize(a,b.id,permissions=['read'],ttl=60)
    assert a.get(private,b.id)['id']==private
    authorize(a,b.id,permissions=[])
    with pytest.raises(Denied):a.get(private,b.id)
    authorize(a,b.id,permissions=['read'],ttl=60);a.db.execute('UPDATE grants SET expires=0')
    with pytest.raises(Denied):a.get(private,b.id)
    cache=b.ingest(a.get(pub,b.id));b.approve(cache)
    assert b.get(cache,seed.id)['id']==cache
    child=a.write_private('derive',[1,0,0],parents=[old])
    with pytest.raises(Denied):a.publish(child,audience=['@public'])


@pytest.mark.parametrize('view', ['summary', 'full'])
def test_inbox_pages_ack_replay_and_receipt_epochs(mesh, view):
    a,b,_=mesh
    for i in range(70):b.receive_message(a.make_message(b.id,'x'*32768,expires=int(time.time())+60),a.id)
    replayed=b.inbox()[0]['message']
    seen=[];after=0
    while True:
        result=tool(b,'read','inbox',after=after,limit=100,view=view)
        assert result['ok'];page=result['result'];assert len(canonical(result))<600000
        seen+=page['messages']
        if page['next'] is None:break
        after=page['next']
    assert len(seen)==70 and len({m['id'] if view=='summary' else m['message']['id'] for m in seen})==70
    maintain(b,ack_before=2**63-1)
    b.receive_message(replayed,a.id);assert b.inbox()==[]
    assert tool(a,'first','authorize',peer=b.id,permissions=[])['ok']
    assert tool(a,'retire','retire_receipts',expected_epoch=0)['result']['receipt_epoch']==1
    assert tool(a,'retire','retire_receipts',expected_epoch=0)['result']['receipt_epoch']==1
    assert not tool(a,'first','authorize',peer=b.id,permissions=[])['ok']
    assert tool(a,'e1:next','authorize',peer=b.id,permissions=[])['ok']
    assert DEFINITIONS['search'][1]['k']['maximum']==20


def test_retention_reject_pin_expiry(mesh):
    a,b,_=mesh
    rid=publish(a);b.ingest(a.get(rid,b.id));b.approve(rid)
    retain(b,rid,priority=0,pinned=True,ttl=1);b.db.execute('UPDATE retention SET expires=1')
    assert maintain(b,evict_to=0)['records_evicted']==0
    retain(b,rid,priority=0,pinned=False)
    assert maintain(b,evict_to=0)['records_evicted']==1
    b.ingest(a.get(rid,b.id));retain(b,rid,reject=True)
    with pytest.raises(Denied):b.ingest(a.get(rid,b.id))


def test_threads_private_acl_paging_and_retirement(mesh):
    a,b,d=mesh
    public=c.create(a,'public conversation',['@public'])['id']
    private=c.create(a,'secret conversation',[b.id])['id']
    assert len(c.page(a,d.id)['items'])==1
    with pytest.raises(Denied):c.page(a,d.id,thread=private)
    obj=c._body(b,'reply','hello',thread=private,parent=private)
    assert c.accept(a,obj,b.id)['id']==obj['id'];c.accept(a,obj,b.id)
    p=c.page(a,b.id,thread=private);assert len(p['items'])==1
    stamp=p['items'][0]['received_ms']
    assert c.page(a,b.id,thread=private,since_ms=stamp+1)['items']==[]
    forged=c._body(d,'reply','intruder',thread=private,parent=private)
    with pytest.raises(Denied):c.accept(a,forged,d.id)
    other=c._body(b,'reply','wrong parent',thread=public,parent=obj['id'])
    with pytest.raises(Invalid):c.accept(a,other,b.id)
    for i in range(20):c.accept(a,c._body(b,'reply','x'*32768,thread=public,parent=public),b.id)
    p=c.page(a,b.id,thread=public,limit=100);assert p['next'] and len(canonical(p))<600000
    c.retire_thread(a,private)
    with pytest.raises(Denied):c.accept(a,obj,b.id)
    assert c.create(a,'new',[b.id])['id']!=private


def test_durable_outbox_offline_then_tls_delivery_and_threads(mesh):
    a,b,_=mesh
    queued=c.queue_message(a,b.id,'offline message',ttl=60)
    c.deliver(a);assert c.deliveries(a)['items'][0]['state']=='queued'
    server=Server(b);thread=server.start()
    a.trust(b.card(port=server.server_address[1]),['read','publish','message'])
    try:
        a.db.execute('UPDATE outbox SET next=0');c.deliver(a)
        assert c.deliveries(a)['items'][0]['state']=='delivered'
        assert len(b.inbox())==1
        a.db.execute("UPDATE outbox SET state='queued',next=0");c.deliver(a)
        assert len(b.inbox())==1
        root=c.create(b,'collaborate',[a.id])['id']
        reply=c.reply(a,b.id,root,'signed answer');c.deliver(a)
        page=c.read(a,b.id,thread=root)
        assert page['items'][0]['object']['id']==reply['id']
        c.deliveries(a,ack=queued['id']);assert all(x['id']!=queued['id'] for x in c.deliveries(a)['items'])
    finally:server.shutdown();thread.join();server.server_close()


def test_queued_thread_replies_survive_same_key_renewal_and_keep_live_acl(mesh):
    from agentmesh.operations import renew
    a,b,d=mesh
    root=c.create(a,'private renewal conversation',[b.id])['id']
    acknowledged=c._body(b,'reply','acknowledgement was lost',thread=root,parent=root)
    waiting=c._body(b,'reply','first delivery after renewal',thread=root,parent=acknowledged['id'])
    assert c.accept(a,acknowledged,b.id)['id']==acknowledged['id']
    renew(b.directory)
    renewed=Node(b.directory)
    try:
        assert renewed.id==b.id and renewed.identity.pem!=b.identity.pem
        a.trust(renewed.card(port=7443),['read','message'])
        assert c.accept(a,acknowledged,b.id)['id']==acknowledged['id']
        assert c.accept(a,waiting,b.id)['id']==waiting['id']
        assert len(c.page(a,a.id,thread=root)['items'])==2
        forged=c._body(d,'reply','different signing key',thread=root,parent=root)
        with pytest.raises(Invalid,match='sender mismatch'):c.accept(a,forged,b.id)
        a.trust(renewed.card(port=7443),['read'])
        with pytest.raises(Denied):c.accept(a,acknowledged,b.id)
        a.block(b.id)
        with pytest.raises(Denied):c.accept(a,waiting,b.id)
    finally:renewed.close()


def test_delivery_worker_isolates_slow_peers_and_preserves_fifo(mesh,monkeypatch):
    import threading
    a,b,d=mesh
    release=threading.Event();slow_started=threading.Event();healthy_done=threading.Event()
    guard=threading.Lock();calls=[];inflight=set();peak=0
    slow=[c.queue_message(a,b.id,'slow '+str(i))['id'] for i in range(2)]
    healthy=[c.queue_message(a,d.id,'healthy '+str(i))['id'] for i in range(5)]
    monkeypatch.setattr(c,'DELIVERY_CONCURRENCY',2)
    def request(client,op,**args):
        nonlocal peak
        mid=args['message']['id']
        with guard:
            assert client.peer_id not in inflight
            inflight.add(client.peer_id);peak=max(peak,len(inflight));calls.append(mid)
        try:
            if client.peer_id==b.id:
                slow_started.set();assert release.wait(5)
            if mid==healthy[-1]:healthy_done.set()
            return {'id':mid}
        finally:
            with guard:inflight.remove(client.peer_id)
    monkeypatch.setattr(Client,'request',request)
    worker=c.DeliveryWorker(a);worker.start()
    try:
        assert slow_started.wait(2)
        assert healthy_done.wait(3), 'healthy peer was blocked behind an unreachable peer'
        assert [mid for mid in calls if mid in healthy]==healthy
        assert [mid for mid in calls if mid in slow]==slow[:1]
        assert peak==2
    finally:release.set();worker.close()
    assert not worker.thread.is_alive() and not a._delivery_peers


def test_delivery_backoff_keeps_causal_successor_behind_parent(mesh,monkeypatch):
    a,b,d=mesh
    root=c.create(b,'causal thread',['@public'])['id']
    parent=c.reply(a,b.id,root,'parent')['id']
    child=c.reply(a,b.id,root,'child',parent=parent)['id']
    healthy=c.queue_message(a,d.id,'another peer')['id']
    attempted=[]
    def request(client,op,**args):
        obj=args['post'] if op=='thread_post' else args['message']
        attempted.append(obj['id'])
        if obj['id']==parent:raise OSError('offline')
        return {'id':obj['id']}
    monkeypatch.setattr(Client,'request',request)
    c.deliver(a);c.deliver(a);c.deliver(a)
    assert attempted==[parent,healthy] and child not in attempted
    a.db.execute('UPDATE outbox SET next=0 WHERE id=?',(parent,))
    monkeypatch.setattr(Client,'request',lambda client,op,**args:{'id':args['post']['id']})
    c.deliver(a);c.deliver(a)
    assert {x['state'] for x in c.deliveries(a)['items']}=={'delivered'}


def test_delivery_worker_drains_past_tls_burst_without_receiver_ban(mesh):
    a,b,_=mesh
    server=Server(b);thread=server.start()
    a.trust(b.card(port=server.server_address[1]),['read','publish','message'])
    queued=[c.queue_message(a,b.id,'paced message '+str(i),ttl=60)['id'] for i in range(30)]
    worker=c.DeliveryWorker(a);worker.start()
    try:
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            items=c.deliveries(a)['items']
            if len(items)==30 and all(x['state']=='delivered' for x in items):break
            time.sleep(.1)
        else:raise AssertionError(items)
        assert all(x['attempts']==1 for x in items)
        assert [m['message']['id'] for m in b.inbox()]==queued
        assert not b.defense.blocked(source='127.0.0.1',peer=a.id)
    finally:worker.close();server.shutdown();thread.join();server.server_close()


def test_offline_backup_restore_renewal_and_lock(mesh,tmp_path):
    from agentmesh.operations import backup,restore,renew
    from agentmesh.service import runtime_lock
    a,b,_=mesh
    record=publish(a)
    with runtime_lock(a.directory):
        with pytest.raises(Denied):backup(a.directory,tmp_path/'blocked')
        with pytest.raises(Denied):renew(a.directory)
    backup(a.directory,tmp_path/'backup')
    restore(tmp_path/'backup',tmp_path/'restored')
    restored=Node(tmp_path/'restored')
    try:
        assert restored.id==a.id
        assert restored.get(record,b.id)['id']==record
        assert (restored.directory/'connectivity-suspended').exists()
    finally:restored.close()
    old=a.identity.pem;renew(a.directory)
    renewed=Node(a.directory)
    try:assert renewed.id==a.id and renewed.identity.pem!=old
    finally:renewed.close()
    (tmp_path/'backup'/'identity.key').write_text('tampered')
    with pytest.raises(Invalid):restore(tmp_path/'backup',tmp_path/'bad')
    assert not (tmp_path/'bad').exists()


def test_document_chunking_atomic_and_private(tmp_path):
    from agentmesh.embedding import write_document,default_encoder
    node=Node.create(tmp_path/'doc')
    try:
        content='A useful observation about decentralized agent communication. '*100
        result=write_document(node,content)
        assert len(result['chunks'])>1
        for chunk in result['chunks']:
            obj=node.inspect(chunk['id']);assert obj['state']=='private'
            passage=obj['record']['body']['text']
            assert passage==content[chunk['start']:chunk['end']]
            assert len(default_encoder().tokenizer.encode(passage).ids)<=128
    finally:node.close()


def test_forgetting_public_body_preserves_public_withdrawal(mesh):
    from agentmesh.lifecycle import forget
    a,b,_=mesh
    a.trust(b.card(port=7443),['public'])
    rid=publish(a,audience=['@public'])
    with pytest.raises(Denied):forget(a,rid)
    a.retract(rid);forget(a,rid)
    assert any(e['body']['target']==rid for e in a.retractions(b.id)['events'])


def test_referral_budget_and_renewed_certificate(mesh):
    from agentmesh.operations import renew
    a,b,seed=mesh
    p=profile({'version':1,'connectivity':{'seeds':[seed.card(port=7443)]},'admission':{'mode':'public'}})
    private_write(a.directory/'network-profile.json',p)
    a.db.execute('DELETE FROM peers WHERE id=?',(b.id,))
    a.db.executemany('INSERT INTO referrals VALUES(?,?)',[(f'{i:064x}',seed.id) for i in range(8)])
    obj=announcement(b,'127.0.0.1',7443,'agentmesh-demo-v1')
    assert not learn(a,obj,'agentmesh-demo-v1',source=seed.id)
    assert learn(a,obj,'agentmesh-demo-v1')
    renew(b.directory)
    renewed=Node(b.directory)
    try:
        # No prior endpoint timestamp needed to prove certificate key continuity.
        a.db.execute('DELETE FROM peer_announcements WHERE peer=?',(b.id,))
        assert learn(a,announcement(renewed,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1')
        assert a.peer(b.id)['card']['certificate']==renewed.identity.pem
    finally:renewed.close()


def test_federated_partial_coverage_and_verified_public_hits(mesh,monkeypatch):
    from agentmesh.openmesh import federated_search
    a,b,d=mesh
    servers=[Server(b),Server(d)];threads=[s.start() for s in servers]
    for n,s in zip((b,d),servers):a.trust(n.card(port=s.server_address[1]),['public'])
    monkeypatch.setattr('agentmesh.embedding.encode_for',lambda *args,**kwargs:[1,0,0])
    for node in (b,d):publish(node,'interesting topic',audience=['@public'])
    try:
        result=federated_search(a,'interesting',peers=[b.id,d.id],k=20)
        assert len(result['results'])==2 and len(result['coverage']['responded'])==2
        a.block(d.id)
        result=federated_search(a,'interesting',peers=[b.id,d.id])
        assert d.id in result['coverage']['failed'] and not result['coverage']['network_complete']
        assert len(result['results'])==1
    finally:
        for server,thread in zip(servers,threads):server.shutdown();thread.join();server.server_close()


def test_incomplete_receipt_reconciliation_never_reexecutes(mesh):
    from agentmesh.lifecycle import receipt
    a,b,_=mesh
    assert tool(a,'mcp:old','authorize',peer=b.id,permissions=[])['ok']
    a.db.execute("UPDATE tool_receipts SET response=NULL WHERE id='mcp:old'")
    with pytest.raises(Denied):retire_epoch(a,0)
    prior=receipt(a,'mcp:old');assert prior['state']=='incomplete'
    a.active_mutations.add('mcp:old')
    with pytest.raises(Denied):receipt(a,'mcp:old',expected_fingerprint=prior['fingerprint'])
    a.active_mutations.clear()
    result=tool(a,'reconcile','receipt_abandon',key='mcp:old',expected_fingerprint=prior['fingerprint'])
    assert result['ok'] and not result['result']['execution_repeated']
    assert not tool(a,'mcp:old','authorize',peer=b.id,permissions=[])['ok']
    assert retire_epoch(a,0)['receipt_epoch']==1
