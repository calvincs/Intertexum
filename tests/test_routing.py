import copy
import time

import pytest

from agentmesh import routing as r
from agentmesh.crypto import Denied, Invalid, sign, canonical
from agentmesh.node import Node


@pytest.fixture
def diamond(tmp_path, monkeypatch):
    nodes = [Node.create(tmp_path / str(i), model='test-v1', dimensions=3) for i in range(4)]
    a,b,c,d = nodes
    links = {a:[b,c],b:[a,d],c:[a,d],d:[b,c]}
    for n in nodes:
        for p in nodes:
            if n != p:n.trust(p.card(port=7443), ['read','message'])
        r.configure(n, {'enabled':True,'forward':True,'pow_bits':8,'neighbors':[p.id for p in links[n]]})
    def request(client, op, **args):
        target = next(n for n in nodes if n.id == client.peer_id)
        if client.node.defense.blocked(peer=target.id):raise OSError('simulated failed next hop')
        if op == 'route_exchange':return r.exchange(target, client.node.id)
        if op == 'route_accept':return r.accept(target, client.node.id, **args)
        raise AssertionError(op)
    monkeypatch.setattr('agentmesh.network.Client.request',request)
    for _ in range(3):
        for n in nodes:r.refresh(n)
    yield nodes
    for n in nodes:n.close()


def converge(nodes, rounds=3):
    for _ in range(rounds):
        # Production polls every 15 seconds. Advance all simulated buckets
        # together before this compressed test round.
        for n in nodes:n.defense.buckets.clear()
        for n in nodes:r.refresh(n)


def test_learned_routes_paid_sealed_delivery_and_receipt(diamond):
    a,b,c,d = diamond
    paths=r.routes(a,d.id)
    assert len(paths)==2 and all(len(p)==2 for p in paths)
    item=r.queue_message(a,d.id,'Private calibration result')
    wire=a.db.execute('SELECT wire FROM route_queue').fetchone()[0]
    assert 'Private calibration result' not in wire
    r.deliver(a)
    assert r.status(a)['deliveries'][0]['state']=='forwarded'
    hop=next(n for n in (b,c) if n.db.execute('SELECT count(*) FROM route_queue').fetchone()[0])
    assert not hop.inbox()
    r.deliver(hop)
    assert len(d.inbox())==1
    converge(diamond)
    assert r.status(a)['deliveries'][0]['state']=='delivered'
    assert d.inbox()[0]['message']['id']==item['message']
    # Re-send the identical custody object: no duplicated recipient message.
    row=hop.db.execute('SELECT wire,chain FROM route_queue').fetchone()
    from agentmesh.crypto import decode
    envelope,chain=decode(row[0].encode()),decode(row[1].encode())
    proof=r.pay(hop,envelope,chain,d.id,r.price(d))
    r.accept(d,hop.id,envelope,chain+[proof])
    assert len(d.inbox())==1


def test_next_hop_failure_uses_alternate_route(diamond):
    a,b,c,d=diamond
    first=r.routes(a,d.id)[0][0]
    # Failure occurs after route selection, before next-hop acknowledgement.
    from agentmesh.network import Client
    old=Client.request
    def fail(client,op,**args):
        if client.peer_id==first:raise OSError('offline')
        return old(client,op,**args)
    item=r.queue_message(a,d.id,'Route around failed hop')
    with pytest.MonkeyPatch.context() as m:
        m.setattr(Client,'request',fail);r.deliver(a)
    row=a.db.execute('SELECT * FROM route_queue WHERE id=?',(item['id'],)).fetchone()
    assert row['state']=='forwarded' and row['next_hop']!=first
    next(n for n in (b,c) if n.id==row['next_hop'])


def test_tampered_ads_no_grants_and_expiry(diamond):
    a,b,c,d=diamond
    obj=r.advertise(b);bad=copy.deepcopy(obj);bad['body']['links']=[d.id]
    with pytest.raises(Invalid):r.ingest_lsa(a,bad)
    obj['body']['expires']=int(time.time())-1
    expired=sign(b.identity.key,r.LSA,obj['body'])
    with pytest.raises(Invalid):r.ingest_lsa(a,expired)
    a.db.execute('UPDATE route_lsas SET expires=0 WHERE peer<>?',(a.id,))
    assert not r.routes(a,d.id)
    assert a.peer(d.id)['permissions']==['message','read']


def test_wrong_toll_chain_loop_expiry_and_ciphertext(diamond):
    a,b,c,d=diamond
    item=r.queue_message(a,d.id,'Bounded route')
    from agentmesh.crypto import decode
    env=decode(a.db.execute('SELECT wire FROM route_queue').fetchone()[0].encode())
    proof=r.pay(a,env,[],b.id,r.price(b))
    bad=copy.deepcopy(proof);bad['body']['nonce']+=1
    with pytest.raises(Invalid):r.accept(b,a.id,env,[bad])
    with pytest.raises(Denied):r.accept(b,c.id,env,[proof])
    with pytest.raises(Invalid):r.accept(b,a.id,env,[proof]*5)
    r.configure(b,{'enabled':True,'forward':True,'pow_bits':12})
    with pytest.raises(Denied,match='toll'):r.accept(b,a.id,env,[proof])
    altered=copy.deepcopy(env);altered['body']['ciphertext']='00'*32
    with pytest.raises(Invalid):r.accept(b,a.id,altered,[proof])
    assert not b.db.execute('SELECT 1 FROM route_queue').fetchone()


def test_final_grants_and_budgets_still_apply(diamond):
    a,b,c,d=diamond
    r.queue_message(a,d.id,'Still needs permission')
    r.deliver(a)
    hop=next(n for n in (b,c) if n.db.execute('SELECT count(*) FROM route_queue').fetchone()[0])
    d.trust(a.card(port=7443), ['public'])
    r.deliver(hop)
    assert not d.inbox()
    assert 'permission denied' in r.status(hop)['deliveries'][0]['error']


def test_owner_opt_in_and_solver_budget(diamond):
    a,b,c,d=diamond
    r.configure(a,{'enabled':False})
    with pytest.raises(Denied):r.queue_message(a,d.id,'No implicit permission')
    r.configure(a,{'enabled':True,'pow_bits':8,'max_solve_bits':8})
    with pytest.raises(Denied,match='work limit'):r.pay(a,{'id':'a'*64,'body':{'expires':int(time.time())+60}},[],b.id,16)
    assert not a.db.execute('SELECT * FROM route_work').fetchone()


def test_recipient_receipt_cannot_be_forged_by_relay(diamond):
    a,b,c,d=diamond
    item=r.queue_message(a,d.id,'Only recipient acknowledges')
    fake=sign(b.identity.key,r.RECEIPT,dict(version=1,envelope=item['id'],message=item['message'],origin=a.id,recipient=d.id,expires=item['expires']))
    with pytest.raises(Invalid):r.ingest_receipt(a,fake)
    assert r.status(a)['deliveries'][0]['state']=='queued'


def test_restart_preserves_custody_and_receipt_state(diamond):
    a,b,c,d=diamond
    item=r.queue_message(a,d.id,'Survive origin restart')
    clone=Node(a.directory)
    try:
        assert r.status(clone)['deliveries'][0]['id']==item['id']
        assert r.status(clone)['deliveries'][0]['state']=='queued'
        assert r.key(clone).public_key().public_bytes_raw()==r.key(a).public_key().public_bytes_raw()
    finally:clone.close()


def test_valid_signature_with_invalid_pow_is_rejected(diamond):
    a,b,c,d=diamond
    r.queue_message(a,d.id,'Pay the toll')
    from agentmesh.crypto import decode
    env=decode(a.db.execute('SELECT wire FROM route_queue').fetchone()[0].encode())
    h=r.pay(a,env,[],b.id,r.price(b))['body']
    while r._proof(h):h['nonce']+=1
    bad=sign(a.identity.key,r.HOP,h)
    with pytest.raises(Invalid,match='paid hop'):r.accept(b,a.id,env,[bad])
    assert not b.db.execute('SELECT 1 FROM route_queue').fetchone()


def test_three_paid_hops_over_real_tls(tmp_path):
    from agentmesh.network import Server
    nodes=[Node.create(tmp_path/str(i),model='test-v1',dimensions=3) for i in range(4)]
    servers=[];threads=[]
    try:
        for n in nodes:
            s=Server(n);servers.append(s);threads.append(s.start())
        for i,n in enumerate(nodes):
            for j,p in enumerate(nodes):
                if i!=j:n.trust(p.card(*servers[j].server_address),['read','message'])
            adjacent=[nodes[j].id for j in (i-1,i+1) if 0<=j<4]
            r.configure(n,{'enabled':True,'forward':True,'neighbors':adjacent,'pow_bits':8})
        for _ in range(4):
            for n in nodes:r.refresh(n)
        a,b,c,d=nodes
        assert r.routes(a,d.id)==[[b.id,c.id,d.id]]
        message=r.queue_message(a,d.id,'Three paid WAN-style hops')
        for n in nodes[:3]:r.deliver(n)
        assert len(d.inbox())==1
        assert not b.inbox() and not c.inbox()
        converge(nodes)
        assert r.status(a)['deliveries'][0]['state']=='delivered'
        assert d.inbox()[0]['message']['id']==message['message']
    finally:
        for s,t in zip(servers,threads):s.shutdown();t.join();s.server_close()
        for n in nodes:n.close()


def test_custody_without_receipt_tries_an_alternate(diamond):
    a,b,c,d=diamond
    item=r.queue_message(a,d.id,'Custody is not final delivery')
    r.deliver(a)
    first=a.db.execute('SELECT next_hop FROM route_queue WHERE id=?',(item['id'],)).fetchone()[0]
    # The first relay remains alive and acknowledges custody but never forwards.
    a.db.execute('UPDATE route_queue SET next=0 WHERE id=?',(item['id'],))
    r.deliver(a)
    second=a.db.execute('SELECT next_hop FROM route_queue WHERE id=?',(item['id'],)).fetchone()[0]
    assert first!=second
    r.deliver(next(n for n in (b,c) if n.id==second))
    converge(diamond)
    assert r.status(a)['deliveries'][0]['state']=='delivered'
    assert len(d.inbox())==1


@pytest.mark.parametrize('value',[None,[],{'body':{'origin':[],'recipient':[]}}, {'body':None}])
def test_malformed_routing_objects_fail_closed(mesh,value):
    a,_,_=mesh
    for fn in (r.ingest_lsa,r.ingest_receipt,r._envelope):
        with pytest.raises(Invalid):fn(a,value)


def test_backup_preserves_routing_and_message_work_policy(mesh,tmp_path):
    from agentmesh.operations import backup,restore
    from agentmesh.message_work import configure as messages,config as message_config
    a,b,_=mesh
    routing_policy=r.configure(a,{'enabled':True,'forward':True,'neighbors':[b.id],
        'pow_bits':16,'solve_hour_ms':8000,'max_pending':12})
    message_policy=messages(a,{'bits':18,'peer_pending':7,'max_solve_ms':2000})
    backup(a.directory,tmp_path/'backup')
    restore(tmp_path/'backup',tmp_path/'restored')
    restored=Node(tmp_path/'restored')
    try:
        assert r.config(restored)==routing_policy
        assert message_config(restored)==message_policy
        assert r.key(restored).public_key().public_bytes_raw()==r.key(a).public_key().public_bytes_raw()
        assert (restored.directory/'connectivity-suspended').exists()
    finally:restored.close()


def test_equal_length_routes_compare_expected_work(mesh,monkeypatch):
    a,_,_=mesh
    r.configure(a,{'enabled':True})
    b,c,e,f,d=[str(i)*64 for i in range(1,6)]
    edges={a.id:[b,e],b:[a.id,c],c:[b,d],e:[a.id,f],f:[e,d],d:[c,f]}
    costs={a.id:8,b:8,c:20,e:15,f:15,d:8}
    ads={p:{'links':links,'forward':True,'bits':costs[p]} for p,links in edges.items()}
    monkeypatch.setattr(r,'table',lambda node:ads)
    monkeypatch.setattr(r,'neighbors',lambda node:[b,e])
    # 2^15 + 2^15 is much cheaper than 2^8 + 2^20, despite the bit sums.
    assert r.routes(a,d)[0]==[e,f,d]
