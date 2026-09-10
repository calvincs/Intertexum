import pytest
from agentmesh.cache import remember,hit,sweep,configure,status,credit,select_peers
from agentmesh.crypto import Denied,Invalid
from agentmesh.onboarding import private_write
from agentmesh.lifecycle import retain
from agentmesh.network import Server,Client
from conftest import publish


def test_public_transit_not_local_approval_and_private_exclusion(mesh):
    a,b,c=mesh
    rid=publish(a,'public knowledge',audience=['@public'])
    obj=a.get(rid,b.id)
    assert remember(b,obj)
    assert b.inspect(rid)['state']=='pending'
    assert b.search(b.id,query_text='knowledge')['results']==[]
    assert b.search(c.id,query_text='knowledge')['results'][0]['record']['id']==rid
    assert b.get(rid,c.id)==obj
    assert hit(b,rid)
    for audience in ([b.id,c.id],['*']):
        secret=publish(a,'secret',audience=audience)
        wire=a.get(secret,b.id)
        assert not remember(b,wire)
        b.ingest(wire)
        with pytest.raises(Denied):b.get(secret,c.id)
    private_write(b.directory/'policy.json',{'reshare':False})
    assert hit(b,rid)
    with pytest.raises(Denied):b.get(rid,c.id)
    b.approve(rid)
    assert not b.db.execute('SELECT 1 FROM transit_cache WHERE id=?',(rid,)).fetchone()
    with pytest.raises(Denied):b.get(rid,c.id)
    private_write(b.directory/'policy.json',{'cache':False})
    assert b.get(rid,c.id)==obj  # Explicit approval remains independent of temporary caching.


def test_expiry_rejection_withdrawal_and_parent_policy(mesh):
    a,b,c=mesh
    parent=publish(a,'parent',audience=['@public'])
    child=publish(a,'child',audience=['@public'],parents=[parent])
    child_obj=a.get(child,b.id)
    assert remember(b,child_obj)
    with pytest.raises(Denied):b.get(child,c.id)
    assert remember(b,a.get(parent,b.id))
    assert b.get(child,c.id)['id']==child
    b.db.execute('UPDATE transit_cache SET expires=0 WHERE id=?',(parent,))
    assert not hit(b,parent)
    with pytest.raises(Denied):b.get(child,c.id)
    assert sweep(b)==1
    assert not b._row(parent)
    remember(b,a.get(parent,b.id))
    b.ingest_retraction(a.retract(parent))
    with pytest.raises(Denied):b.get(child,c.id)
    retain(b,child,reject=True)
    assert not b._row(child)
    assert not remember(b,child_obj)
    assert status(b)['stored_records']<=2


def test_cache_bounds_and_explicit_retention(mesh):
    a,b,_=mesh
    configure(b,max_records=1)
    first=publish(a,'one',audience=['@public']);second=publish(a,'two',audience=['@public'])
    remember(b,a.get(first,b.id));remember(b,a.get(second,b.id))
    assert not b._row(first) and b._row(second)
    assert status(b)['stored_records']==1
    retain(b,second,pinned=True)
    b.db.execute('UPDATE transit_cache SET expires=0')
    sweep(b)
    assert b._row(second) and status(b)['stored_records']==0
    assert not remember(b,a.get(second,b.id))
    b.approve(second)
    assert b.get(second,b.id)['id']==second
    with pytest.raises(Invalid):configure(b,ttl=1)
    with pytest.raises(Invalid):configure(b,max_records=True)


def test_credit_deduplicates_expires_and_cannot_grant_access(mesh):
    a,b,c=mesh
    rid=publish(a,'requested third-party record',audience=['@public']);obj=a.get(rid,b.id)
    credit(c,a.id,obj)  # An origin serving its own record earns no relay credit.
    assert status(c)['providers']==[]
    credit(c,b.id,obj);credit(c,b.id,obj)
    assert status(c)['providers'][0]['distinct_records']==1
    assert select_peers(c)[0]==b.id
    c.trust(b.card(port=7443),['public'])
    secret=publish(c,'private local information',audience=[b.id])
    with pytest.raises(Denied):c.get(secret,b.id)
    c.block(b.id)
    assert b.id not in select_peers(c)
    c.db.execute('UPDATE relay_observations SET expires=0')
    assert status(c)['providers']==[]


def test_real_fetch_search_cache_and_verified_relay_credit(mesh):
    a,b,c=mesh
    servers=[];threads=[]
    try:
        for n in (a,b):
            s=Server(n);servers.append(s);threads.append(s.start())
        b.trust(a.card(port=servers[0].server_address[1]),['read','publish','message'])
        c.trust(b.card(port=servers[1].server_address[1]),['read','publish','message'])
        rid=publish(a,'shared data',audience=['@public'])
        assert Client(b,a.id).fetch(rid)==rid
        assert b.inspect(rid)['state']=='pending'
        assert Client(c,b.id).fetch(rid)==rid
        assert status(c)['providers'][0]['peer']==b.id
        # A second access is local; no peer request or reward is generated.
        client=Client(c,b.id)
        def fail(*args,**kwargs):raise AssertionError('cache hit performed a remote request')
        client.request=fail
        assert client.fetch(rid)==rid
        with pytest.raises(AssertionError):client.fetch(rid,refresh=True)
        assert status(c)['providers'][0]['distinct_records']==1
        new=publish(a,'search access',audience=['@public'])
        assert Client(b,a.id).search(query_text='search access')['results']
        assert hit(b,new) and b.inspect(new)['state']=='pending'
        assert b.get(new,c.id)['id']==new
    finally:
        for s,t in zip(servers,threads):s.shutdown();t.join();s.server_close()


def test_cache_restart_and_invalid_data(tmp_path):
    from agentmesh.node import Node
    a=Node.create(tmp_path/'a',model='test',dimensions=3)
    b=Node.create(tmp_path/'b',model='test',dimensions=3)
    try:
        a.trust(b.card(port=7443),['read','publish']);b.trust(a.card(port=7443),['read','publish'])
        rid=publish(a,'restart',audience=['@public']);obj=a.get(rid,b.id)
        import copy
        forged=copy.deepcopy(obj);forged['body']['text']='forged'
        with pytest.raises(Invalid):remember(b,forged)
        assert status(b)['stored_records']==0
        remember(b,obj);configure(b,ttl=60,max_records=3)
        b.close();b=Node(tmp_path/'b')
        assert hit(b,rid) and status(b)['settings']['max_records']==3
        b.db.execute('UPDATE transit_cache SET expires=0')
        with pytest.raises(Denied):b.get(rid,a.id)
        sweep(b);assert not b._row(rid)
    finally:a.close();b.close()
