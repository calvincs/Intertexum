import copy
import time

import pytest

from agentmesh.bootstrap import (Directory, BootstrapServer, BootstrapClient, announcement,
                                 check_announcement)
from agentmesh.crypto import Invalid, Denied, sign
from agentmesh.pow import Issuer, solve


def test_work_binding_expiry_difficulty_and_budget(mesh):
    a,b,c = mesh
    issuer = Issuer(a.id,'test',bits=8)
    ticket = issuer.issue(b.id,c.id,now=1000)
    nonce = solve(ticket)
    issuer.verify(ticket,nonce,b.id,c.id,now=1000)
    for peer,payload,now in ((a.id,c.id,1000),(b.id,a.id,1000),(b.id,c.id,1120)):
        with pytest.raises(Invalid):
            issuer.verify(ticket,nonce,peer,payload,now=now)
    altered = copy.deepcopy(ticket)
    altered['body']['bits']=0
    with pytest.raises(Invalid):
        issuer.verify(altered,0,b.id,c.id,now=1000)
    with pytest.raises(Invalid):
        Issuer(c.id,'test',bits=8).verify(ticket,nonce,b.id,c.id,now=1000)
    with pytest.raises(Invalid):
        Issuer(a.id,'other',bits=8).verify(ticket,nonce,b.id,c.id,now=1000)
    with pytest.raises(Invalid):
        solve({'body':{'bits':21}})
    with pytest.raises(Invalid):
        solve(ticket,max_seconds=0)


def test_directory_replay_persistence_policy_and_no_trust(mesh):
    seed,peer,_ = mesh
    # Existing mesh fixture approvals are unrelated; directory operations must not mutate them.
    before = seed.peers()
    directory = Directory(seed,bits=4)
    obj = announcement(peer,'127.0.0.1',7443,directory.network)
    ticket = directory.issuer.issue(peer.id,obj['id'])
    nonce = solve(ticket)
    result = directory.register(obj,ticket,nonce)
    assert result['permissions_granted']==[] and seed.peers()==before
    with pytest.raises(Denied,match='already spent'):
        directory.register(obj,ticket,nonce)
    directory.close()
    directory=Directory(seed,bits=4)
    assert directory.dispatch({'op':'discover','args':{}})['announcements']==[obj]
    with pytest.raises(Invalid):
        directory.register(obj,ticket,nonce) # restart rotates stateless challenge key
    directory.close()
    with pytest.raises(Invalid):
        Directory(seed,network='another-network')


def test_signed_discovery_claims(mesh):
    a,b,_=mesh
    obj=announcement(a,'127.0.0.1',7443,'demo')
    check_announcement(obj,'demo')
    with pytest.raises(Invalid):
        check_announcement(obj,'other')
    with pytest.raises(Invalid):
        check_announcement(obj,'demo',public=True)
    altered=copy.deepcopy(obj)
    altered['body']['card']['port']=80
    with pytest.raises(Invalid):
        check_announcement(altered,'demo')
    body=copy.deepcopy(obj['body']);body['issued']=int(time.time())-100;body['expires']=int(time.time())-1
    with pytest.raises(Invalid):
        check_announcement(sign(a.identity.key,'agentmesh.announcement.v1',body),'demo')
    body=copy.deepcopy(obj['body']);body['card']['id']=b.id
    with pytest.raises(Invalid):
        check_announcement(sign(a.identity.key,'agentmesh.announcement.v1',body),'demo')
    body=copy.deepcopy(obj['body']);body['card']['host']=2130706433
    with pytest.raises(Invalid):
        check_announcement(sign(a.identity.key,'agentmesh.announcement.v1',body),'demo')


def test_unknown_peer_bootstrap_over_tls_and_rate_bound(tmp_path):
    from agentmesh.node import Node
    nodes=[Node.create(tmp_path/name,model='test',dimensions=3) for name in ('seed','peer')]
    seed,peer=nodes
    directory=Directory(seed,bits=8)
    with BootstrapServer(directory) as server:
        thread=server.start()
        try:
            client=BootstrapClient(seed.card(port=server.server_address[1]))
            assert client.register(peer,'127.0.0.1',7443)['registered']==peer.id
            assert client.discover()[0]['body']['card']['id']==peer.id
            assert seed.peers()==[] and peer.peers()==[]
            assert not all(server._allow('192.0.2.1') for _ in range(20))
        finally:
            server.shutdown();thread.join()
    directory.close()
    for node in nodes: node.close()


def test_seed_rate_response_exposes_retry_delay(mesh):
    from agentmesh.defense import RateLimited
    seed,_,_=mesh
    directory=Directory(seed)
    with BootstrapServer(directory) as server:
        thread=server.start()
        try:
            seed.defense.buckets['discovery:global']=(0,time.time())
            client=BootstrapClient(seed.card(port=server.server_address[1]))
            with pytest.raises(RateLimited) as error:client.discover_page()
            assert error.value.retry_after>=1
        finally:server.shutdown();thread.join()
    directory.close()


def test_discover_page_rejects_invalid_order_and_cursor(mesh,monkeypatch):
    seed,a,b=mesh
    client=BootstrapClient(seed.card(port=7444))
    objects=sorted([announcement(n,'127.0.0.1',7443,client.network) for n in (a,b)],key=lambda obj:obj['body']['card']['id'])
    page={'announcements':objects,'next':None,'network':client.network}
    monkeypatch.setattr(client,'request',lambda *args,**kwargs:page)
    assert len(client.discover_page()['announcements'])==2
    page['announcements']=list(reversed(objects))
    with pytest.raises(Invalid,match='entry'):client.discover_page()
    page['announcements']=objects
    page['next']=objects[0]['body']['card']['id']
    with pytest.raises(Invalid,match='cursor'):client.discover_page()
