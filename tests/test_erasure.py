import copy
import time

import pytest

from agentmesh.bootstrap import Directory, BootstrapServer, BootstrapClient, announcement
from agentmesh.crypto import Invalid, Denied
from agentmesh.erasure import request
from agentmesh.pow import solve


def enroll(directory,node):
    obj=announcement(node,'127.0.0.1',7443,directory.network)
    ticket=directory.issuer.issue(node.id,obj['id'])
    directory.register(obj,ticket,solve(ticket))
    return obj


def test_signed_removal_hidden_countdown_restart_security_retained(mesh,monkeypatch):
    seed,peer,_=mesh
    directory=Directory(seed)
    enroll(directory,peer)
    seed.defense.remember('peer',peer.id,'invalid_request')
    obj=request(peer,seed.id,directory.network)
    receipt=directory.deregister(obj)['body']
    assert receipt['clear_at']-receipt['accepted_at']==60
    assert receipt['status']=='scheduled'
    assert directory.dispatch({'op':'discover','args':{}})['announcements']==[]
    assert directory.db.execute('SELECT count(*) FROM announcements').fetchone()[0]==1
    again=directory.deregister(obj)['body']
    assert again==receipt
    directory.close();directory=Directory(seed)
    try:
        assert directory.deregister(obj)['body']==receipt
        with pytest.raises(Denied,match='suppression'):
            enroll(directory,peer)
        now=receipt['clear_at']+1
        monkeypatch.setattr('agentmesh.bootstrap.time.time',lambda:now)
        directory.purge()
        assert directory.db.execute('SELECT count(*) FROM announcements').fetchone()[0]==0
        assert not any(x['peer']==peer.id for x in seed.defense.events())
        assert seed.defense.evidence()[0]['target']==peer.id
        assert directory.deregister(obj)['body']['status']=='cleared'
        now=receipt['suppression_until']+1
        directory.purge()
        assert directory.db.execute('SELECT count(*) FROM removals').fetchone()[0]==0
        with pytest.raises(Invalid,match='expired'):directory.deregister(obj)
    finally:directory.close()


def test_forgery_wrong_seed_and_no_arbitrary_tombstone_allocation(mesh):
    seed,a,b=mesh
    directory=Directory(seed)
    try:
        enroll(directory,a)
        obj=request(b,seed.id,directory.network)
        forged=copy.deepcopy(obj);forged['body']['peer']=a.id
        with pytest.raises(Invalid):directory.deregister(forged)
        with pytest.raises(Invalid):directory.deregister(request(a,b.id,directory.network))
        with pytest.raises(Invalid):directory.deregister(request(a,seed.id,'wrong-network'))
        receipt=directory.deregister(obj)['body']
        assert receipt['status']=='cleared'
        assert directory.db.execute('SELECT count(*) FROM removals').fetchone()[0]==0
        assert len(directory.dispatch({'op':'discover','args':{}})['announcements'])==1
    finally:directory.close()


def test_real_tls_deregister_needs_no_work(mesh,monkeypatch):
    seed,a,_=mesh
    directory=Directory(seed,bits=8)
    with BootstrapServer(directory) as server:
        thread=server.start()
        try:
            client=BootstrapClient(seed.card(port=server.server_address[1]))
            client.register(a,'127.0.0.1',7443)
            # Removal must work even if the proof-of-work solver is unavailable.
            def no_work(*args,**kwargs):
                raise AssertionError('de-registration must not require PoW')
            monkeypatch.setattr('agentmesh.bootstrap.solve',no_work)
            receipt=client.deregister(a)
            assert receipt['body']['discovery_removed']
            assert client.discover()==[]
        finally:server.shutdown();thread.join()
    directory.close()


def test_evidence_survives_routine_expiry_and_repeat_ban_escalates(tmp_path):
    from agentmesh.defense import Defense
    now=[1000.]
    d=Defense(tmp_path,clock=lambda:now[0])
    for _ in range(8):d.failure('192.0.2.1',peer='a'*64,event='invalid')
    assert d.rules()[0]['expires']==1300
    d.close();now[0]=100000.
    d=Defense(tmp_path,clock=lambda:now[0])
    try:
        d.events();assert d.evidence()
        for _ in range(8):d.failure('192.0.2.1',peer='a'*64,event='invalid')
        assert d.rules()[0]['expires']==100600
        d.erase_routine('a'*64);assert d.evidence()
        d.clear_evidence('peer','a'*64,'Reviewed false positive after operator investigation')
        assert not d.evidence()
        assert d.rules() # retention review does not silently lift a ban
    finally:d.close()
