import threading

import pytest

from agentmesh.crypto import Denied, Invalid
from agentmesh.defense import Defense
from agentmesh.network import Server, Client
from agentmesh.bootstrap import Directory, announcement
from agentmesh.pow import solve
from agentmesh.records import SearchBudget, rank


def test_bans_persist_expire_and_ranges_are_local(tmp_path):
    now=[1000.]
    a=Defense(tmp_path,clock=lambda:now[0])
    a.block('cidr','192.0.2.1/24',seconds=300)
    b=Defense(tmp_path,clock=lambda:now[0])
    try:
        assert b.blocked(source='192.0.2.99')
        assert not b.blocked(source='198.51.100.1')
        now[0]+=301
        assert not b.blocked(source='192.0.2.99')
        a.block('peer','a'*64)
        assert b.blocked(peer='a'*64)
        b.unblock('peer','a'*64)
        assert not a.blocked(peer='a'*64)
    finally:a.close();b.close()


def test_authenticated_search_abuse_does_not_ban_other_nat_users(tmp_path):
    guard=Defense(tmp_path,clock=lambda:1000.)
    try:
        for _ in range(8):guard.operation('192.0.2.1','a'*64,'search','data')
        for _ in range(8):
            with pytest.raises(Denied):guard.operation('192.0.2.1','a'*64,'search','data')
        assert guard.blocked(peer='a'*64)
        assert not guard.blocked(source='192.0.2.1',peer='b'*64)
        guard.operation('192.0.2.1','b'*64,'search','data')
        assert any(r['event']=='auto_ban' for r in guard.events())
    finally:guard.close()


def test_global_saturation_is_not_blame(tmp_path):
    guard=Defense(tmp_path,clock=lambda:1000.)
    try:
        guard.buckets['search:global']=(0,1000.)
        for i in range(8):
            with pytest.raises(Denied,match='global'):
                guard.operation(f'192.0.2.{i+1}',f'{i+1:064x}','search','data')
        assert guard.rules()==[] and guard.failures=={}
    finally:guard.close()


def test_pre_auth_failures_log_only_observed_ip(tmp_path,capsys):
    guard=Defense(tmp_path,clock=lambda:1000.)
    try:
        for _ in range(8):guard.failure('192.0.2.9',event='transport_failure')
        assert not guard.connection('192.0.2.9','bootstrap')
        assert capsys.readouterr().err=='agentmesh abuse source=192.0.2.9\n'
        for _ in range(2100):guard.audit('test')
        assert guard.db.execute('SELECT count(*) FROM audit').fetchone()[0]==2000
    finally:guard.close()


def test_search_busy_is_rejected_without_queuing_and_peer_block_live(mesh,monkeypatch):
    a,b,c=mesh
    entered,release=threading.Event(),threading.Event()
    original=a.search
    def slow(*args,**kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args,**kwargs)
    monkeypatch.setattr(a,'search',slow)
    with Server(a) as server:
        b.trust(a.card(port=server.server_address[1]),['read','publish'])
        c.trust(a.card(port=server.server_address[1]),['read','publish'])
        thread=server.start();result=[]
        worker=threading.Thread(target=lambda:result.append(Client(b,a.id).search(query_text='hello')))
        try:
            worker.start();assert entered.wait(3)
            with pytest.raises(Denied,match='busy'):
                Client(c,a.id).search(query_text='hello')
            release.set();worker.join(5);assert result
            a.defense.block('peer',c.id)
            with pytest.raises(Denied,match='blocked'):
                Client(c,a.id).search(query_text='hello')
        finally:
            release.set();worker.join(5);server.shutdown();thread.join()


def test_discovery_filters_and_registration_price(mesh):
    seed,a,b=mesh
    directory=Directory(seed)
    def register(node):
        obj=announcement(node,'127.0.0.1',7443,directory.network)
        ticket=directory.issuer.issue(node.id,obj['id'])
        return directory.register(obj,ticket,solve(ticket))
    try:
        register(a)
        seed.defense.block('peer',a.id)
        assert directory.dispatch({'op':'discover','args':{}})['announcements']==[]
        with pytest.raises(Denied,match='blocked'):register(a)
        seed.defense.block('cidr','127.0.0.0/8')
        with pytest.raises(Denied,match='blocked'):register(b)
        directory.forget(a.id)
        assert directory.db.execute('SELECT count(*) FROM announcements').fetchone()[0]==0
    finally:directory.close()
    with pytest.raises(Invalid,match='16'):Directory(seed,public=True,bits=0)


def test_expensive_search_has_deadline_not_silent_partial_result(mesh):
    a,_,_=mesh
    with pytest.raises(SearchBudget):a._active('a'*64,a.id,deadline=0)
    with pytest.raises(SearchBudget):rank([],None,'query',10,deadline=0)


def test_registration_identity_churn_does_not_reset_source_budget(tmp_path):
    guard=Defense(tmp_path,clock=lambda:1000.)
    try:
        for _ in range(4):guard.operation('192.0.2.1','','challenge','bootstrap')
        with pytest.raises(Denied,match='rate'):
            guard.operation('192.0.2.1','','challenge','bootstrap')
    finally:guard.close()


def test_expensive_search_charges_cpu_debt(tmp_path,monkeypatch):
    guard=Defense(tmp_path,clock=lambda:1000.)
    ticks=iter([0.,.4])
    monkeypatch.setattr('agentmesh.defense.time.thread_time',lambda:next(ticks))
    try:
        guard.operation('192.0.2.1','a'*64,'search','data')
        with guard.search('192.0.2.1','a'*64): pass
        with pytest.raises(Denied,match='rate'):
            guard.operation('192.0.2.1','a'*64,'search','data')
    finally:guard.close()
