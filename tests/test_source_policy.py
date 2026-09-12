import pytest

from agentmesh.crypto import Denied, Invalid
from agentmesh.node import Node
from agentmesh.network import Client, Server
from agentmesh.source_policy import configure, config
from agentmesh.onboarding import policy
from agentmesh.cache import select_peers
from conftest import publish


@pytest.fixture
def connected(mesh):
    servers = [Server(n) for n in mesh]
    for server in servers:server.start()
    for node in mesh:
        for peer,server in zip(mesh,servers):
            if node != peer:node.trust(peer.card(port=server.server_address[1]), ['read','publish','message'])
    yield mesh
    for server in servers:server.shutdown();server.server_close()


def test_sources_authors_network_and_cache(connected):
    author,holder,reader=connected
    rid=publish(author,'documentation needle',audience=['@public'])
    foreign=publish(holder,'unapproved needle',audience=['@public'])
    Client(holder,author.id).fetch(rid)
    configure(reader,{'sources':[holder.id],'authors':[author.id]})
    assert select_peers(reader)==[holder.id]
    with pytest.raises(Denied):Client(reader,author.id).search(query_text='needle')
    result=Client(reader,holder.id).search(query_text='needle')
    assert [h['record']['id'] for h in result['results']]==[rid]
    with pytest.raises(Denied):Client(reader,holder.id).request('get',id=foreign)
    Client(reader,holder.id).fetch(rid)
    reader.approve(rid)
    assert reader.search(reader.id,query_text='needle')['results']
    configure(reader,{'sources':[], 'authors':[author.id]})
    assert not reader.search(reader.id,query_text='needle')['results']
    with pytest.raises(Denied):reader.inspect(rid)
    with pytest.raises(Denied):Client(reader,holder.id).fetch(rid)
    with pytest.raises(Denied):reader.get(rid,author.id)
    configure(reader,{'sources':[holder.id], 'authors':[]})
    with pytest.raises(Denied):reader.inspect(rid)


def test_legacy_imports_fail_closed_and_refetch_restores_provenance(connected):
    a,b,c=connected
    rid=publish(a,'legacy record',audience=['@public'])
    b.ingest(a.get(rid,b.id));b.approve(rid)
    configure(b,{'sources':[a.id]})
    with pytest.raises(Denied):b.inspect(rid)
    Client(b,a.id).fetch(rid)
    assert b.inspect(rid)['record']['id']==rid
    assert b.db.execute('SELECT source FROM record_sources WHERE record=?',(rid,)).fetchone()[0]==a.id


def test_sender_change_hides_history_and_cursor_advances(connected):
    a,b,c=connected
    Client(a,b.id).send('old excluded message')
    Client(c,b.id).send('allowed message')
    configure(b,{'senders':[c.id]})
    with pytest.raises(Denied):Client(a,b.id).send('new excluded message')
    assert len(b.inbox())==1
    page=b.inbox_page(limit=1)
    assert page['messages']==[] and page['next'] is not None
    last=b.inbox_page(after=page['next'],limit=1)
    assert last['messages'][0]['message']['body']['origin']==c.id
    assert last['next'] is None
    configure(b,{'senders':[]})
    assert b.inbox()==[]
    assert b.inbox_page(limit=100)['next'] is None


def test_provider_serves_own_content_only_and_preserves_owner_updates(connected):
    a,provider,reader=connected
    imported=publish(a,'foreign documentation',audience=['@public'])
    Client(provider,a.id).fetch(imported);provider.approve(imported)
    own=publish(provider,'official documentation',audience=['@public'])
    from agentmesh.routing import configure as route_configure, config as route_config
    route_configure(provider,{'enabled':True,'forward':True})
    configure(provider,{'mode':'provider'})
    caps=policy(provider)
    assert caps['serve_memory'] and caps['publish'] and not caps['receive']
    assert not route_config(provider)['enabled'] and not route_config(provider)['forward']
    results=Client(reader,provider.id).search(query_text='documentation')['results']
    assert [h['record']['id'] for h in results]==[own]
    Client(reader,provider.id).fetch(own)
    with pytest.raises(Denied):Client(reader,provider.id).fetch(imported)
    with pytest.raises(Denied):Client(a,provider.id).send('unwanted')
    with pytest.raises(Denied):provider.inbox()
    with pytest.raises(Denied):Client(provider,a.id).search(query_text='documentation')
    with pytest.raises(Denied):Client(reader,provider.id).request('threads')
    with pytest.raises(Denied):Client(reader,provider.id).request('route_exchange')
    assert Client(reader,provider.id).peer_status()['operations']['message'] is False
    publish(provider,'updated documentation',audience=['@public'])
    provider.retract(own)
    with pytest.raises(Denied):Client(reader,provider.id).fetch(own,refresh=True)


def test_policy_persists_and_invalid_configuration_keeps_previous(mesh):
    a,b,c=mesh
    configure(a,{'sources':[b.id],'authors':[],'senders':[]})
    for bad in ({'version':True},{'sources':'*'},{'authors':[b.id,b.id]},{'senders':['host.example']},{'mode':'oops'},{'extra':True}):
        with pytest.raises(Invalid):configure(a,bad)
    other=Node(a.directory)
    try:assert config(other)==config(a) and config(other)['sources']==[b.id]
    finally:other.close()


def test_parent_restriction_and_threads(mesh):
    a,b,c=mesh
    parent=publish(a,'parent',audience=['@public'])
    b.ingest(a.get(parent,b.id),source=a.id);b.approve(parent)
    child=publish(b,'derived',parents=[parent],audience=['@public'])
    from agentmesh.conversations import create, accept, _body, page
    root=create(b,'discussion',['@public'])['id']
    post=_body(a,'reply','old post',thread=root,parent=root)
    accept(b,post,a.id)
    configure(b,{'authors':[], 'senders':[]})
    with pytest.raises(Denied):b.get(child,b.id)
    with pytest.raises(Denied):accept(b,_body(a,'reply','new post',thread=root,parent=root),a.id)
    assert page(b,b.id,thread=root)['items']==[]


def test_mcp_views_and_federated_selection_obey_policy(connected,monkeypatch):
    from agentmesh.agent import call
    from agentmesh.service import LocalBackend
    def available(n):return {t["name"] for t in LocalBackend(n).dispatch({"method":"tools/list"})}
    from agentmesh.openmesh import federated_search
    a,b,c=connected
    rid=publish(a,'visible documentation',audience=['@public'])
    Client(b,a.id).fetch(rid);b.approve(rid)
    configure(b,{'sources':[], 'authors':[]})
    for view in ('summary','full'):
        response=call(b,{'id':'inspect-'+view,'tool':'inspect','arguments':{'id':rid,'view':view}})
        assert not response['ok']
    monkeypatch.setattr('agentmesh.embedding.encode_for',lambda *a,**k:[1.,0.,0.])
    assert federated_search(b,'documentation')['coverage']['requested']==[]
    result=federated_search(b,'documentation',peers=[a.id])
    assert not result['results'] and result['coverage']['failed'][a.id]=='Denied'
    configure(b,{'mode':'provider'})
    assert 'search' not in available(b) and 'inbox' not in available(b)
    assert 'source-config' not in available(b)


def test_policy_backup_restore(mesh,tmp_path):
    from agentmesh.operations import backup,restore
    a,b,c=mesh
    configure(a,{'mode':'provider','senders':[]})
    target=tmp_path/'backup'
    backup(a.directory,target)
    dest=tmp_path/'restored'
    restore(target,dest)
    restored=Node(dest)
    try:
        assert config(restored)['mode']=='provider'
        assert not policy(restored)['receive']
    finally:restored.close()


def test_routed_sender_list_checks_final_origin(tmp_path):
    # Final receipt ingestion uses the same receive boundary even after hop work.
    a=Node.create(tmp_path/'a',model='test',dimensions=3)
    b=Node.create(tmp_path/'b',model='test',dimensions=3)
    try:
        a.trust(b.card(port=7443),['message']);b.trust(a.card(port=7443),['message'])
        configure(b,{'senders':[]})
        with pytest.raises(Denied,match='source_policy_denied:senders'):
            b.receive_message(a.make_message(b.id,'sealed origin'),a.id,_routed_work={})
        assert b.db.execute('SELECT count(*) FROM messages').fetchone()[0]==0
    finally:a.close();b.close()
