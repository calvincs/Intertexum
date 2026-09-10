import json
import time
import asyncio

import pytest

from agentmesh.node import Node
from agentmesh.bootstrap import Directory, BootstrapServer
from agentmesh.connectivity import Connectivity, configuration, selected_path
from agentmesh.crypto import Invalid, Denied
from agentmesh.network import Client


def wait_until(predicate, timeout=25):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.05)
    raise AssertionError('condition did not become true')


def test_turn_requires_credentials_and_no_secret_status(tmp_path):
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    try:
        assert 'ice_candidate_cidrs' not in configuration({'seeds':[seed.card(port=7444)]})
        assert configuration({'seeds':[seed.card(port=7444)],'ice_candidate_cidrs':['10.1.2.3/8']})['ice_candidate_cidrs']==['10.0.0.0/8']
        with pytest.raises(Invalid,match='authenticated'):
            configuration({'seeds':[seed.card(port=7444)],'ice_servers':[{'urls':'turn:127.0.0.1'}]})
        with pytest.raises(Invalid,match='TURN'):
            configuration({'seeds':[seed.card(port=7444)],'relay_only':True})
    finally:seed.close()


def run_pair(tmp_path, *, ice_servers=(), relay_only=False):
    nodes=[Node.create(tmp_path/n,model='test',dimensions=3) for n in ('seed','alice','bob')]
    seed,a,b=nodes
    d=Directory(seed)
    server=BootstrapServer(d);thread=server.start()
    config={'seeds':[seed.card(port=server.server_address[1])],
            'ice_servers':list(ice_servers),'relay_only':relay_only,
            'ice_candidate_cidrs':['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']}
    for node,peer in ((a,b),(b,a)):
        node.trust(peer.card(port=9),['read','publish','message'])
        (node.directory/'connectivity.json').write_text(json.dumps(config))
        node.connectivity=Connectivity(node,config,port=7443).start()
    return nodes,d,server,thread


def cleanup(pair):
    nodes,d,server,thread=pair
    for n in nodes[1:]:n.close()
    server.shutdown();thread.join();server.server_close();d.close();nodes[0].close()


def test_real_ice_hole_punch_dtls_rpc_and_reconnect(tmp_path):
    pair=run_pair(tmp_path)
    seed,a,b=pair[0]
    try:
        wait_until(lambda:all(m.state['seeds'].get(seed.id)=='connected' for m in (a.connectivity,b.connectivity)))
        async def idle_mailbox():
            b.connectivity.poll_interval[seed.id]=10
            b.connectivity.poll_due[seed.id]=time.monotonic()+10
        asyncio.run_coroutine_threadsafe(idle_mailbox(),b.connectivity.loop).result(5)
        started=time.monotonic()
        response=Client(a,b.id).send('A signed message over direct ICE, without a TCP listener.')
        assert time.monotonic()-started<25 # Idle backoff still fits offer establishment deadline.
        assert response and len(b.inbox())==1
        wait_until(lambda:a.connectivity.state['peers'].get(b.id,{}).get('path')=='direct-ice')
        # Socket replacement generates new ICE candidates and a fresh signed
        # session. The next RPC reconnects rather than reusing obsolete routes.
        async def break_connection():
            for s in list(a.connectivity.sessions.values()):await s.pc.close()
        asyncio.run_coroutine_threadsafe(break_connection(),a.connectivity.loop).result(5)
        Client(a,b.id).send('Second message after the old ICE sockets closed.')
        assert len(b.inbox())==2
        b.defense.block('peer',a.id)
        with pytest.raises(Denied):Client(a,b.id).search(query_text='blocked')
    except BaseException:
        print('CONNECTIVITY STATE',a.connectivity.state,b.connectivity.state)
        raise
    finally:cleanup(pair)


def test_signed_signal_scope_identity_replay_and_suspension(tmp_path):
    from agentmesh.rendezvous import envelope, validate
    nodes=[Node.create(tmp_path/n,model='test',dimensions=3) for n in ('seed','a','b','stranger')]
    seed,a,b,stranger=nodes
    manager=Connectivity(a,{'seeds':[seed.card(port=7444)]})
    try:
        a.trust(b.card(port=7443),['message'])
        obj=envelope(b,seed.id,'agentmesh-demo-v1','send',{'to':a.id})
        assert validate(obj,seed.id,'agentmesh-demo-v1')['origin']==b.id
        with pytest.raises(Invalid):validate(obj,stranger.id,'agentmesh-demo-v1')
        obj['body']['args']['to']=stranger.id
        with pytest.raises(Invalid):validate(obj,seed.id,'agentmesh-demo-v1')
        unknown=envelope(stranger,seed.id,'agentmesh-demo-v1','send',{'to':a.id})
        with pytest.raises(Denied):asyncio.run(manager._signal(seed.card(),unknown))
        assert not manager.sessions
        manager.generation(b.id,3)
        with pytest.raises(Invalid,match='replayed'):manager.generation(b.id,2)
        manager.close()
        manager=Connectivity(a,{'seeds':[seed.card(port=7444)]})
        with pytest.raises(Invalid,match='replayed'):manager.generation(b.id,3)
        (a.directory/'connectivity-suspended').touch()
        with pytest.raises(Denied,match='suspended'):asyncio.run(manager.connect(b.id))
    finally:
        manager.close()
        for n in nodes:n.close()


def test_candidates_bounded_and_no_multicast():
    from agentmesh.connectivity import check_sdp
    prefix='m=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n'
    with pytest.raises(Invalid):check_sdp(prefix+'a=candidate:x 1 udp 1 224.0.0.1 9999 typ host\n')
    for host in ('::ffff:224.0.0.1','::ffff:0.0.0.0'):
        with pytest.raises(Invalid):check_sdp(prefix+f'a=candidate:x 1 udp 1 {host} 9999 typ host\n',allowed=lambda ip:True)
    with pytest.raises(Invalid):check_sdp(prefix+33*'a=candidate:x 1 udp 1 192.168.1.2 9999 typ host\n')


def test_public_ice_filters_internal_addresses_and_enforces_owner_cidrs(mesh):
    import ipaddress
    from agentmesh.connectivity import check_sdp
    a,b,seed=mesh
    manager=Connectivity(a,{'seeds':[seed.card(port=7444)]})
    prefix='m=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n'
    candidate=lambda ip:f'a=candidate:x 1 udp 1 {ip} 9999 typ host\n'
    allowed=lambda ip:manager.candidate_allowed(b.id,ip)
    try:
        for host in ('127.0.0.1','::1','::ffff:127.0.0.1','64:ff9b::7f00:1','169.254.169.254','10.0.0.1','192.168.1.2','fe80::1','fc00::1','fec0::1','2002:7f00:1::'):
            with pytest.raises(Denied,match='address policy'):
                check_sdp(prefix+candidate(host),allowed=allowed)
        clean=check_sdp(prefix+candidate('10.0.0.1')+candidate('8.8.8.8'),allowed=allowed)
        assert '10.0.0.1' not in clean and '8.8.8.8' in clean
        manager.config['ice_candidate_cidrs']=['127.0.0.0/8']
        assert allowed(ipaddress.ip_address('127.0.0.1'))
        assert allowed(ipaddress.ip_address('::ffff:127.0.0.1'))
        a.defense.block('cidr','127.0.0.0/8')
        assert not allowed(ipaddress.ip_address('::ffff:127.0.0.1'))
        assert not allowed(ipaddress.ip_address('64:ff9b::7f00:1'))
        a.defense.block('cidr','8.8.8.0/24')
        assert not allowed(ipaddress.ip_address('8.8.8.8'))
        # Merely having a private card / private grant creates no LAN exception.
        assert not allowed(ipaddress.ip_address('192.168.1.2'))
        a.trust(b.card(host='192.168.1.2',port=7443),['public'])
        a.db.execute('INSERT INTO lan_peers VALUES(?)',(b.id,))
        assert allowed(ipaddress.ip_address('192.168.1.2'))
        assert not allowed(ipaddress.ip_address('192.168.1.3'))
        (a.directory/'policy.json').write_text('{"mdns":false}')
        assert not allowed(ipaddress.ip_address('192.168.1.2'))
    finally:manager.close()


def test_public_signal_cannot_create_loopback_probe_session(mesh):
    from agentmesh.rendezvous import envelope
    a,b,seed=mesh
    a.trust(b.card(port=7443),['public'])
    manager=Connectivity(a,{'seeds':[seed.card(port=7444)]})
    sdp='m=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\na=candidate:x 1 udp 1 127.0.0.1 9999 typ host\n'
    obj=envelope(b,seed.id,'agentmesh-demo-v1','send',dict(to=a.id,session='a'*64,generation=1,type='offer',sdp=sdp))
    try:
        with pytest.raises(Denied,match='address policy'):asyncio.run(manager._signal(seed.card(port=7444),obj))
        assert manager.sessions=={}
        assert manager.db.execute('SELECT count(*) FROM generations').fetchone()[0]==0
    finally:manager.close()


def test_idle_polling_thirty_nodes_fits_seed_capacity(tmp_path,monkeypatch):
    from agentmesh.defense import Defense
    from types import SimpleNamespace
    import random
    now=[1000.]
    monkeypatch.setattr('agentmesh.connectivity.time.monotonic',lambda:now[0])
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    guard=Defense(tmp_path,clock=lambda:now[0])
    managers=[];counts={'poll':0,'denied':0}
    try:
        for i in range(30):
            path=tmp_path/f'node{i}';path.mkdir()
            node=SimpleNamespace(directory=path,id=f'{i+1:064x}')
            manager=Connectivity(node,{'seeds':[seed.card(port=7444)]},passive=False)
            manager.last_observed[seed.id]=now[0];manager.registered[seed.id]=now[0]
            manager.poll_due[seed.id]=now[0]+i/3
            manager.random=random.Random(i)
            async def call(card,action,args,peer=node.id):
                assert action=='poll'
                if not guard.connection('192.0.2.1','bootstrap'):counts['denied']+=1;raise OSError('connection throttled')
                try:
                    guard.operation('192.0.2.1','', 'connectivity','bootstrap')
                    assert guard.consume([('signaling:peer:'+peer,2,8)])
                except Denied:counts['denied']+=1;raise
                counts['poll']+=1
                return {'messages':[]}
            manager._call=call
            managers.append(manager)
        async def run():
            for tick in range(1100):
                now[0]=1000+tick/10
                for manager in managers:await manager._seed(seed.card(port=7444))
        asyncio.run(run())
        assert counts['poll']>=300
        assert counts['denied']==0
        assert guard.rules()==[]
        assert all(m.poll_interval[seed.id]==10 for m in managers)
    finally:
        for manager in managers:manager.close()
        guard.close();seed.close()


def test_seed_discovery_one_page_and_probe_failure_does_not_block_poll(mesh,monkeypatch):
    from agentmesh.bootstrap import BootstrapClient
    a,b,seed=mesh
    manager=Connectivity(a,{'seeds':[seed.card(port=7444)]})
    calls=[]
    async def call(card,action,args):
        calls.append(action)
        if action=='observe':return {'observed_ip':'127.0.0.1'}
        if action=='probe':raise Denied('probe rate limited')
        return {'messages':[]}
    manager._call=call
    monkeypatch.setattr(BootstrapClient,'register',lambda *args:None)
    pages=[]
    def page(client,after):
        pages.append(after)
        return {'announcements':[],'next':b.id,'network':client.network}
    monkeypatch.setattr(BootstrapClient,'discover_page',page)
    try:
        asyncio.run(manager._seed(seed.card(port=7444)))
        assert calls==['observe','probe','poll']
        assert manager.state['seeds'][seed.id]=='connected'
        asyncio.run(manager.refresh(seed.card(port=7444)))
        assert pages==['']
        asyncio.run(manager.refresh(seed.card(port=7444)))
        assert pages==['',b.id]
    finally:manager.close()


def test_connectivity_start_stop_drains_pending_transport_tasks(tmp_path):
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    node=Node.create(tmp_path/'node',model='test',dimensions=3)
    node.trust(seed.card(port=7444),['public'])
    try:
        for _ in range(3):
            manager=Connectivity(node,{'seeds':[seed.card(port=7444)]},passive=False)
            async def idle_seed(card):pass
            manager._seed=idle_seed
            manager.refresh=idle_seed
            manager.start()
            async def allocate():
                session=manager.make_session(seed.id,'a'*64)
                session.attach(session.pc.createDataChannel('agentmesh-rpc-v1'))
                await session.pc.setLocalDescription(await session.pc.createOffer())
                return session
            session=asyncio.run_coroutine_threadsafe(allocate(),manager.loop).result(5)
            manager.close()
            assert session.pc.connectionState=='closed'
            assert not manager.thread.is_alive() and manager.loop.is_closed()
            assert not manager.sessions and not manager.tasks
    finally:node.close();seed.close()


def test_connectivity_immediate_close_preserves_stop_before_main(tmp_path):
    import threading
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    node=Node.create(tmp_path/'node',model='test',dimensions=3)
    try:
        for delayed_start in [False,True]*10:
            manager=Connectivity(node,{'seeds':[seed.card(port=7444)]},passive=False)
            original=manager._run
            if delayed_start:
                enqueued=threading.Event()
                schedule=manager.loop.call_soon_threadsafe
                def enqueue(*args,**kwargs):
                    result=schedule(*args,**kwargs)
                    enqueued.set()
                    return result
                manager.loop.call_soon_threadsafe=enqueue
                def run_after_close_requested():
                    # Force close's callback into the loop queue before _main is
                    # constructed, in addition to exercising the ordinary race.
                    assert enqueued.wait(2)
                    original()
                manager._run=run_after_close_requested
            async def idle_seed(card):pass
            manager._seed=idle_seed
            manager.refresh=idle_seed
            manager.start()
            manager.close()
            assert manager.stop_requested.is_set() and manager.stopping
            assert not manager.thread.is_alive() and manager.loop.is_closed()
            assert not manager.sessions and not manager.tasks
    finally:node.close();seed.close()


def test_message_work_and_free_reply_over_real_ice(tmp_path):
    from agentmesh.message_work import configure,reply_message
    from agentmesh import conversations as c
    pair=run_pair(tmp_path)
    seed,a,b=pair[0]
    try:
        configure(a,{'bits':4});configure(b,{'bits':4})
        wait_until(lambda:all(m.state['seeds'].get(seed.id)=='connected' for m in (a.connectivity,b.connectivity)))
        result=Client(a,b.id).send('paid over ICE')
        assert b.inbox_page()['messages'][0]['reply_offer']['uses']==1
        reply=reply_message(b,a.id,result['id'],'free ICE response')
        c.deliver(b)
        assert c.deliveries(b)['items'][0]['state']=='delivered'
        assert a.inbox()[0]['message']['id']==reply['id']
        assert not b.db.execute('SELECT 1 FROM message_work_out').fetchone()
        assert a.connectivity.state['peers'][b.id]['path']=='direct-ice'
    finally:cleanup(pair)
