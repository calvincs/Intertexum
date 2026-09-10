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
            'ice_servers':list(ice_servers),'relay_only':relay_only}
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
        response=Client(a,b.id).send('A signed message over direct ICE, without a TCP listener.')
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
    with pytest.raises(Invalid):check_sdp(prefix+33*'a=candidate:x 1 udp 1 192.168.1.2 9999 typ host\n')
