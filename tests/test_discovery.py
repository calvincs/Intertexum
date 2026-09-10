import asyncio
import time
import uuid
from types import SimpleNamespace

import pytest
from zeroconf import ServiceInfo

from agentmesh.bootstrap import announcement
from agentmesh.connectivity import configuration
from agentmesh.crypto import Denied, Invalid
from agentmesh.discovery import SERVICE, Discovery, introduction, local_address, properties, service_name
from agentmesh.node import Node
from agentmesh.onboarding import private_write, profile


def configure(node, network='lan-test', admission=None):
    value = profile({'version': 1, 'connectivity': {'network': network, 'seeds': []},
                     'admission': admission or {'mode': 'public'}})
    private_write(node.directory/'network-profile.json', value)
    return value


def info(node, network='lan-test', host='192.168.1.2', obj=None):
    return ServiceInfo(SERVICE, service_name(node.id, network), port=7443,
        parsed_addresses=[host], properties=properties(obj or announcement(node, host, 7443, network)))


def test_signed_lan_scope_permissions_and_blocks(mesh):
    a, b, _ = mesh
    configure(a);configure(b)
    a.db.execute('DELETE FROM peers WHERE id=?', (b.id,))
    assert introduction(a, info(b), 'lan-test')
    assert a.peer(b.id)['permissions'] == ['public']
    private = b.publish(b.write_private('private', [1,0,0]), audience=[a.id])
    b.db.execute('DELETE FROM peers WHERE id=?', (a.id,))
    assert introduction(b, info(a), 'lan-test')
    with pytest.raises(Denied): b.get(private, a.id)
    with pytest.raises(Invalid): introduction(a, info(b), 'other-network')
    forged = announcement(b, '192.168.1.2', 7443, 'lan-test')
    forged['body']['card']['port'] = 7444
    with pytest.raises(Invalid): introduction(a, info(b, obj=forged), 'lan-test')
    with pytest.raises(Invalid): introduction(a, info(b, host='8.8.8.8'), 'lan-test')
    mismatch = info(b);mismatch.port = 7444
    with pytest.raises(Invalid): introduction(a, mismatch, 'lan-test')
    a.defense.block('cidr', '192.168.1.0/24')
    assert not introduction(a, info(b), 'lan-test')
    a.defense.unblock('cidr', '192.168.1.0/24')
    a.defense.block('peer', b.id)
    assert not introduction(a, info(b), 'lan-test')


def test_private_lan_requires_invitation_and_policy(mesh):
    a, b, c = mesh
    invitation={'key':'ab'*32,'permissions':['message']}
    configure(a, admission=invitation);configure(b, admission=invitation);configure(c)
    a.db.execute('DELETE FROM peers')
    assert not introduction(a, info(c), 'lan-test')
    assert introduction(a, info(b), 'lan-test')
    assert a.peer(b.id)['permissions'] == ['message']
    private_write(a.directory/'policy.json', {'mdns':False})
    with pytest.raises(Denied): introduction(a, info(b), 'lan-test')


def test_discovery_bounds_and_configuration(mesh):
    a,b,_=mesh
    configure(a);configure(b)
    assert configuration({'seeds':[]})['seeds']==[]
    for extra in ({'mdns':False}, {'mdns':1}, {'relay_only':True}):
        with pytest.raises(Invalid):configuration({'seeds':[],**extra})
    for host in ('127.0.0.1','0.0.0.0','224.0.0.251','8.8.8.8','::1','fe80::1'):
        assert not local_address(host)
    a.db.executemany('INSERT INTO lan_peers VALUES(?)', [(str(i),) for i in range(128)])
    assert not introduction(a, info(b), 'lan-test')
    invalid=SimpleNamespace(properties={b'0':b'x'*201})
    with pytest.raises(Invalid):introduction(a, invalid, 'lan-test')
    owner=SimpleNamespace(node=a, config={'network':'lan-test','seeds':[], 'relay_only':True}, state={})
    assert not Discovery(owner).enabled()


def test_real_multicast_seedless_discovery_and_shutdown(tmp_path):
    from aioice.ice import get_host_addresses
    from agentmesh.network import Server, Client
    if not any(local_address(a) for a in get_host_addresses(use_ipv4=True,use_ipv6=False)):
        pytest.skip('requires an IPv4 LAN interface; run in the isolated LAN test namespace')
    network='mdns-test-'+uuid.uuid4().hex
    nodes=[Node.create(tmp_path/n,model='test',dimensions=3) for n in ('a','b')]
    servers=[];threads=[]
    try:
        for n in nodes:
            value=configure(n,network)
            private_write(n.directory/'connectivity.json',value['connectivity'])
            server=Server(n,'0.0.0.0',0)
            servers.append(server);threads.append(server.start())
        a,b=nodes
        deadline=time.monotonic()+20
        while time.monotonic()<deadline and not all(n.peers() for n in nodes):time.sleep(.1)
        assert a.peer(b.id)['permissions']==['public']
        assert b.peer(a.id)['permissions']==['public']
        rid=b.publish(b.write_private('LAN public record',[1,0,0]),audience=['@public'])
        assert Client(a,b.id).request('get',id=rid)['id']==rid
        for n in nodes:private_write(n.directory/'policy.json',{'mdns':False})
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and any(n.connectivity.state['mdns']['status']!='disabled' for n in nodes):time.sleep(.1)
        assert all(n.connectivity.state['mdns']['status']=='disabled' for n in nodes)
    finally:
        for s,t in zip(servers,threads):s.shutdown();t.join();s.server_close()
        for n in nodes:n.close()
