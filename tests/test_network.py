import socket
import ssl
import struct

import pytest

from agentmesh.crypto import Invalid, Denied, decode
from agentmesh.network import Server, Client, context, transmit, receive
from agentmesh.node import Node
from conftest import publish


@pytest.fixture
def live(mesh):
    servers = [Server(node) for node in mesh]
    for node in mesh:
        for server in servers:
            if node != server.node:
                host, port = server.server_address
                node.trust(server.node.card(host, port), ["read", "publish", "message"])
    threads = [server.start() for server in servers]
    yield mesh, servers
    for server, thread in zip(servers, threads):
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def test_tls_fetch_quarantine_cache_and_signed_direct_message(live):
    (a, b, c), _ = live
    rid = publish(a)
    client = Client(b, a.id)
    result = client.search(query_text="research")
    assert result["results"][0]["record"]["id"] == rid
    client.fetch(rid)
    with pytest.raises(Denied):
        Client(c, b.id).request("get", id=rid)
    b.approve(rid)
    assert Client(c, b.id).fetch(rid) == rid
    assert len(a.inventory()) == 2  # original private + explicit published copy
    assert len(b.inventory()) == len(c.inventory()) == 1
    client.send("signed and TLS-encrypted")
    assert a.inbox()[0]["message"]["body"]["origin"] == b.id


def test_retraction_propagates_through_a_cache(live):
    (a, b, c), _ = live
    rid = publish(a)
    Client(b, a.id).fetch(rid); b.approve(rid)
    Client(c, b.id).fetch(rid); c.approve(rid)
    a.retract(rid)
    Client(b, a.id).sync_retractions()
    Client(c, b.id).sync_retractions()
    for node in (a, b, c):
        with pytest.raises(Denied):
            node.get(rid, node.id)
        assert node.search(node.id, query_text="research")["results"] == []


def test_block_is_live_without_server_restart(live):
    (a, b, _), _ = live
    assert Client(b, a.id).search(query_text="anything")
    # Separate operator process/connection writes the local policy database.
    operator = Node(a.directory)
    operator.block(b.id)
    operator.close()
    with pytest.raises((ssl.SSLError, OSError, Invalid, Denied)):
        Client(b, a.id).search(query_text="anything")


def test_unknown_peer_is_not_admitted_by_presenting_a_valid_identity(live, tmp_path):
    (a, _, _), servers = live
    outsider = Node.create(tmp_path / "outsider", model=a.model, dimensions=3)
    outsider.trust(a.card(*servers[0].server_address), ["read", "publish"])
    try:
        with pytest.raises((ssl.SSLError, OSError, Invalid, Denied)):
            Client(outsider, a.id).search(query_text="anything")
    finally:
        outsider.close()


def test_wrong_endpoint_cannot_impersonate_pinned_peer(live):
    (a, b, _), servers = live
    card = a.card(*servers[2].server_address)  # Alice identity, Carol's listener
    b.trust(card, ["read", "publish"])
    with pytest.raises((ssl.SSLError, OSError, Invalid, Denied)):
        Client(b, a.id).search(query_text="anything")


def test_tls13_is_negotiated_and_admin_rpcs_do_not_exist(live):
    (a, b, _), servers = live
    ctx = context(b, server=False, peer_pem=a.identity.pem)
    with socket.create_connection(servers[0].server_address, timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=None) as conn:
            assert conn.version() == "TLSv1.3"
            transmit(conn, {"op": "trust", "args": {"id": b.id, "permissions": ["publish"]}})
            response = receive(conn)
            assert response["ok"] is False
            assert response["error"] == "invalid"


def test_large_results_are_limited_with_explicit_coverage(live, monkeypatch):
    (a, b, _), _ = live
    for i in range(5):
        publish(a, text=f"research {i} " + "x" * 500)
    monkeypatch.setattr("agentmesh.network.MAX_WIRE_BYTES", 2500)
    result = Client(b, a.id).search(query_text="research", k=5)
    assert 0 < len(result["results"]) < 5
    assert result["coverage"]["results_limited_by_response_size"] is True
    assert result["coverage"]["network_complete"] is False


def test_oversized_frame_and_idle_client_do_not_break_listener(live):
    (a, b, _), servers = live
    ctx = context(b, server=False, peer_pem=a.identity.pem)
    with socket.create_connection(servers[0].server_address, timeout=5) as idle:
        with socket.create_connection(servers[0].server_address, timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as conn:
                conn.sendall(struct.pack("!I", 2**31))
                rejection = receive(conn)
                assert rejection["ok"] is False
                assert rejection["error"] == "invalid"
                assert rejection["detail"] == "invalid frame size"
        assert Client(b, a.id).search(query_text="still alive")


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_ambiguous_json_is_rejected(payload):
    with pytest.raises(Invalid):
        decode(payload)


def test_remote_capabilities_are_scoped_to_caller_and_live_policy(live):
    from agentmesh.openmesh import authorize
    from agentmesh.onboarding import private_write
    (a, b, c), servers = live
    a.trust(b.card(*servers[1].server_address), ['public'])
    status = Client(b, a.id).peer_status()
    assert status['permissions'] == ['public']
    assert status['operations']['search']
    assert not status['operations']['message']
    assert status['model_compatible'] and status['private_thread_membership_required']
    assert c.id not in str(status)  # Other peer grants are not disclosed.
    authorize(a, b.id, permissions=['message'], ttl=60)
    assert Client(b, a.id).peer_status()['operations']['message']
    a.db.execute('UPDATE grants SET expires=0 WHERE peer=?', (b.id,))
    assert not Client(b, a.id).peer_status()['operations']['message']
    private_write(a.directory / 'policy.json', {'serve_memory': False})
    assert not Client(b, a.id).peer_status()['operations']['search']


def test_capability_response_identity_and_legacy_unknown(mesh, monkeypatch):
    from agentmesh.peer_status import describe
    a, b, _ = mesh
    client = Client(a, b.id)
    response = describe(b, a.id)
    response['peer'] = a.id
    monkeypatch.setattr(client, 'request', lambda *a, **k: response)
    with pytest.raises(Invalid, match='identity'):
        client.peer_status()
    def old_peer(*args, **kwargs):
        raise Invalid('unsupported operation or arguments')
    monkeypatch.setattr(client, 'request', old_peer)
    status = client.peer_status()
    assert status['supported'] is False
    assert status['operations'] is None


def test_relay_only_never_attempts_direct_tcp(mesh, monkeypatch):
    from types import SimpleNamespace
    a, b, _ = mesh
    calls = []
    manager = SimpleNamespace(config={'relay_only': True}, state={'peers': {}},
        request=lambda peer, op, args: calls.append((peer, op)) or {'ok': True, 'result': {'relayed': True}})
    a.connectivity = manager
    try:
        client = Client(a, b.id)
        def forbidden(*args, **kwargs):
            raise AssertionError('direct TCP was attempted')
        monkeypatch.setattr('agentmesh.network.socket.create_connection', forbidden)
        assert client.request('capabilities') == {'relayed': True}
        assert calls == [(b.id, 'capabilities')]
        with pytest.raises(Denied, match='relay-only'):
            client._direct('capabilities', {})
    finally:
        a.connectivity = None


def test_relay_only_listener_rejects_direct_peer_data(live):
    from types import SimpleNamespace
    (a, b, _), _ = live
    a.connectivity = SimpleNamespace(config={'relay_only': True})
    try:
        assert Client(b, a.id).request('paths')['accepted'] == ['relay']
        with pytest.raises(Denied, match='peer requires relay'):
            Client(b, a.id).request('search', query_text='private')
    finally:
        a.connectivity = None


def test_outbound_blocks_apply_before_any_transport(mesh, monkeypatch):
    a, b, _ = mesh
    a.defense.block('peer', b.id)
    def forbidden(*args, **kwargs):
        raise AssertionError('blocked peer contacted')
    monkeypatch.setattr('agentmesh.network.socket.create_connection', forbidden)
    with pytest.raises(Denied, match='blocked'):
        Client(a, b.id).send('must stay local')


def test_sync_rejects_oversized_event_page(mesh, monkeypatch):
    a, b, _ = mesh
    client = Client(a, b.id)
    monkeypatch.setattr(client, 'request', lambda *a, **k: {'events': [None] * 501, 'next': None})
    with pytest.raises(Invalid, match='page'):
        client.sync_retractions()


def test_concurrent_relay_requests_create_one_manager(mesh, monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor
    a, b, c = mesh
    created = []
    class Manager:
        def __init__(self, node, config, **kwargs):
            created.append(self)
            self.config = config
            self.state = {'peers': {}}
            time.sleep(.02)
        def start(self):
            return self
        def request(self, peer, op, args):
            return {'ok': True, 'result': peer}
    monkeypatch.setattr('agentmesh.connectivity.load_config', lambda node: {'relay_only': True})
    monkeypatch.setattr('agentmesh.connectivity.Connectivity', Manager)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda peer: Client(a, peer).request('capabilities'), [b.id, c.id] * 2))
        assert results == [b.id, c.id] * 2
        assert len(created) == 1
    finally:
        a.connectivity = None


@pytest.mark.parametrize('host,address,family', [
    ('::ffff:127.0.0.1', '::ffff:127.0.0.1', socket.AF_INET6),
    ('blocked.example', '127.0.0.1', socket.AF_INET),
])
def test_direct_cidr_blocks_apply_before_dns_or_mapped_address_connect(mesh, monkeypatch, host, address, family):
    from agentmesh.network import peer_socket
    a, b, _ = mesh
    a.defense.block('cidr', '127.0.0.0/8')
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (family, socket.SOCK_STREAM, 6, '', (address, 7443))])
    def forbidden(*args, **kwargs):
        raise AssertionError('blocked destination socket created')
    monkeypatch.setattr(socket, 'socket', forbidden)
    with pytest.raises(Denied, match='blocked'):
        peer_socket(a, b.id, host, 7443)


def test_live_fetch_does_not_import_unrelated_withdrawal_history(mesh, monkeypatch):
    from agentmesh.crypto import sign
    from agentmesh.records import RETRACT_DOMAIN
    a, b, _ = mesh
    b.trust(a.card(port=7443), ['public'])
    history = [sign(a.identity.key, RETRACT_DOMAIN,
        {'version': 1, 'origin': a.id, 'target': f'{i:064x}'}) for i in range(300)]
    live_id = publish(a, 'live memory', audience=['@public'])
    live_obj = a.get(live_id, b.id)
    client = Client(b, a.id)
    monkeypatch.setattr(client, 'request', lambda op, **args:
        live_obj if op == 'get' else {'events': history, 'next': None})
    assert client.fetch(live_id) == live_id
    assert b.db.execute('SELECT count(*) FROM retractions').fetchone()[0] == 0
    assert b.inspect(live_id)['state'] == 'pending'
    assert b.db.execute('SELECT count(*) FROM transit_cache').fetchone()[0] == 1


def test_requested_withdrawal_after_long_history_blocks_import_and_reshare(mesh, monkeypatch):
    from agentmesh.crypto import sign
    from agentmesh.records import RETRACT_DOMAIN
    a, b, _ = mesh
    b.trust(a.card(port=7443), ['public'])
    history = [sign(a.identity.key, RETRACT_DOMAIN,
        {'version': 1, 'origin': a.id, 'target': f'{i:064x}'}) for i in range(300)]
    rid = publish(a, 'later withdrawn', audience=['@public'])
    obj = a.get(rid, b.id)
    history.append(a.retract(rid))
    client = Client(b, a.id)
    monkeypatch.setattr(client, 'request', lambda op, **args:
        obj if op == 'get' else {'events': history, 'next': None})
    with pytest.raises(Denied, match='withdrawn'):
        client.fetch(rid)
    assert b._row(rid) is None
    assert b._withdrawn(rid, a.id)
    assert not b.db.execute('SELECT 1 FROM transit_cache').fetchone()


def test_explicit_pre_dispatch_transport_refusal_falls_back(mesh, monkeypatch):
    from types import SimpleNamespace
    from agentmesh.network import PATH_PROTOCOL
    a,b,_=mesh;client=Client(a,b.id);calls=[]
    manager=SimpleNamespace(config={'relay_only':False},state={'peers':{}},
        request=lambda peer,op,args: calls.append(op) or {'ok':True,'result':{'id':'delivered'}})
    monkeypatch.setattr('agentmesh.connectivity.load_config',lambda node:{'relay_only':False})
    monkeypatch.setattr('agentmesh.network.connectivity_manager',lambda node,config:manager)
    response={'ok':False,'error':'transport_required','executed':False,
        'paths':{'protocol':PATH_PROTOCOL,'accepted':['relay'],'configured_ice':True,'relay_only':True}}
    monkeypatch.setattr(client,'_direct',lambda op,args:response)
    assert client.request('message',message={})=={'id':'delivered'}
    assert calls==['message']
    assert manager.state['path_decisions'][b.id]['operation_executed_on_tcp'] is False
    calls.clear();response['executed']=True
    with pytest.raises(Invalid):client.request('message',message={})
    assert not calls
    response.clear();response.update(ok=False,error='denied',detail='permission denied')
    with pytest.raises(Denied):client.request('message',message={})
    assert not calls
