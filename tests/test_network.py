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
