import pytest

from agentmesh.node import Node


@pytest.fixture
def mesh(tmp_path):
    nodes = [Node.create(tmp_path / name, model="test-v1", dimensions=3) for name in ("alice", "bob", "carol")]
    for node in nodes:
        for peer in nodes:
            if peer != node:
                node.trust(peer.card(port=7443), ["read", "publish", "message"])
    yield nodes
    for node in nodes:
        node.close()


def publish(node, text="shared research", vec=None, audience=None, parents=()):
    private = node.write_private(text, vec or [1., 0., 0.], parents=parents)
    return node.publish(private, audience=["*"] if audience is None else audience)
