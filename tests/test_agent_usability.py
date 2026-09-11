"""Check that the agent evaluation fixture exercises real MCP and durable effects."""
import asyncio
import json
import time

import pytest

from examples.agent_usability import Fixture, bridge, state_root, verify


def test_fixture_mcp_recovery(tmp_path):
    async def scenario(root, fixture):
        async def call(node, tool, arguments, **options):
            result = await bridge(root, node, "call", tool=tool, arguments=arguments,
                                  scenario="fixture-integration", **options)
            if not options.get("drop_response"):
                assert result["ok"], result
            return result

        alice = fixture.value["nodes"]["alice"]["id"]
        bob = fixture.value["nodes"]["bob"]["id"]
        write_args = {"text": "Calibration uses green lamps.", "idempotency_key": "e0:private"}
        hidden = await call("alice", "mesh_write", write_args, drop_response=True)
        assert hidden["transport_response_lost"] and "result" not in hidden
        assert verify(root)["nodes"]["alice"]["record_counts"]["private"] == 1
        recovered = await call("alice", "mesh_write", write_args)
        private_id = recovered["result"]["id"]
        again = await call("alice", "mesh_write", write_args)
        assert recovered == again
        local = await call("alice", "mesh_search", {"text": "green calibration"})
        assert len(local["result"]["results"]) == 1
        remote = await call("bob", "mesh_search", {"text": "green calibration", "peer": alice})
        assert remote["result"]["results"] == []

        publication = await call("alice", "mesh_publish", {
            "id": private_id, "audience": [bob], "idempotency_key": "e0:publish",
        })
        shared_id = publication["result"]["id"]
        denied = await call("carol", "mesh_search", {"text": "green calibration", "peer": alice})
        assert denied["result"]["results"] == []
        await call("bob", "mesh_fetch", {"id": shared_id, "peer": alice, "idempotency_key": "e0:fetch"})
        assert verify(root)["nodes"]["bob"]["record_counts"]["pending"] == 1
        await call("bob", "mesh_inspect", {"id": shared_id})
        await call("bob", "mesh_approve", {"id": shared_id, "idempotency_key": "e0:approve"})
        assert verify(root)["nodes"]["bob"]["record_counts"]["accepted"] == 1

        await call("alice", "mesh_send", {
            "peer": bob, "text": "Calibration is ready.", "idempotency_key": "e0:direct",
        })
        fixture.dispatch({"method": "stop", "node": "bob"})
        queued = await call("alice", "mesh_queue_message", {
            "peer": bob, "content": "Resume calibration after the outage.", "idempotency_key": "e0:queued",
        })
        assert queued["result"]["id"]
        assert verify(root)["nodes"]["bob"]["inbox_count"] == 1
        fixture.dispatch({"method": "start", "node": "bob"})
        deadline = time.monotonic() + 15
        while verify(root)["nodes"]["bob"]["inbox_count"] != 2:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.2)
        inbox = await call("bob", "mesh_inbox", {})
        assert len(inbox["result"]["messages"]) == 2
        tools = await bridge(root, "carol", "tools", scenario="fixture-integration")
        assert not {"mesh_send", "mesh_publish", "mesh_authorize"} & {item["name"] for item in tools}
        restriction = await bridge(root, "carol", "call", tool="mesh_send", arguments={
            "peer": alice, "text": "This must stay denied.", "idempotency_key": "e0:denied",
        }, scenario="fixture-integration")
        assert not restriction["ok"] and restriction["error"]["code"] == "denied"
        durable = verify(root)["nodes"]
        assert durable["alice"]["inbox_count"] == 0
        assert len([r for r in durable["alice"]["receipts"] if r["key"] == "mcp:e0:private"]) == 1
        assert durable["alice"]["outbox"][0]["state"] == "delivered"
        logs = [json.loads(line) for line in (root / "transcript.jsonl").read_text().splitlines()]
        lost = next(entry for entry in logs if entry.get("response_intentionally_hidden"))
        assert lost["response"]["result"]["id"] == private_id
        assert "result" not in lost["visible_response"]
        assert lost["mcp_response"]["structuredContent"] == lost["response"]
        assert lost["response_bytes"] > 0 and lost["elapsed_seconds"] > 0

    with Fixture(tmp_path / "fixture") as fixture:
        asyncio.run(scenario(tmp_path / "fixture", fixture))
    assert not (tmp_path / "fixture" / "fixture.sock").exists()
    assert all(not (tmp_path / "fixture" / alias / "control.sock").exists()
               for alias in ("alice", "bob", "carol"))


def test_fixture_refuses_existing_state(tmp_path):
    (tmp_path / "keep.txt").write_text("unrelated state")
    with pytest.raises(ValueError, match="new or empty"):
        with Fixture(tmp_path):
            pass
    assert (tmp_path / "keep.txt").read_text() == "unrelated state"
    with pytest.raises(ValueError, match="below /tmp"):
        state_root("/home/example/real-node")
