"""Run an actual three-process mesh lifecycle; no shared in-memory node state."""
from __future__ import annotations

import argparse
import json
import selectors
import subprocess
import sys
import tempfile
from pathlib import Path

from agentmesh.crypto import Denied
from agentmesh.node import Node
from agentmesh.network import Client

REPO = Path(__file__).resolve().parents[1]


class Process:
    def __init__(self, node, command="serve", extra=()):
        self.node = node
        self.process = subprocess.Popen(
            [sys.executable, "-m", "agentmesh", "--data", str(node.directory), command, "--port", "0", *extra],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=10):
                    raise RuntimeError("server did not become ready")
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("server failed: " + self.process.stderr.read())
            self.address = json.loads(line)["listening"]
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()


def run_demo(root):
    root = Path(root).resolve()
    nodes, processes = [], []
    try:
        for name in ("alice", "bob", "carol"):
            nodes.append(Node.create(root / name, model="demo-vector-v1", dimensions=3))
        for node in nodes:
            processes.append(Process(node))
        a, b, c = nodes

        def update_cards():
            for node in nodes:
                for process in processes:
                    if node.id != process.node.id:
                        node.trust(process.node.card(*process.address), ["read", "publish", "message"])

        update_cards()
        original_pids = [p.process.pid for p in processes]
        private = a.write_private("Research notes about resilient memory", [1, 0, 0])
        if Client(b, a.id).search(query_text="resilient")["results"]:
            raise AssertionError("private record escaped")
        record = a.publish(private, audience=["*"])
        found = Client(b, a.id).search(query_text="resilient")
        assert found["results"][0]["record"]["id"] == record
        Client(b, a.id).fetch(record)
        try:
            Client(c, b.id).request("get", id=record)
        except Denied:
            pass
        else:
            raise AssertionError("pending record escaped quarantine")
        b.approve(record)
        derived_private = b.write_private("Derived summary of resilient memory", [1, .1, 0], parents=[record])
        child = b.publish(derived_private, audience=["*"])
        for rid in (record, child):
            Client(c, b.id).fetch(rid)
            c.approve(rid)
        Client(b, a.id).send("We cached the research notes.")
        assert a.inbox()[0]["message"]["body"]["origin"] == b.id

        # Kill the publisher's listener. Bob must serve his own durable copy.
        processes[0].stop()
        assert Client(c, b.id).request("get", id=record)["id"] == record

        # Restart Bob in a new process; both original and derived data survive.
        processes[1].stop()
        processes[1] = Process(b)
        update_cards()
        for rid in (record, child):
            assert Client(c, b.id).request("get", id=rid)["id"] == rid

        # Offline Carol still has valid old data until a withdrawal reaches her.
        a.retract(record)
        assert c.get(record, c.id)["id"] == record
        processes[0] = Process(a)
        update_cards()
        Client(b, a.id).sync_retractions()
        Client(c, b.id).sync_retractions()
        for node in nodes:
            assert node.search(node.id, query_text="resilient")["results"] == []
            for rid in (record, child):
                try:
                    node.get(rid, node.id)
                except Denied:
                    pass
                else:
                    raise AssertionError("withdrawn lineage still served")
        return {"status": "passed", "initial_server_pids": original_pids,
                "restarted_bob_pid": processes[1].process.pid,
                "node_directories": [str(n.directory) for n in nodes],
                "checks": ["private write isolation", "TLS peer search", "quarantine before approval",
                           "cache serves while publisher offline", "cache survives process restart",
                           "signed direct message", "retraction relayed through cache",
                           "original and descendant rejected by search and direct lookup"],
                "partition_limit_demonstrated": "Carol serves old data until learning the retraction"}
    finally:
        for process in processes:
            process.stop()
        for node in nodes:
            node.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, help="retain demo state in a new directory")
    args = parser.parse_args()
    if args.data_root:
        result = run_demo(args.data_root)
    else:
        with tempfile.TemporaryDirectory(prefix="agentmesh-demo-") as root:
            result = run_demo(root)
            result["node_directories"] = "temporary demo directories removed after success"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
