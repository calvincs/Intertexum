"""Local, synthetic fixtures for evaluating agents through the real MCP adapter.

Start: ``python -m examples.agent_usability serve --data-root /tmp/mesh-eval``.
Discover: ``python -m examples.agent_usability tools --data-root /tmp/mesh-eval
--node alice``. Use ``call --help`` for tool calls, ``fixture --help`` for recipient
outages, and ``verify`` for independent read-only inspection. Stop serve with
SIGINT or SIGTERM. All generated node state and transcripts belong in a fresh
directory below /tmp. This is an owner-side evaluation tool, not an authorization
boundary against an agent with shell access.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import threading
import time
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentmesh.conversations import DeliveryWorker
from agentmesh.network import Server
from agentmesh.node import Node
from agentmesh.onboarding import private_write
from agentmesh.service import AttachedBackend, ControlServer, LocalBackend, runtime_lock


FORMAT = "intertexum-agent-usability-v1"
ALIASES = ("alice", "bob", "carol")
REPO = Path(__file__).resolve().parents[1]


def state_root(value: str | Path) -> Path:
    """Accept only evaluation paths below /tmp, never a source or real node path."""
    supplied = Path(value).absolute()
    root = supplied.resolve()
    if root == Path("/tmp") or not root.is_relative_to(Path("/tmp")):
        raise ValueError("evaluation state must be in a fresh directory below /tmp")
    if supplied != root:
        raise ValueError("evaluation paths must not contain symlinks or '..'")
    return root


def manifest(root: Path) -> dict[str, Any]:
    value = json.loads((root / "manifest.json").read_text())
    if value.get("format") != FORMAT or value.get("data_root") != str(root):
        raise ValueError("not a synthetic evaluation fixture")
    if set(value.get("nodes", {})) != set(ALIASES):
        raise ValueError("fixture aliases do not match")
    for alias in ALIASES:
        if value["nodes"][alias]["directory"] != str(root / alias):
            raise ValueError("fixture node paths do not match")
    return value


def append_log(root: Path, entry: dict[str, Any]) -> None:
    """Append a private, process-safe transcript without creating source artifacts."""
    import fcntl

    payload = (json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    fd = os.open(root / "transcript.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "ab") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(payload)
        stream.flush()


class NodeRuntime:
    """Run production listener, worker and local control on a synthetic node."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.port = 0
        self.node: Node | None = None
        self.stack: ExitStack | None = None

    def start(self) -> None:
        if self.node is not None:
            return
        stack = ExitStack()
        try:
            node = Node(self.directory)
            stack.callback(node.close)
            stack.enter_context(runtime_lock(self.directory))
            # Deliberately no connectivity.json: no discovery, STUN, TURN or ICE.
            if (self.directory / "connectivity.json").exists():
                raise ValueError("evaluation nodes must not have connectivity configuration")
            server = Server(node, "127.0.0.1", self.port)
            stack.callback(server.server_close)
            thread = server.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            path = self.directory / "control.sock"
            control = ControlServer(path, LocalBackend(node))
            stack.callback(path.unlink, missing_ok=True)
            stack.callback(control.server_close)
            thread = threading.Thread(
                target=control.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            thread.start()
            stack.callback(thread.join)
            stack.callback(control.shutdown)
            worker = DeliveryWorker(node)
            worker.start()
            stack.callback(worker.close)
            self.port = server.server_address[1]
            self.node = node
            self.stack = stack
        except BaseException:
            stack.close()
            raise

    def stop(self) -> None:
        if self.stack is not None:
            self.stack.close()
        self.stack = None
        self.node = None


class Fixture:
    """Owner-only, bounded fixture controls for three newly created identities."""

    def __init__(self, root: Path):
        self.root = root
        self.nodes: dict[str, NodeRuntime] = {}
        self.lock = threading.Lock()

    def __enter__(self) -> "Fixture":
        self.root = state_root(self.root)
        if self.root.exists() and any(self.root.iterdir()):
            raise ValueError("serve requires a new or empty data-root; never reuse real nodes")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        try:
            for alias in ALIASES:
                directory = self.root / alias
                node = Node.create(directory)
                node.close()
                private_write(directory / "policy.json", {
                    "mdns": False,
                    "manage_access": False,
                    **({"publish": False, "send": False} if alias == "carol" else {}),
                })
                runtime = NodeRuntime(directory)
                self.nodes[alias] = runtime
                runtime.start()
            for alias, runtime in self.nodes.items():
                for peer_alias, peer in self.nodes.items():
                    if peer_alias == alias:
                        continue
                    permissions = ["public"]
                    if {alias, peer_alias} == {"alice", "bob"}:
                        permissions.extend(["read", "publish", "message"])
                    runtime.node.trust(peer.node.card("127.0.0.1", peer.port), permissions)
            self.value = {
                "format": FORMAT,
                "data_root": str(self.root),
                "nodes": {
                    alias: {"id": runtime.node.id, "directory": str(runtime.directory),
                            "host": "127.0.0.1", "port": runtime.port}
                    for alias, runtime in self.nodes.items()
                },
                "permissions": {
                    "alice_bob": "mutual read/publish/message/public",
                    "carol": "public-only peer access; owner disables publish and send",
                    "all_nodes": "owner disables manage_access and mDNS",
                },
                "transport": "real pinned mutual TLS over loopback; no discovery or external networking",
                "status_note": "Manual peers work even though discovery readiness reports not_connected. Use peer_status and actual operations to verify access.",
                "loss_simulation": "--drop-response hides a completed call result from the tester; it does not kill or interrupt the operation",
            }
            private_write(self.root / "manifest.json", self.value)
            self.control = ControlServer(self.root / "fixture.sock", self)
            self.thread = threading.Thread(
                target=self.control.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            self.thread.start()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict) or set(request) != {"method", "node"}:
            raise ValueError("fixture requires method and node")
        method, alias = request["method"], request["node"]
        if method not in ("start", "stop", "status") or alias not in ALIASES:
            raise ValueError("only start/stop/status of synthetic alice/bob/carol is allowed")
        with self.lock:
            if method == "start":
                self.nodes[alias].start()
            elif method == "stop":
                self.nodes[alias].stop()
            result = {"node": alias, "running": self.nodes[alias].node is not None}
            append_log(self.root, {"time": time.time(), "operation": "fixture",
                                   "request": request, "response": result})
            return result

    def __exit__(self, *_: Any) -> None:
        if hasattr(self, "control"):
            self.control.shutdown()
            self.thread.join()
            self.control.server_close()
            (self.root / "fixture.sock").unlink(missing_ok=True)
        for runtime in reversed(list(self.nodes.values())):
            runtime.stop()


async def bridge(
    root: Path, alias: str, operation: str, *, tool: str | None = None,
    arguments: dict[str, Any] | None = None, uri: str | None = None,
    scenario: str = "unspecified", drop_response: bool = False,
) -> Any:
    """Open a fresh official MCP session; preserve its real structured result."""
    value = manifest(root)
    directory = value["nodes"][alias]["directory"]
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentmesh", "--data", directory, "mcp", "--attach"],
        cwd=str(REPO),
    )
    request = {"operation": operation, "node": alias}
    if operation == "call":
        request.update(tool=tool, arguments=arguments)
    elif operation == "resource":
        request["uri"] = uri
    started = time.monotonic()
    try:
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                if operation == "tools":
                    response = await session.list_tools()
                    output = [item.model_dump(mode="json", by_alias=True) for item in response.tools]
                elif operation == "resource":
                    response = await session.read_resource(uri)
                    output = response.model_dump(mode="json", by_alias=True)
                elif operation == "call":
                    response = await session.call_tool(tool, arguments or {})
                    output = response.structured_content
                else:
                    raise ValueError("unknown bridge operation")
                wire = response.model_dump(mode="json", by_alias=True)
    except Exception as exc:
        output = {"ok": False, "bridge_error": type(exc).__name__, "detail": str(exc)}
        append_log(root, {"time": time.time(), "scenario": scenario, "request": request,
                          "response": output, "elapsed_seconds": time.monotonic() - started})
        raise
    visible = ({"ok": False, "transport_response_lost": True,
                "detail": "Evaluation simulation: the call ran, but its response was hidden. Completion and effects are unknown to this caller; recover through normal tools."}
               if drop_response else output)
    append_log(root, {
        "time": time.time(), "scenario": scenario, "request": request,
        "response": output, "mcp_response": wire, "visible_response": visible,
        "request_bytes": len(json.dumps(request, separators=(",", ":")).encode()),
        "response_bytes": len(json.dumps(output, separators=(",", ":")).encode()),
        "mcp_response_bytes": len(json.dumps(wire, separators=(",", ":")).encode()),
        "display_bytes": len((json.dumps(visible, ensure_ascii=False, indent=2) + "\n").encode()),
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "response_intentionally_hidden": drop_response,
    })
    return visible


def verify(root: Path) -> dict[str, Any]:
    """Inspect durable state through read-only SQLite, independently of tool claims."""
    value = manifest(root)
    result = {}
    for alias in ALIASES:
        path = root / alias / "mesh.sqlite"
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            records = []
            for row in db.execute("SELECT id,state,wire FROM records ORDER BY id"):
                body = json.loads(row["wire"])["body"]
                records.append({
                    "id": row["id"], "state": row["state"], "origin": body["origin"],
                    "audience": body["audience"],
                    "text_sha256": hashlib.sha256(body["text"].encode()).hexdigest(),
                })
            receipts = []
            if "tool_receipts" in tables:
                for row in db.execute("SELECT id,fingerprint,response FROM tool_receipts ORDER BY id"):
                    response = json.loads(row["response"]) if row["response"] else None
                    receipts.append({"key": row["id"], "fingerprint": row["fingerprint"],
                                     "state": "completed" if response else "incomplete",
                                     "ok": response.get("ok") if response else None,
                                     "error_code": (response.get("error") or {}).get("code") if response else None})
            messages = []
            for row in db.execute("SELECT id,wire FROM messages ORDER BY id"):
                body = json.loads(row["wire"])["body"]
                messages.append({"id": row["id"], "origin": body["origin"],
                                 "text_sha256": hashlib.sha256(body["text"].encode()).hexdigest()})
            result[alias] = {
                "id": value["nodes"][alias]["id"],
                "record_counts": {state: sum(r["state"] == state for r in records)
                                  for state in ("private", "pending", "accepted")},
                "records": records, "inbox_count": len(messages), "messages": messages,
                "outbox": [dict(r) for r in db.execute("SELECT id,peer,state,attempts,error FROM outbox ORDER BY id")],
                "receipts": receipts,
                "retractions": [dict(r) for r in db.execute("SELECT id,origin,target FROM retractions ORDER BY id")],
                "receipt_epoch": db.execute("SELECT value FROM lifecycle WHERE key='receipt_epoch'").fetchone()[0],
            }
    return {"format": FORMAT, "read_only": True,
            "snapshot_note": "Each node is read consistently; snapshots across nodes are not atomic. Verify after outstanding calls and delivery have settled.",
            "nodes": result}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("serve", "tools", "call", "resource", "fixture", "verify"):
        item = sub.add_parser(command)
        item.add_argument("--data-root", type=state_root, required=True)
        if command in ("tools", "call", "resource", "fixture"):
            item.add_argument("--node", choices=ALIASES, required=True)
        if command in ("tools", "call", "resource"):
            item.add_argument("--scenario", default="unspecified", help="transcript label")
        if command == "call":
            item.add_argument("--tool", required=True)
            item.add_argument("--arguments", type=json.loads, default={})
            item.add_argument("--drop-response", action="store_true",
                              help="hide the completed response; retain it privately in the transcript")
        elif command == "resource":
            item.add_argument("--uri", required=True)
        elif command == "fixture":
            item.add_argument("--action", choices=("start", "stop", "status"), required=True)
    args = parser.parse_args()
    if args.command == "serve":
        stop = threading.Event()
        previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            with Fixture(args.data_root) as fixture:
                print(json.dumps(fixture.value), flush=True)
                stop.wait()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return
    if args.command == "verify":
        output = verify(args.data_root)
    elif args.command == "fixture":
        manifest(args.data_root)
        output = AttachedBackend(args.data_root, args.data_root / "fixture.sock").dispatch(
            {"method": args.action, "node": args.node}
        )
    else:
        output = asyncio.run(bridge(
            args.data_root, args.node, args.command,
            tool=getattr(args, "tool", None), arguments=getattr(args, "arguments", None),
            uri=getattr(args, "uri", None), scenario=args.scenario,
            drop_response=getattr(args, "drop_response", False),
        ))
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
