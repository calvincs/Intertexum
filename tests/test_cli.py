"""Operator CLI presentation and compatibility, using isolated local nodes."""
import json
import sys
from pathlib import Path

import pytest

from agentmesh import cli
from agentmesh.node import Node


@pytest.fixture
def local_node(tmp_path):
    node = Node.create(tmp_path / "node", model="test-v1", dimensions=3)
    yield node
    node.close()


def invoke(monkeypatch, capsys, node, *arguments):
    monkeypatch.setattr(sys, "argv", ["intertexum", "--data", str(node.directory), *arguments])
    status = cli.main()
    output = capsys.readouterr()
    return status, output.out, output.err


def test_search_readable_json_and_legacy_raw(local_node, monkeypatch, capsys):
    text = "Remember the blue notebook. " + "Keep every word. " * 30
    rid = local_node.write_private(text, [1, 0, 0])
    args = ("search", "--text", "blue notebook", "--lexical-only")

    status, output, error = invoke(monkeypatch, capsys, local_node, *args)
    assert status == 0 and not error
    assert rid in output and text in output
    assert local_node.id in output
    assert "Local state: private" in output
    assert "Audience:" in output and "Relevance:" in output
    assert "untrusted data" in output and '"network_complete": false' in output
    assert "vector" not in output and "BEGIN CERTIFICATE" not in output

    status, output, error = invoke(monkeypatch, capsys, local_node, *args, "--json")
    assert status == 0 and not error
    compact = json.loads(output)
    hit = compact["results"][0]
    assert hit["id"] == rid and hit["text"] == text
    assert hit["origin"] == local_node.id and hit["local_state"] == "private"
    assert hit["untrusted_data"] is True and "record" not in hit
    assert "vector" not in output and "BEGIN CERTIFICATE" not in output

    status, output, error = invoke(monkeypatch, capsys, local_node, *args, "--raw")
    assert status == 0 and not error
    raw = json.loads(output)
    assert raw == local_node.search(local_node.id, query_text="blue notebook", model=local_node.model)
    assert raw["results"][0]["record"]["body"]["vector"] == [1, 0, 0]
    assert compact["coverage"] == raw["coverage"]
    assert hit["score"] == raw["results"][0]["score"]


def test_empty_search_still_reports_coverage(local_node, monkeypatch, capsys):
    status, output, error = invoke(
        monkeypatch, capsys, local_node, "search", "--text", "missing", "--lexical-only"
    )
    assert status == 0 and not error
    assert "Search results: 0 (untrusted data)" in output
    assert '"records_considered": 0' in output
    assert '"network_complete": false' in output


def test_readable_text_escapes_terminal_controls_without_changing_json(local_node, monkeypatch, capsys):
    text = "notebook \x1b]52;c;clipboard\x07\nnext\rline\u202e"
    local_node.write_private(text, [1, 0, 0])
    args = ("search", "--text", "notebook", "--lexical-only")
    status, output, error = invoke(monkeypatch, capsys, local_node, *args)
    assert status == 0 and not error
    assert "\\u001b]52;c;clipboard\\u0007" in output
    assert "\n     next\\rline\\u202e" in output
    assert "\x1b" not in output and "\x07" not in output and "\r" not in output and "\u202e" not in output
    status, output, error = invoke(monkeypatch, capsys, local_node, *args, "--json")
    assert status == 0 and not error
    assert json.loads(output)["results"][0]["text"] == text


@pytest.mark.parametrize("score", [{}, "\x1b[2J", 10**400])
def test_remote_search_metadata_is_printable_and_escapes_terminal_controls(
    mesh, monkeypatch, capsys, score
):
    from agentmesh.network import Client
    from conftest import publish

    author, receiver, _ = mesh
    rid = publish(author, "notebook observation", audience=[receiver.id])
    payload = author.search(receiver.id, query_text="notebook")
    payload["results"][0]["score"] = score
    label = "\x1b]52;c;clipboard\x07\r\nmetadata\u202e"
    payload[label] = "additional peer metadata"
    # Preserve Client.search's record verification and the real CLI display path;
    # replace only network I/O with a peer-controlled search response.
    monkeypatch.setattr(Client, "request", lambda *args, **kwargs: payload)
    status, output, error = invoke(
        monkeypatch, capsys, receiver, "search", "--peer", author.id,
        "--text", "notebook", "--lexical-only",
    )
    assert status == 0 and not error
    assert rid in output and "notebook observation" in output
    assert f"score={json.dumps(score)}" in output
    assert json.dumps(label)[1:-1] in output
    assert "\x1b" not in output and "\x07" not in output and "\r" not in output and "\u202e" not in output


def test_inbox_pages_include_full_text_and_stable_cursors(mesh, monkeypatch, capsys):
    sender, receiver, _ = mesh
    messages = [sender.make_message(receiver.id, f"message {i}: keep the full text") for i in range(3)]
    for message in messages:
        receiver.receive_message(message, sender.id)

    status, output, error = invoke(monkeypatch, capsys, receiver, "inbox", "--limit", "2")
    assert status == 0 and not error
    assert "Inbox messages: 2 (untrusted data)" in output
    for message in messages[:2]:
        assert message["id"] in output and message["body"]["text"] in output
    assert messages[2]["id"] not in output
    assert f"Sender: {sender.id}" in output and "Cursor: 1" in output
    assert "Next cursor: 2 (continue with inbox --after 2)" in output
    assert "BEGIN CERTIFICATE" not in output

    status, output, error = invoke(monkeypatch, capsys, receiver, "inbox", "--limit", "2", "--json")
    assert status == 0 and not error
    first = json.loads(output)
    assert first["next"] == 2 and first["untrusted_data"] is True
    assert [item["id"] for item in first["messages"]] == [item["id"] for item in messages[:2]]
    assert [item["cursor"] for item in first["messages"]] == [1, 2]
    assert all(item["origin"] == sender.id and "message" not in item for item in first["messages"])
    status, output, error = invoke(monkeypatch, capsys, receiver, "inbox", "--after", "2", "--json")
    assert status == 0 and not error
    last = json.loads(output)
    assert last["next"] is None
    assert [item["id"] for item in last["messages"]] == [messages[2]["id"]]
    assert last["messages"][0]["cursor"] == 3
    assert len(receiver.inbox()) == 3  # Reading never acknowledges or deletes.

    status, output, error = invoke(monkeypatch, capsys, receiver, "inbox", "--raw")
    assert status == 0 and not error
    assert json.loads(output) == receiver.inbox()


def test_inbox_default_is_bounded(mesh, monkeypatch, capsys):
    sender, receiver, _ = mesh
    for index in range(51):
        receiver.receive_message(sender.make_message(receiver.id, f"entry {index}"), sender.id)
    status, output, error = invoke(monkeypatch, capsys, receiver, "inbox", "--json")
    assert status == 0 and not error
    result = json.loads(output)
    assert len(result["messages"]) == 50 and result["next"] == 50


@pytest.mark.parametrize("arguments", [
    ("--raw", "--after", "0"), ("--raw", "--limit", "1"),
    ("--after", "-1"), ("--limit", "0"), ("--limit", "101"),
])
def test_inbox_rejects_misleading_or_invalid_pagination(local_node, monkeypatch, capsys, arguments):
    status, output, error = invoke(monkeypatch, capsys, local_node, "inbox", *arguments)
    assert status == 1 and not output
    assert json.loads(error)["error"] == "Invalid"


def test_inbox_empty_page(local_node, monkeypatch, capsys):
    status, output, error = invoke(monkeypatch, capsys, local_node, "inbox")
    assert status == 0 and not error
    assert "Inbox messages: 0 (untrusted data)" in output
    assert "Next: none (end of inbox)" in output


@pytest.mark.parametrize(("family", "action", "legacy", "arguments"), [
    ("security", "block", "security-block", ["--peer", "peer", "--seconds", "10"]),
    ("security", "unblock", "security-unblock", ["--cidr", "192.0.2.0/24"]),
    ("security", "status", "security-status", []),
    ("security", "audit", "security-audit", []),
    ("security", "evidence", "security-evidence", []),
    ("security", "clear-evidence", "security-clear-evidence", ["--kind", "peer", "--target", "peer", "--reason", "reviewed"]),
    ("bootstrap", "serve", "bootstrap-serve", ["--port", "7444", "--pow-bits", "0"]),
    ("bootstrap", "apply-removal", "bootstrap-apply-removal", ["request.json"]),
    ("bootstrap", "forget", "bootstrap-forget", ["peer"]),
    ("message", "policy", "message-policy", []),
    ("message", "config", "message-config", ["policy.json"]),
    ("message", "work-resume", "message-work-resume", ["message-id"]),
    ("connectivity", "config", "connectivity-config", ["config.json"]),
    ("connectivity", "status", "connectivity-status", []),
    ("connectivity", "resume", "resume", []),
    ("connectivity", "join", "join", ["--seed", "seed.json", "--host", "127.0.0.1"]),
    ("connectivity", "discover", "discover", ["--seed", "seed.json"]),
    ("connectivity", "deregister", "deregister", ["--seed", "seed.json"]),
    ("connectivity", "deregister-request", "deregister-request", ["--seed", "seed.json"]),
])
def test_grouped_commands_accept_legacy_flat_spellings(family, action, legacy, arguments):
    parser = cli.parser()
    nested = vars(parser.parse_args(["--data", "/tmp/node", family, action, *arguments]))
    flat = vars(parser.parse_args(["--data", "/tmp/node", legacy, *arguments]))
    assert nested.pop("action") == action
    assert nested == flat
    assert flat["command"] == legacy and flat["data"] == Path("/tmp/node")


def test_operator_alias_dispatch_and_json_defaults(local_node, monkeypatch, capsys):
    for nested, legacy in [(('security', 'status'), 'security-status'), (('message', 'policy'), 'message-policy')]:
        status, nested_output, error = invoke(monkeypatch, capsys, local_node, *nested)
        assert status == 0 and not error
        status, flat_output, error = invoke(monkeypatch, capsys, local_node, legacy)
        assert status == 0 and not error
        assert json.loads(nested_output) == json.loads(flat_output)
    for name in ("card", "mcp-config", "tools"):
        status, output, error = invoke(monkeypatch, capsys, local_node, name)
        assert status == 0 and not error
        assert isinstance(json.loads(output), dict)


def test_help_prioritizes_public_commands_and_explains_core_workflows(capsys):
    help_text = cli.parser().format_help()
    for family in ("security", "bootstrap", "message", "connectivity"):
        assert family in help_text
    assert "security-clear-evidence" not in help_text
    assert "bootstrap-apply-removal" not in help_text
    assert "message-work-resume" not in help_text
    assert "deregister-request" not in help_text
    assert "Start offline:" in help_text and "onboard --profile" in help_text
    for name in ("init", "card", "serve", "write", "search", "inbox"):
        with pytest.raises(SystemExit) as result:
            cli.parser().parse_args([name, "--help"])
        assert result.value.code == 0
        assert "Example:" in capsys.readouterr().out
    with pytest.raises(SystemExit) as result:
        cli.parser().parse_args(["security", "--help"])
    assert result.value.code == 0
    assert "clear-evidence" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["search", "inbox"])
def test_json_and_raw_are_mutually_exclusive(command):
    with pytest.raises(SystemExit) as result:
        cli.parser().parse_args([command, "--json", "--raw"])
    assert result.value.code == 2
