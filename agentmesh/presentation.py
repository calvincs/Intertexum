"""Concise local views of records; signed storage and peer RPCs stay intact.

The agent boundary screens the original response before calling these helpers.
These are display projections, never replacements for signature verification.
"""
from copy import deepcopy

from .crypto import Invalid


def record_view(record: dict, *, local_state: str) -> dict:
    """Keep content, provenance and visibility without embedding or wire details."""
    body = record["body"]
    return {
        "id": record["id"],
        "text": body["text"],
        "origin": body["origin"],
        "audience": list(body["audience"]),
        "parents": list(body["parents"]),
        "created_ms": body["created_ms"],
        "local_state": local_state,
        "untrusted_data": True,
    }


def search_view(result: dict, node) -> dict:
    """Project already-checked hits and preserve all coverage/holder metadata."""
    output = {key: deepcopy(value) for key, value in result.items() if key != "results"}
    hits = []
    for hit in result["results"]:
        record = hit["record"]
        try:
            state = node.inspect(record["id"])["state"]
        except Invalid:
            state = "not_stored"
        summary = record_view(record, local_state=state)
        if state == "not_stored":
            summary["next_action"] = "Fetch this ID from a responding peer before local inspection or approval."
        for key in ("score", "cosine", "bm25", "holders"):
            if key in hit:
                summary[key] = deepcopy(hit[key])
        hits.append(summary)
    output.update(results=hits, view="summary", untrusted_data=True)
    return output


def inspect_view(result: dict) -> dict:
    inspected = result["record"]
    return {
        "record": record_view(inspected["record"], local_state=inspected["state"]),
        "view": "summary",
        "untrusted_data": True,
    }


def inbox_view(page: dict) -> dict:
    """Preserve stable cursors, reply offers and screened placeholders verbatim."""
    output = {key: deepcopy(value) for key, value in page.items() if key != "messages"}
    messages = []
    for entry in page["messages"]:
        if entry.get("withheld"):
            messages.append(deepcopy(entry))
            continue
        message = entry["message"]
        body = message["body"]
        summary = {key: deepcopy(value) for key, value in entry.items() if key != "message"}
        summary.update(
            id=message["id"], origin=body["origin"], recipient=body["recipient"],
            text=body["text"], untrusted_data=True,
        )
        for key in ("expires", "reply_to"):
            if key in body:
                summary[key] = body[key]
        messages.append(summary)
    output.update(messages=messages, view="summary", untrusted_data=True)
    return output
