"""Wire schemas. Identifiers cover all signed content, including access policy."""
from __future__ import annotations

import math
import re
import time

from .crypto import Invalid, Denied, valid_id


class SearchBudget(Denied):
    pass


def check_budget(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise SearchBudget('search time budget exceeded; no complete result available')

RECORD_DOMAIN = "agentmesh.record.v1"
RETRACT_DOMAIN = "agentmesh.retract.v1"
MESSAGE_DOMAIN = "agentmesh.message.v1"
MAX_TEXT_BYTES = 32 * 1024
MAX_PARENTS = 16
MAX_DEPTH = 64


def vector(values, dimensions: int) -> list[float]:
    if not isinstance(values, list) or len(values) != dimensions:
        raise Invalid("embedding dimension mismatch")
    if any(type(x) not in (int, float) or not math.isfinite(x) or abs(x) > 1e10 for x in values):
        raise Invalid("embedding must contain finite, bounded numbers")
    norm = math.sqrt(sum(x*x for x in values))
    if norm == 0:
        raise Invalid("zero embedding")
    return [float(x) for x in values]


def text(value):
    if not isinstance(value, str) or not value.strip() or len(value.encode()) > MAX_TEXT_BYTES:
        raise Invalid("text must be nonempty and at most 32 KiB")


def audience(value, *, private=False):
    if not isinstance(value, list) or len(value) > 256 or any(not isinstance(x, str) for x in value):
        raise Invalid("invalid audience")
    if not value and not private:
        raise Invalid("shared memory requires an explicit audience")
    if value != sorted(set(value)):
        raise Invalid("audience must be unique and sorted")
    if ("*" in value or "@public" in value) and value not in (["*"],["@public"]):
        raise Invalid("mesh audience cannot be mixed with named peers")
    if any(x not in ("*","@public") and not valid_id(x) for x in value):
        raise Invalid("audience must contain peer IDs or '*'")


def validate_record(body, model, dimensions, *, private=False):
    fields = {"version", "origin", "model", "vector", "text", "parents", "audience", "created_ms"}
    if set(body) != fields or type(body["version"]) is not int or body["version"] != 1:
        raise Invalid("invalid record schema")
    if not valid_id(body["origin"]):
        raise Invalid("invalid origin")
    if body["model"] != model:
        raise Invalid("embedding model mismatch")
    vector(body["vector"], dimensions)
    text(body["text"])
    audience(body["audience"], private=private)
    parents = body["parents"]
    if (not isinstance(parents, list) or len(parents) > MAX_PARENTS
            or any(not valid_id(x) for x in parents) or parents != sorted(set(parents))):
        raise Invalid("invalid parents")
    if type(body["created_ms"]) is not int or not 0 <= body["created_ms"] < 2**63:
        raise Invalid("invalid creation time")


def cosine(a, b):
    return sum(x*y for x, y in zip(a, b)) / math.sqrt(sum(x*x for x in a) * sum(y*y for y in b))


def terms(value):
    return re.findall(r"\w+", value.casefold())


def rank(records, query_vector, query_text, k, *, deadline=None):
    """Independent cosine and BM25 candidate lists, fused by reciprocal rank.

    Brute force deliberately establishes a reference baseline before routing
    or approximate indexes are introduced. Text candidates need not be vector
    candidates. Only records already authorized by the caller enter scoring.
    """
    vector_scores = {}
    if query_vector:
        for r in records:
            check_budget(deadline)
            vector_scores[r['id']] = cosine(query_vector,r['body']['vector'])
    lexical_scores = {}
    if query_text and records:
        docs = {}
        for r in records:
            check_budget(deadline)
            docs[r['id']] = terms(r['body']['text'])
        avglen = sum(map(len, docs.values())) / len(docs) or 1
        for term in set(terms(query_text)):
            df = sum(term in words for words in docs.values())
            idf = math.log(1 + (len(docs) - df + .5) / (df + .5))
            for rid, words in docs.items():
                check_budget(deadline)
                tf = words.count(term)
                if tf:
                    lexical_scores[rid] = lexical_scores.get(rid, 0) + idf * tf * 2.2 / (
                        tf + 1.2 * (.25 + .75 * len(words) / avglen))
    fused = {}
    for scores in (vector_scores, lexical_scores):
        for position, (rid, _) in enumerate(sorted(scores.items(), key=lambda x: (-x[1], x[0])), 1):
            fused[rid] = fused.get(rid, 0) + 1 / (60 + position)
    by_id = {r["id"]: r for r in records}
    check_budget(deadline)
    return [{"record": by_id[rid], "score": score,
             "cosine": vector_scores.get(rid), "bm25": lexical_scores.get(rid),
             "untrusted_data": True}
            for rid, score in sorted(fused.items(), key=lambda x: (-x[1], x[0]))[:k]]
