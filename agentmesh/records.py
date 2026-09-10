"""Wire schemas. Identifiers cover all signed content, including access policy."""
from __future__ import annotations

import math
import re
import time
from collections import Counter

import numpy as np

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


class SearchIndex:
    """Derived retrieval data, never an authorization or verification cache.

    Posting lists avoid tokenizing the corpus per request. Normalized vectors
    live in a compact matrix, so scoring does not parse or verify signed wires.
    Callers must authorize every selected record against current durable state.
    """

    def __init__(self, dimensions):
        self.dimensions = dimensions
        self.entries = {}
        self.postings = {}
        self.lengths = {}
        self.tokens = {}
        self.slots = {}
        self.free = []
        self.matrix = np.zeros((0, dimensions), dtype=np.float64)

    def discard(self, rid):
        if rid not in self.entries:
            return
        for term in self.tokens.pop(rid):
            posting = self.postings[term]
            del posting[rid]
            if not posting:
                del self.postings[term]
        del self.lengths[rid]
        del self.entries[rid]
        self.free.append(self.slots.pop(rid))

    def put(self, rid, body, state):
        self.discard(rid)
        if not self.free:
            start = len(self.matrix)
            self.matrix = np.concatenate((self.matrix, np.zeros((256, self.dimensions))))
            self.free.extend(range(start + 255, start - 1, -1))
        slot = self.free.pop()
        values = np.asarray(body['vector'], dtype=np.float64)
        self.matrix[slot] = values / np.linalg.norm(values)
        self.slots[rid] = slot
        self.entries[rid] = (state, body['origin'], tuple(body['audience']))
        words = Counter(terms(body['text']))
        self.tokens[rid] = set(words)
        self.lengths[rid] = sum(words.values())
        for term, frequency in words.items():
            self.postings.setdefault(term, {})[rid] = frequency

    def candidates(self, eligible, query_vector, query_text, limit, *, deadline=None):
        """Fuse independent lexical/vector lists before the authorization bound."""
        check_budget(deadline)
        if not eligible:
            return [], False
        ids = sorted(eligible)
        fused = {}
        if query_vector is not None:
            values = np.asarray(query_vector, dtype=np.float64)
            values /= np.linalg.norm(values)
            # einsum avoids a BLAS thread pool for this small, bounded matrix.
            scores = np.einsum('ij,j->i', self.matrix, values)
            ordered = sorted(ids, key=lambda rid: (-scores[self.slots[rid]], rid))
            for position, rid in enumerate(ordered, 1):
                fused[rid] = 1 / (60 + position)
        lexical = {}
        avglen = sum(self.lengths[rid] for rid in ids) / len(ids) or 1
        for term in set(terms(query_text)):
            check_budget(deadline)
            posting = self.postings.get(term, {})
            matching = eligible.intersection(posting)
            df = len(matching)
            idf = math.log(1 + (len(ids) - df + .5) / (df + .5))
            for rid in matching:
                tf = posting[rid]
                lexical[rid] = lexical.get(rid, 0) + idf * tf * 2.2 / (
                    tf + 1.2 * (.25 + .75 * self.lengths[rid] / avglen))
        for position, (rid, _) in enumerate(sorted(lexical.items(), key=lambda item: (-item[1], item[0])), 1):
            fused[rid] = fused.get(rid, 0) + 1 / (60 + position)
        check_budget(deadline)
        ordered = sorted(fused, key=lambda rid: (-fused[rid], rid))
        return ordered[:limit], len(ordered) > limit


def rank(records, query_vector, query_text, k, *, deadline=None):
    """Independent cosine and BM25 candidate lists, fused by reciprocal rank.

    Re-rank the bounded, fully authorized candidates selected by SearchIndex.
    Text candidates need not be vector candidates. Computing final scores only
    from authorized records keeps hidden text out of returned scoring statistics.
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
