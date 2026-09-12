"""Durable node state. Every peer has its own database and local policy.

All serving paths use the same recursive authorization function. Receiving a
valid signature does not approve content. Neither referrals nor self-reported
reputation grant permissions.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from collections import OrderedDict
from copy import deepcopy

from .crypto import Identity, Invalid, Denied, canonical, decode, certificate, public_id, sign, verify, valid_id
from .records import (RECORD_DOMAIN, RETRACT_DOMAIN, MESSAGE_DOMAIN, MAX_DEPTH, SearchBudget,
                      validate_record, vector, text, rank, SearchIndex, check_budget)

PERMISSIONS = {"read", "publish", "message", "public"}
SEARCH_LIMIT = 20
MAX_RECORDS = 10000
MAX_EVENTS = 10000
MAX_UNKNOWN_RETRACTIONS_PER_ORIGIN = 256
MAX_UNKNOWN_RETRACTIONS_PER_SUPPLIER = 512
SEARCH_CANDIDATES = 256
VERIFICATION_CACHE_BYTES = 16 * 1024 * 1024


class Node:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.identity = Identity(self.directory)
        self.id = self.identity.id
        self.connectivity = None
        from .defense import Defense
        self.defense = Defense(self.directory)
        config = decode((self.directory / "config.json").read_bytes())
        self.model, self.dimensions = config["model"], config["dimensions"]
        self.lock = threading.RLock()
        self.active_mutations=set()
        self._verified_wires = OrderedDict()
        self._verified_bytes = 0
        self._search_index = None
        self._indexed_versions = {}
        self._search_data_version = None
        self._search_epoch = 0
        self._search_rebuilding = False
        self.db = sqlite3.connect(self.directory / "mesh.sqlite", check_same_thread=False,
                                  isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS admissions (peer TEXT PRIMARY KEY, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS peers (
                id TEXT PRIMARY KEY, card TEXT NOT NULL, permissions TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY, wire TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('private','pending','accepted')));
            CREATE TABLE IF NOT EXISTS retractions (
                id TEXT PRIMARY KEY, origin TEXT NOT NULL, target TEXT NOT NULL,
                wire TEXT NOT NULL, UNIQUE(origin,target));
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, wire TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS retraction_sources (
                id TEXT PRIMARY KEY, supplier TEXT NOT NULL, allocation TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS retraction_allocations ON retraction_sources(allocation,supplier);
            CREATE TABLE IF NOT EXISTS published_private (id TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS search_dirty (id TEXT PRIMARY KEY);
            CREATE TRIGGER IF NOT EXISTS records_search_insert AFTER INSERT ON records BEGIN
                INSERT OR IGNORE INTO search_dirty VALUES(NEW.id);
            END;
            CREATE TRIGGER IF NOT EXISTS records_search_update AFTER UPDATE ON records BEGIN
                INSERT OR IGNORE INTO search_dirty VALUES(OLD.id);
                INSERT OR IGNORE INTO search_dirty VALUES(NEW.id);
            END;
            CREATE TRIGGER IF NOT EXISTS records_search_delete AFTER DELETE ON records BEGIN
                INSERT OR IGNORE INTO search_dirty VALUES(OLD.id);
            END;
        """)

        from .lifecycle import schema as lifecycle_schema
        from .openmesh import schema as open_schema
        lifecycle_schema(self);open_schema(self)
        from .conversations import schema as conversation_schema
        conversation_schema(self)
        from .message_work import schema as message_schema
        message_schema(self)
        from .cache import schema as cache_schema
        cache_schema(self)
        from .routing import schema as routing_schema
        routing_schema(self)
        from .source_policy import schema as source_schema
        source_schema(self)
        self._migrate_retractions()
        # Rebuild once during startup, outside a remote request's time budget.
        self._refresh_search_index()

    @classmethod
    def create(cls, directory, *, model=None, dimensions=None):
        if model is None and dimensions is None:
            from .embedding import profile
            selected = profile()
            model, dimensions = selected['id'], selected['spec']['dimensions']
        if not isinstance(model, str) or not model.strip() or len(model) > 200:
            raise Invalid("an embedding model identifier is required")
        if type(dimensions) is not int or not 1 <= dimensions <= 4096:
            raise Invalid("dimensions must be between 1 and 4096")
        Identity.create(Path(directory))
        (Path(directory) / "config.json").write_bytes(canonical({"model": model, "dimensions": dimensions}))
        return cls(directory)

    @contextmanager
    def transaction(self):
        with self.lock:
            search_epoch = self._search_epoch
            self.db.execute('SAVEPOINT node_change')
            try:
                yield
                self.db.execute('RELEASE node_change')
            except BaseException:
                self.db.execute('ROLLBACK TO node_change')
                self.db.execute('RELEASE node_change')
                # A nested read may have indexed uncommitted mutations.
                if self._search_epoch != search_epoch:
                    self._search_index = None
                    self._refresh_search_index()
                raise

    def close(self):
        if self.connectivity:
            self.connectivity.close()
            self.connectivity=None
        with self.lock:
            self.db.close()
            self.defense.close()

    def capability(self, name):
        from .onboarding import require
        require(self,name)

    def write_text(self, content, *, parents=()):
        self.capability('write')
        from .embedding import encode_for
        return self.write_private(content, encode_for(self,content), parents=parents)

    def search_text(self, content, *, k=10):
        self.capability('search')
        from .embedding import encode_for
        return self.search(self.id,query_text=content,query_vector=encode_for(self,content,query=True),
                           model=self.model,k=k)

    def card(self, host="127.0.0.1", port=0):
        # Endpoint is a local operator hint, not an authenticated discovery claim.
        return {"id": self.id, "certificate": self.identity.pem, "host": host, "port": port}

    def trust(self, card, permissions):
        if not isinstance(card, dict) or set(card) != {"id", "certificate", "host", "port"}:
            raise Invalid("invalid peer card")
        cert = certificate(card["certificate"])
        if public_id(cert.public_key()) != card["id"]:
            raise Invalid("peer ID does not match certificate")
        if (not isinstance(card["host"], str) or not card["host"] or len(card["host"]) > 253
                or type(card["port"]) is not int or not 1 <= card["port"] <= 65535):
            raise Invalid("invalid peer endpoint")
        if not isinstance(permissions, (list, set, tuple)) or not set(permissions) <= PERMISSIONS:
            raise Invalid("unknown permission")
        if card["id"] == self.id:
            raise Invalid("cannot add self as a remote peer")
        with self.transaction():
            self.db.execute('DELETE FROM admissions WHERE peer=?',(card['id'],))
            # Trust is a LOCAL operator action; there is no network trust endpoint.
            self.db.execute("""INSERT INTO peers(id,card,permissions,blocked) VALUES(?,?,?,0)
                ON CONFLICT(id) DO UPDATE SET card=excluded.card,
                permissions=excluded.permissions, blocked=0""",
                (card["id"], canonical(card).decode(), json.dumps(sorted(set(permissions)))))

    def peers(self):
        from .openmesh import effective
        with self.lock:
            result=[]
            for row in self.db.execute("SELECT * FROM peers ORDER BY id"):
                grant=self.db.execute('SELECT expires FROM grants WHERE peer=?',(row['id'],)).fetchone()
                admission=self.db.execute('SELECT expires FROM admissions WHERE peer=?',(row['id'],)).fetchone()
                result.append({'card':decode(row['card'].encode()),
                    'permissions':sorted(effective(self,row['id'],json.loads(row['permissions']))),
                    'blocked':bool(row['blocked']),
                    'grant_expires':grant[0] if grant else None,
                    'membership_expires':admission[0] if admission else None})
            return result

    def peer(self, peer_id, *, allow_blocked=False):
        with self.lock:
            row = self.db.execute("SELECT * FROM peers WHERE id=?", (peer_id,)).fetchone()
            admission=self.db.execute('SELECT expires FROM admissions WHERE peer=?',(peer_id,)).fetchone()
            if not allow_blocked and admission and admission[0]<=time.time():raise Denied('membership_expired')
            if row is None or (row["blocked"] and not allow_blocked):
                raise Denied("peer is unknown or blocked")
            from .openmesh import effective
            return {"card": decode(row["card"].encode()), "permissions": sorted(effective(self,peer_id,json.loads(row["permissions"]))),
                    "blocked": bool(row["blocked"])}

    def require(self, peer_id, permission):
        if peer_id!=self.id:
            allowed=self.peer(peer_id)['permissions']
            if permission not in allowed and not (permission=='read' and 'public' in allowed):raise Denied('permission denied')

    def block(self, peer_id):
        with self.lock:
            self.peer(peer_id, allow_blocked=True)
            self.db.execute("UPDATE peers SET blocked=1 WHERE id=?", (peer_id,))

    def _key(self, peer_id, *, historical=False):
        if peer_id == self.id:
            return self.identity.key.public_key()
        return certificate(self.peer(peer_id, allow_blocked=historical)["card"]["certificate"]).public_key()

    def _verified_record(self, obj, *, private=False):
        try:
            origin = obj["body"]["origin"]
            if origin!=self.id:
                permissions=self.peer(origin)['permissions']
                if 'publish' not in permissions and not ('public' in permissions and obj['body'].get('audience')==['@public']):raise Denied('origin cannot publish private memory')
            body = verify(obj, self._key(origin), RECORD_DOMAIN)
            validate_record(body, self.model, self.dimensions, private=private)
            return body
        except (KeyError, TypeError) as exc:
            raise Invalid("invalid record") from exc

    def _stored_record(self, row, *, private=False):
        """Cache immutable wire verification only; authorization is always live."""
        wire = row['wire']
        entry = self._verified_wires.get(row['id'])
        if entry and entry[0] == wire and entry[1] == private:
            obj = entry[2]
            origin = obj['body']['origin']
            pin = self.identity.pem
            if origin != self.id:
                peer = self.peer(origin)
                permissions = peer['permissions']
                pin = peer['card']['certificate']
                if 'publish' not in permissions and not (
                        'public' in permissions and obj['body']['audience'] == ['@public']):
                    raise Denied('origin cannot publish private memory')
            if entry[3] == pin:
                self._verified_wires.move_to_end(row['id'])
                return obj
        obj = decode(wire.encode())
        if not isinstance(obj, dict) or obj.get('id') != row['id']:
            raise Invalid('stored record ID mismatch')
        self._verified_record(obj, private=private)
        if entry:
            self._verified_bytes -= len(entry[0])
            del self._verified_wires[row['id']]
        origin = obj['body']['origin']
        pin = self.identity.pem if origin == self.id else self.peer(origin)['card']['certificate']
        self._verified_wires[row['id']] = (wire, private, obj, pin)
        self._verified_bytes += len(wire)
        while self._verified_bytes > VERIFICATION_CACHE_BYTES:
            _, removed = self._verified_wires.popitem(last=False)
            self._verified_bytes -= len(removed[0])
        return obj

    def _refresh_search_index(self, deadline=None):
        rebuilding = self._search_index is None
        data_version = self.db.execute('PRAGMA data_version').fetchone()[0]
        if rebuilding:
            self._search_index = SearchIndex(self.dimensions)
            self._indexed_versions = {}
            self._search_rebuilding = True
            self._search_epoch += 1
            rows = self.db.execute('SELECT * FROM records').fetchall()
        elif self._search_rebuilding or data_version != self._search_data_version:
            # Another Node/owner connection may have drained the shared dirty
            # table. Compare derived row versions before re-indexing its changes.
            rows = self.db.execute('SELECT * FROM records').fetchall()
            present = {row['id'] for row in rows}
            for rid in set(self._indexed_versions) - present:
                self._search_index.discard(rid)
                del self._indexed_versions[rid]
                self._search_epoch += 1
        else:
            rows = self.db.execute('SELECT r.* FROM search_dirty d CROSS JOIN records r WHERE r.id=d.id').fetchall()
            for row in self.db.execute('SELECT d.id FROM search_dirty d LEFT JOIN records r USING(id) WHERE r.id IS NULL'):
                self._search_index.discard(row['id'])
                self._indexed_versions.pop(row['id'], None)
                self._search_epoch += 1
        for row in rows:
            check_budget(deadline)
            version = (hash(row['wire']), row['state'])
            if self._indexed_versions.get(row['id']) == version:
                continue
            self._search_index.discard(row['id'])
            self._search_epoch += 1
            try:
                obj = decode(row['wire'].encode())
                if obj['id'] != row['id']:
                    continue
                body = obj['body']
                validate_record(body, self.model, self.dimensions, private=row['state'] == 'private')
                self._search_index.put(row['id'], body, row['state'])
                # Recover original draft markers for pre-index databases too.
                if body['origin'] == self.id and row['state'] == 'accepted':
                    from .crypto import digest
                    draft = {**body, 'audience': []}
                    private_id = digest(RECORD_DOMAIN.encode() + b'\x00' + canonical(draft))
                    self.db.execute('INSERT OR IGNORE INTO published_private VALUES(?)', (private_id,))
            except (Invalid, KeyError, TypeError):
                continue
            self._indexed_versions[row['id']] = version
        self.db.execute('DELETE FROM search_dirty')
        self._search_data_version = data_version
        self._search_rebuilding = False

    def _search_eligible(self, requester, deadline):
        """Cheap current-policy prefilter; _active checks every selected ancestry."""
        from .onboarding import policy
        caps = policy(self)
        from .source_policy import config as source_config
        source_policy = source_config(self)
        suppliers = {}
        if source_policy['sources'] is not None:
            for row in self.db.execute('SELECT record,source FROM record_sources'):
                suppliers.setdefault(row[0], set()).add(row[1])
        own = requester == self.id
        reader = own or 'read' in self.peer(requester)['permissions']
        origins = {self.id: {'publish', 'public'}}
        for origin in {entry[1] for entry in self._search_index.entries.values()} - {self.id}:
            try:
                origins[origin] = set(self.peer(origin)['permissions'])
            except Denied:
                origins[origin] = set()
        withdrawn = {(r[0], r[1]) for r in self.db.execute('SELECT target,origin FROM retractions')}
        drafts = {r[0] for r in self.db.execute('SELECT id FROM published_private')}
        transit = {r[0] for r in self.db.execute('SELECT id FROM transit_cache WHERE expires>?', (time.time(),))}
        eligible = set()
        for rid, (state, origin, audience) in self._search_index.entries.items():
            check_budget(deadline)
            public = audience == ('@public',)
            if origin != self.id:
                if source_policy['mode'] == 'provider':continue
                if source_policy['authors'] is not None and origin not in source_policy['authors']:continue
                if source_policy['sources'] is not None and not suppliers.get(rid,set()).intersection(source_policy['sources']):continue
            if state == 'private':
                if own and origin == self.id and rid not in drafts:
                    eligible.add(rid)
                continue
            if state != 'accepted' and not (
                    not own and rid in transit and public and caps['cache'] and caps['reshare']):
                continue
            if origin != self.id and ('publish' not in origins[origin] and not (public and 'public' in origins[origin])):
                continue
            if not own and origin != self.id and not caps['reshare']:
                continue
            if (rid, origin) in withdrawn:
                continue
            if requester == origin or public or (reader and (audience == ('*',) or requester in audience)):
                eligible.add(rid)
        return eligible

    def _row(self, rid):
        return self.db.execute("SELECT * FROM records WHERE id=?", (rid,)).fetchone()

    def _save(self, obj, state):
        wire = canonical(obj).decode()
        if not self._row(obj["id"]) and self.db.execute("SELECT count(*) FROM records").fetchone()[0] >= MAX_RECORDS:
            raise Denied("node record quota reached")
        self.db.execute("INSERT OR IGNORE INTO records VALUES(?,?,?)", (obj["id"], wire, state))
        if self._search_index is not None:
            # Ordinary ingestion pays incremental indexing cost, not the next
            # reader. Triggers still catch writes from another operator process.
            self._refresh_search_index()

    def write_private(self, content, embedding, *, parents=()):
        self.capability('write')
        with self.lock:
            body = {"version": 1, "origin": self.id, "model": self.model,
                    "vector": vector(embedding, self.dimensions), "text": content,
                    "parents": sorted(set(parents)), "audience": [], "created_ms": int(time.time()*1000)}
            validate_record(body, self.model, self.dimensions, private=True)
            obj = sign(self.identity.key, RECORD_DOMAIN, body)
            self._save(obj, "private")
            return obj["id"]

    def publish(self, private_id, *, audience):
        self.capability('publish')
        with self.lock:
            row = self._row(private_id)
            if row is None or row["state"] != "private":
                raise Invalid("publish requires a local private record")
            obj = decode(row["wire"].encode())
            body = self._verified_record(obj, private=True)
            body["audience"] = sorted(set(audience))
            validate_record(body, self.model, self.dimensions)
            self._check_parents(body)
            shared = sign(self.identity.key, RECORD_DOMAIN, body)
            if self._withdrawn(shared["id"], self.id):
                raise Denied("this content has been withdrawn")
            self._save(shared, "accepted")
            return shared["id"]

    def _visible(self,body,requester):
        if requester==body['origin']:return True
        if body['audience']==['@public']:return True
        if requester!=self.id and 'read' not in self.peer(requester)['permissions']:return False
        return body['audience']==['*'] or requester in body['audience']

    def _withdrawn(self, rid, origin):
        return self.db.execute("SELECT 1 FROM retractions WHERE origin=? AND target=?", (origin, rid)).fetchone() is not None

    def _active(self, rid, requester, path=None, memo=None, deadline=None, transit=False):
        from .records import check_budget
        check_budget(deadline)
        path = set() if path is None else path
        memo = {} if memo is None else memo
        if rid in path or len(path) >= MAX_DEPTH:
            return None
        cache_key = (rid, len(path))
        if cache_key in memo:
            return memo[cache_key]
        # Memoize failures too. Dense ancestry must not create exponential
        # signature work when several branches share the same ancestors.
        memo[cache_key] = None
        row = self._row(rid)
        if row is None:return None
        cached=False
        private = row['state'] == 'private' and requester == self.id
        if row['state']!='accepted':
            from .cache import eligible
            cached=row['state']=='pending' and (requester!=self.id or transit) and eligible(self,rid,reshare=requester!=self.id)
            if not cached and not private:return None
        try:
            obj = self._stored_record(row, private=private)
            body = obj['body']
            from .source_policy import require_record
            require_record(self, obj)
            if private and body['origin'] != self.id:return None
            if cached and body['audience']!=['@public']:return None
            if requester!=self.id and body['origin']!=self.id:
                from .onboarding import policy
                if not policy(self)['reshare']:return None
            if self._withdrawn(rid, body["origin"]) or not self._visible(body, requester):
                return None
            for parent in body["parents"]:
                ancestor=self._active(parent, requester, path | {rid}, memo,deadline,transit=transit)
                if ancestor is None or (cached and ancestor['body']['audience']!=['@public']):return None
            memo[cache_key] = obj
            return obj
        except SearchBudget:
            raise
        except (Invalid, Denied):
            return None

    def _check_parents(self, body):
        for rid in body["parents"]:
            parent = self._active(rid, self.id)
            if parent is None:
                raise Denied("parent is missing, unapproved, withdrawn, or inaccessible")
            pa = parent["body"]["audience"]
            if pa != ["@public"]:
                allowed = set(pa) | {parent["body"]["origin"]}
                if body["audience"] == ["@public"] or (pa != ["*"] and (body["audience"] == ["*"] or not set(body["audience"]) <= allowed)):
                    raise Denied("derived memory cannot widen its parents' audience")

    def ingest(self, obj, *, source=None):
        self.capability("fetch")
        with self.lock:
            body = self._verified_record(obj)
            if not self._visible(body, self.id):
                raise Denied("this node is outside the record audience")
            if self._withdrawn(obj["id"], body["origin"]):
                raise Denied("record has been withdrawn")
            if self.db.execute('SELECT 1 FROM rejected WHERE id=?',(obj['id'],)).fetchone():raise Denied('record rejected locally')
            from .source_policy import require, require_record, remember_source
            require(self, "authors", body["origin"])
            if source is None:
                require_record(self, obj)
            else:
                require(self, "sources", source)
            self._save(obj, "pending")
            if source is not None:remember_source(self, obj, source)
            return obj["id"]

    def approve(self, rid):
        self.capability('approve')
        with self.lock:
            row = self._row(rid)
            if row is None or row["state"] == "private":
                raise Invalid("no imported record to approve")
            obj = decode(row["wire"].encode())
            body = self._verified_record(obj)
            from .source_policy import require_record
            require_record(self, obj)
            if self._withdrawn(rid, body["origin"]) or not self._visible(body, self.id):
                raise Denied("record withdrawn or inaccessible")
            self._check_parents(body)
            # Limit depth by testing the resulting record under the same read policy.
            old_state = row["state"]
            self.db.execute("UPDATE records SET state='accepted' WHERE id=?", (rid,))
            if self._active(rid, self.id) is None:
                self.db.execute("UPDATE records SET state=? WHERE id=?", (old_state, rid))
                raise Denied("record lineage exceeds depth limit")
            self.db.execute("DELETE FROM transit_cache WHERE id=?",(rid,))

    def inspect(self, rid):
        """Local operator inspection, including pending/private/audit data."""
        with self.lock:
            row = self._row(rid)
            if row is None:
                raise Invalid("unknown record")
            obj = decode(row["wire"].encode())
            from .source_policy import require_record
            require_record(self, obj)
            return {"state": row["state"], "record": obj, "untrusted_data": True}

    def inventory(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT id,state FROM records ORDER BY id")]

    def get(self, rid, requester):
        if requester!=self.id:self.capability("serve_memory")
        with self.lock:
            self.require(requester, "read")
            obj = self._active(rid, requester)
            if obj is None:
                raise Denied("record unavailable")
            return deepcopy(obj)

    def search(self, requester, *, query_text="", query_vector=None, model=None, k=10):
        self.capability("search" if requester==self.id else "serve_memory")
        with self.lock:
            self.require(requester, "read")
            if type(k) is not int or not 1 <= k <= SEARCH_LIMIT:
                raise Invalid("k must be between 1 and 20")
            if not isinstance(query_text, str) or len(query_text.encode()) > 4096:
                raise Invalid("invalid search text")
            if query_vector is not None:
                if model != self.model:
                    raise Invalid("embedding model mismatch")
                query_vector = vector(query_vector, self.dimensions)
            if not query_text.strip() and query_vector is None:
                raise Invalid("search needs text or a vector")
            memo = {}
            deadline = time.monotonic()+.5 if requester!=self.id else None
            self._refresh_search_index(deadline)
            eligible = self._search_eligible(requester, deadline)
            candidates, limited = self._search_index.candidates(
                eligible, query_vector, query_text, SEARCH_CANDIDATES, deadline=deadline)
            records = [obj for rid in candidates
                       if (obj := self._active(rid, requester, memo=memo,deadline=deadline)) is not None]
            return {"results": deepcopy(rank(records, query_vector, query_text, k,deadline=deadline)),
                    "coverage": {"responding_peer": self.id, "scope": "authorized_local_records",
                                 "records_considered": len(records), "network_complete": False,
                                 "candidate_limit": SEARCH_CANDIDATES,
                                 "candidate_limited": limited}}

    def retract(self, rid):
        with self.lock:
            row = self._row(rid)
            if row is None or row["state"] == "private":
                raise Invalid("no shared record to retract")
            record = decode(row["wire"].encode())
            if record["body"]["origin"] != self.id:
                raise Denied("only the author can issue a retraction")
            obj = sign(self.identity.key, RETRACT_DOMAIN,
                       {"version": 1, "origin": self.id, "target": rid})
            self.ingest_retraction(obj)
            return obj

    def _retraction_allocation(self, origin, target):
        if origin == self.id:
            return 'local'
        row = self._row(target)
        if row:
            try:
                if decode(row['wire'].encode())['body']['origin'] == origin:
                    return 'stored'
            except (Invalid, KeyError, TypeError):
                pass
        return 'unknown'

    def _migrate_retractions(self):
        # Preserve all legacy tombstones, including stores already above one of
        # the new foreign limits. New local withdrawals have an independent pool.
        with self.transaction():
            rows = self.db.execute('''SELECT r.* FROM retractions r
                LEFT JOIN retraction_sources s USING(id) WHERE s.id IS NULL''').fetchall()
            for row in rows:
                allocation = self._retraction_allocation(row['origin'], row['target'])
                self.db.execute('INSERT INTO retraction_sources VALUES(?,?,?)',
                                (row['id'], row['origin'], allocation))

    def ingest_retraction(self, obj, *, supplier=None, requested_record=None):
        with self.transaction():
            try:
                # A blocked origin may still withdraw its own content. Never allow
                # an arbitrary relay to withdraw another origin's content.
                body = verify(obj, self._key(obj["body"]["origin"], historical=True), RETRACT_DOMAIN)
            except (KeyError, TypeError) as exc:
                raise Invalid("invalid retraction") from exc
            if (set(body) != {"version", "origin", "target"} or type(body["version"]) is not int
                    or body["version"] != 1 or not valid_id(body["target"])):
                raise Invalid("invalid retraction schema")
            if self._withdrawn(body['target'], body['origin']):
                return
            supplier = body['origin'] if supplier is None else supplier
            if supplier != self.id:
                self.peer(supplier, allow_blocked=True)
            allocation = self._retraction_allocation(body['origin'], body['target'])
            requested_public = False
            if (allocation == 'unknown' and isinstance(requested_record, dict)
                    and requested_record.get('id') == body['target']
                    and isinstance(requested_record.get('body'), dict)
                    and requested_record['body'].get('origin') == body['origin']):
                # A fetch must synchronize withdrawal before storing its record.
                # Reserve capacity for that verified, specifically requested
                # target without requiring a transient (possibly withdrawn) copy.
                requested_body = self._verified_record(requested_record)
                if not self._visible(requested_body, self.id):
                    raise Denied('requested record is outside the local audience')
                allocation = 'stored'
                requested_public = requested_body['audience'] == ['@public']
            if self.db.execute('SELECT count(*) FROM retraction_sources WHERE allocation=?',
                               (allocation,)).fetchone()[0] >= MAX_EVENTS:
                raise Denied(f'{allocation} retraction quota reached; keep tombstones and inspect capacity')
            if allocation == 'unknown':
                origin_count = self.db.execute('''SELECT count(*) FROM retractions r
                    JOIN retraction_sources s USING(id) WHERE s.allocation='unknown' AND r.origin=?''',
                    (body['origin'],)).fetchone()[0]
                supplied = self.db.execute("SELECT count(*) FROM retraction_sources WHERE allocation='unknown' AND supplier=?",
                                          (supplier,)).fetchone()[0]
                if origin_count >= MAX_UNKNOWN_RETRACTIONS_PER_ORIGIN or supplied >= MAX_UNKNOWN_RETRACTIONS_PER_SUPPLIER:
                    raise Denied('unknown-target retraction origin/supplier quota reached; inspect or block the source; never discard tombstones')
            target=self._row(body['target'])
            if allocation != 'unknown' and (requested_public or (
                    target and decode(target['wire'].encode())['body']['audience']==['@public'])):
                self.db.execute('INSERT OR IGNORE INTO public_tombstones VALUES(?)',(body['target'],))
            self.db.execute("INSERT OR IGNORE INTO retractions VALUES(?,?,?,?)",
                            (obj["id"], body["origin"], body["target"], canonical(obj).decode()))
            self.db.execute('INSERT INTO retraction_sources VALUES(?,?,?)',
                            (obj['id'], supplier, allocation))

    def retractions(self, requester, after=""):
        with self.lock:
            self.require(requester, "read")
            if not isinstance(after, str) or (after and not valid_id(after)):
                raise Invalid("invalid cursor")
            rows = self.db.execute("SELECT * FROM retractions WHERE id>? ORDER BY id LIMIT 500", (after,)).fetchall()
            public_only=requester!=self.id and 'read' not in self.peer(requester)['permissions']
            events=[]
            for row in rows:
                target=self._row(row['target'])
                if not public_only or (target and decode(target['wire'].encode())['body']['audience']==['@public']) or self.db.execute('SELECT 1 FROM public_tombstones WHERE id=?',(row['target'],)).fetchone():events.append(decode(row['wire'].encode()))
            return {"events": events,
                    "next": rows[-1]["id"] if len(rows) == 500 else None}

    def make_message(self, recipient, content, *, expires=None, reply_to=None, permit=None):
        self.capability('send')
        self.peer(recipient)
        text(content)
        import uuid
        return sign(self.identity.key, MESSAGE_DOMAIN,
                    {"version": 3 if reply_to is not None else (2 if expires is not None else 1), "origin": self.id, "recipient": recipient,
                     "text": content, "nonce": uuid.uuid4().hex, **({"expires":expires} if expires is not None else {}),
                     **({"reply_to":reply_to,"permit":permit} if reply_to is not None else {})})

    def receive_message(self, obj, requester, admission=None, *, _routed_work=None):
        self.capability('receive')
        from .source_policy import require
        require(self, 'senders', requester)
        with self.transaction():
            self.require(requester, "message")
            body = verify(obj, self._key(requester), MESSAGE_DOMAIN)
            if (set(body) != ({"version", "origin", "recipient", "text", "nonce"} | ({"expires"} if body.get("version") in (2,3) else set()) | ({"reply_to","permit"} if body.get("version")==3 else set()))
                    or type(body["version"]) is not int or body["version"] not in (1,2,3)
                    or body["origin"] != requester or body["recipient"] != self.id
                    or not isinstance(body["nonce"], str) or len(body["nonce"]) != 32):
                raise Invalid("invalid direct message")
            text(body["text"])
            if body["version"]==3 and (not valid_id(body["reply_to"]) or not valid_id(body["permit"])):
                raise Invalid("invalid reply binding")
            now=int(time.time())
            expiry=body.get('expires',0)
            if body['version'] in (2,3) and (type(expiry) is not int or not now<expiry<=now+604800):raise Denied('message expired or invalid expiry')
            self.db.execute('DELETE FROM received_ids WHERE expires>0 AND expires<=?',(now,))
            if self.db.execute('SELECT 1 FROM received_ids WHERE id=?',(obj['id'],)).fetchone():return obj['id']
            if self.db.execute('SELECT count(*) FROM received_ids').fetchone()[0]>=20000:raise Denied('message replay budget reached')
            self.db.execute('INSERT INTO received_ids VALUES(?,?)',(obj['id'],expiry))
            if self.db.execute('SELECT 1 FROM messages WHERE id=?',(obj['id'],)).fetchone():return obj['id']
            if self.db.execute("SELECT count(*) FROM messages").fetchone()[0] >= MAX_RECORDS:
                raise Denied("inbox quota reached")
            from .message_work import admit
            admit(self,obj,requester,"message",admission,_routed_work=_routed_work)
            self.db.execute("INSERT OR IGNORE INTO messages VALUES(?,?)", (obj["id"], canonical(obj).decode()))
            return obj["id"]

    def inbox_page(self, *, after=0, limit=50):
        from .lifecycle import message_page
        return message_page(self,after=after,limit=limit)

    def inbox(self):
        from .source_policy import allowed, config
        if config(self)['mode'] == 'provider':raise Denied('source_policy_denied:provider_inbox')
        with self.lock:
            return [{"message": decode(row["wire"].encode()), "untrusted_data": True}
                    for row in self.db.execute("SELECT wire FROM messages ORDER BY rowid")
                    if allowed(self, "senders", decode(row["wire"].encode())["body"]["origin"])]
