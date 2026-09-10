"""Bounded JSON RPC over pinned mutual TLS 1.3; no shared process state.

One request per connection. The OpenSSL handshake runs in a bounded worker,
with deadlines, so an idle plaintext connection cannot block the accept loop.
"""
from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import threading
import time
from contextlib import nullcontext

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .crypto import Invalid, Denied, MAX_WIRE_BYTES, canonical, decode, certificate, public_id

TIMEOUT = 5


def _read_exact(sock, count, deadline):
    out = bytearray()
    while len(out) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Invalid("frame deadline exceeded")
        sock.settimeout(remaining)
        part = sock.recv(count - len(out))
        if not part:
            raise Invalid("truncated frame")
        out.extend(part)
    return bytes(out)


def receive(sock, max_bytes=MAX_WIRE_BYTES, *, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    size = struct.unpack("!I", _read_exact(sock, 4, deadline))[0]
    if not 0 < size <= max_bytes:
        raise Invalid("invalid frame size")
    return decode(_read_exact(sock, size, deadline))


def transmit(sock, obj):
    data = canonical(obj)
    if len(data) > MAX_WIRE_BYTES:
        raise Invalid("response too large")
    sock.sendall(struct.pack("!I", len(data)) + data)


def context(node, *, server, peer_pem=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if not server:
        # Identity is pinned below; endpoint DNS names are not identity.
        ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(node.identity.cert_path, node.identity.key_path)
    pems = ([p["card"]["certificate"] for p in node.peers() if not p["blocked"]]
            if server else [peer_pem])
    if pems:
        ctx.load_verify_locations(cadata="\n".join(pems))
    return ctx


def authenticate(sock, node, expected=None):
    der = sock.getpeercert(binary_form=True)
    peer_id = public_id(x509.load_der_x509_certificate(der).public_key())
    if expected is not None and peer_id != expected:
        raise Denied("wrong TLS peer identity")
    card = node.peer(peer_id)["card"]
    pinned = certificate(card["certificate"]).public_bytes(serialization.Encoding.DER)
    if der != pinned:
        raise Denied("peer certificate does not match pin")
    return peer_id


def dispatch(node, peer_id, request):
    node.capability("network")
    if not isinstance(request, dict) or set(request) != {"op", "args"} or not isinstance(request["args"], dict):
        raise Invalid("invalid request schema")
    op, args = request["op"], request["args"]
    if op=='peer_view' and set(args)<={'after','limit'}:
        from .openmesh import peer_view
        return peer_view(node,peer_id,**args)
    if op == "threads" and set(args)<={"thread","after","since_ms","until_ms","limit"}:
        from .conversations import page
        return page(node,peer_id,**args)
    if op == "thread_post" and set(args)=={"post"}:
        from .conversations import accept
        return accept(node,args["post"],peer_id)
    if op == "search" and set(args) <= {"query_text", "query_vector", "model", "k"}:
        return node.search(peer_id, **args)
    if op == "get" and set(args) == {"id"}:
        if not isinstance(args["id"], str):
            raise Invalid("invalid record ID")
        return node.get(args["id"], peer_id)
    if op == "retractions" and set(args) <= {"after"}:
        return node.retractions(peer_id, **args)
    if op == "message" and set(args) == {"message"}:
        return {"id": node.receive_message(args["message"], peer_id)}
    raise Invalid("unsupported operation or arguments")


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        node = self.server.node
        source, peer_id = self.client_address[0], ''
        self.request.settimeout(TIMEOUT)
        try:
            # Rebuild the trust context on each connection: local approvals and
            # blocks take effect without restarting the listener.
            with context(node, server=True).wrap_socket(self.request, server_side=True) as conn:
                peer_id = authenticate(conn, node)
                try:
                    request = receive(conn,128*1024)
                    op = request.get('op') if isinstance(request,dict) else None
                    node.defense.operation(source,peer_id,op,'data')
                    with node.defense.search(source,peer_id) if op=='search' else nullcontext():
                        result = dispatch(node, peer_id, request)
                    response = {"ok": True, "result": result}
                    if isinstance(result, dict) and "results" in result and "coverage" in result:
                        while len(canonical(response)) > MAX_WIRE_BYTES and result["results"]:
                            result["results"].pop()
                            result["coverage"]["results_limited_by_response_size"] = True
                except Denied as exc:
                    response = {"ok": False, "error": "denied", "detail": str(exc)}
                except (Invalid, TypeError, KeyError) as exc:
                    node.defense.failure(source,peer=peer_id,event='invalid_request')
                    response = {"ok": False, "error": "invalid", "detail": str(exc)}
                transmit(conn, response)
        except (OSError, Invalid, Denied):
            node.defense.failure(source,peer=peer_id,event='transport_failure')
            # Malformed or unauthenticated connections receive no application data.
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, node, host="127.0.0.1", port=0):
        self.node = node
        self.defense = node.defense
        self._slots = threading.BoundedSemaphore(16)
        super().__init__((host, port), _Handler)
        if (node.directory/'connectivity.json').exists():
            from .connectivity import Connectivity, load_config
            node.connectivity=Connectivity(node,load_config(node),port=self.server_address[1],listen_host=self.server_address[0]).start()

    def server_close(self):
        node=getattr(self,'node',None)
        if node and node.connectivity:
            node.connectivity.close();node.connectivity=None
        super().server_close()

    def process_request(self, request, client_address):
        if not self.defense.connection(client_address[0],getattr(self,'role','data')):
            self.shutdown_request(request)
            return
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def start(self):
        thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        return thread

    def service_actions(self):
        if time.monotonic()-getattr(self,'_audit_purged',0)>60:
            from .cache import sweep
            if getattr(self,'role','data')!='bootstrap':sweep(self.node)
            self.defense.events()
            self.defense.rules()
            self._audit_purged=time.monotonic()


class Client:
    def __init__(self, node, peer_id):
        self.node, self.peer_id = node, peer_id

    def _direct(self, op, args):
        card = self.node.peer(self.peer_id)["card"]
        ctx = context(self.node, server=False, peer_pem=card["certificate"])
        with socket.create_connection((card["host"], card["port"]), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as conn:
                authenticate(conn, self.node, self.peer_id)
                try:
                    transmit(conn, {"op": op, "args": args})
                    response = receive(conn)
                except OSError:
                    if op=='message':raise Denied('delivery status unknown; inspect recipient inbox before resending')
                    raise
        return response

    def request(self, op, **args):
        self.node.capability("network")
        if op=="search":self.node.capability("search")
        if op=="get":self.node.capability("fetch")
        if op in ("message","thread_post"):self.node.capability("send")
        if op in ("threads","thread_post"):self.node.capability("threads")
        manager=self.node.connectivity
        if manager and manager.state['peers'].get(self.peer_id,{}).get('path') in ('direct-ice','relay'):
            response=manager.request(self.peer_id,op,args)
            return self._result(response)
        try:
            response=self._direct(op,args)
        except Denied:
            raise
        except OSError:
            from .connectivity import Connectivity, load_config
            config=load_config(self.node)
            if config is None:raise
            manager=self.node.connectivity
            if manager is None:
                manager=Connectivity(self.node,config,passive=False).start()
                self.node.connectivity=manager
            future=__import__('asyncio').run_coroutine_threadsafe(manager.refresh(),manager.loop)
            try:future.result(timeout=20)
            except TimeoutError:future.cancel()
            try:response=self._direct(op,args)
            except Denied:raise
            except OSError:response=manager.request(self.peer_id,op,args)
        return self._result(response)

    @staticmethod
    def _result(response):
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise Invalid("invalid peer response")
        if not response["ok"]:
            if response.get("error") == "denied":
                raise Denied(response.get("detail", "peer denied request"))
            raise Invalid(response.get("detail", "peer rejected request"))
        return response["result"]

    def search(self, *, query_text="", query_vector=None, k=10):
        result = self.request("search", query_text=query_text, query_vector=query_vector,
                              model=self.node.model, k=k)
        try:
            if not isinstance(result,dict) or not isinstance(result.get('results'),list) or len(result['results'])>20:raise Invalid('invalid search result bounds')
            for hit in result["results"]:
                body = self.node._verified_record(hit["record"])
                if not self.node._visible(body, self.node.id):
                    raise Denied("remote result outside audience")
                if self.node._withdrawn(hit["record"]["id"], body["origin"]):
                    raise Denied("remote result is withdrawn locally")
                hit["untrusted_data"] = True
            from .cache import remember
            for hit in result['results']:remember(self.node,hit['record'])
            return result
        except (KeyError, TypeError) as exc:
            raise Invalid("malformed search response") from exc

    def fetch(self, rid, *, refresh=False):
        if type(refresh) is not bool:raise Invalid('refresh must be boolean')
        self.node.capability('network');self.node.capability('fetch')
        self.node.peer(self.peer_id)
        if self.node.defense.blocked(peer=self.peer_id):raise Denied('peer blocked')
        from .cache import hit,remember,credit
        if not refresh and hit(self.node,rid):return rid
        self.sync_retractions()
        obj = self.request("get", id=rid)
        if not isinstance(obj, dict) or obj.get("id") != rid:
            raise Invalid("peer returned the wrong record")
        with self.node.transaction():
            remember(self.node,obj)
            result=self.node.ingest(obj)
            credit(self.node,self.peer_id,obj)
            return result

    def sync_retractions(self):
        after, count, unknown = "", 0, 0
        # Each pass starts at the beginning; persistent tombstones are idempotent.
        # A bounded sweep cannot claim global freshness or partition-time safety.
        for _ in range(21):
            page = self.request("retractions", after=after)
            if not isinstance(page, dict) or set(page) != {"events", "next"} or not isinstance(page["events"], list):
                raise Invalid("invalid retraction page")
            for event in page["events"]:
                try:
                    origin = event["body"]["origin"]
                    self.node._key(origin, historical=True)
                except Denied:
                    unknown += 1
                    continue
                except (KeyError, TypeError) as exc:
                    raise Invalid("invalid retraction event") from exc
                self.node.ingest_retraction(event)
                count += 1
            cursor = page["next"]
            if cursor is None:
                return {"verified_events": count, "unknown_origins_skipped": unknown,
                        "network_complete": False}
            if not isinstance(cursor, str) or cursor <= after:
                raise Invalid("non-advancing retraction cursor")
            after = cursor
        raise Invalid("retraction sweep exceeded limit")

    def send(self, content):
        return self.request("message", message=self.node.make_message(self.peer_id, content))
