"""Bounded JSON RPC over pinned mutual TLS 1.3; no shared process state.

One request per connection. The OpenSSL handshake runs in a bounded worker,
with deadlines, so an idle plaintext connection cannot block the accept loop.
"""
from __future__ import annotations

import socket
import ipaddress
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
PATH_PROTOCOL = 'agentmesh.peer-paths.v1'


def paths(node):
    """Local transport policy, not a promise of reachability or authorization."""
    from .connectivity import load_config
    manager = node.connectivity
    config = manager.config if manager else load_config(node)
    only = bool(config and config['relay_only'])
    return {'protocol': PATH_PROTOCOL, 'accepted': ['relay'] if only else
            (['direct-tcp', 'direct-ice', 'relay'] if config else ['direct-tcp']),
            'configured_ice': bool(config), 'relay_only': only}


def relay_only(node):
    manager = node.connectivity
    if manager is not None:
        return manager.config.get('relay_only', False)
    from .connectivity import load_config
    config = load_config(node)
    return bool(config and config['relay_only'])


def connectivity_manager(node, config):
    # Independent delivery destinations may discover the missing manager together.
    # Only its construction is serialized; no lock is held across network work.
    with node.lock:
        if node.connectivity is None:
            from .connectivity import Connectivity
            node.connectivity = Connectivity(node, config, passive=False).start()
        return node.connectivity


def endpoint_blocked(node, peer, host):
    from .connectivity import candidate_address
    address = ipaddress.ip_address(host)
    normalized = candidate_address(address)
    addresses = {address, normalized}
    if isinstance(address, ipaddress.IPv6Address):
        if address.sixtofour:
            addresses.add(address.sixtofour)
        addresses.update(address.teredo or ())
    return any(node.defense.blocked(source=str(value), peer=peer) for value in addresses)


def peer_socket(node, peer, host, port):
    """Resolve once and filter numeric destinations before any TCP connection."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    permitted = [item for item in addresses[:32] if not endpoint_blocked(node, peer, item[4][0])]
    if not permitted:
        raise Denied('peer endpoint blocked by local policy')
    last_error = OSError('no reachable peer endpoint')
    deadline = time.monotonic() + TIMEOUT
    for family, kind, protocol, _, address in permitted:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('peer connection deadline exceeded')
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(remaining)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise last_error


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
    if op == 'paths' and not args:
        return paths(node)
    if op == 'route_exchange' and not args:
        from .routing import exchange
        return exchange(node, peer_id)
    if op == 'route_accept' and set(args) == {'envelope', 'chain'}:
        from .routing import accept
        return accept(node, peer_id, **args)
    if op == 'message_challenge' and set(args)=={'operation','id','thread','offer'}:
        from .source_policy import require
        require(node, 'senders', peer_id)
        from .message_work import challenge
        return challenge(node,peer_id,**args)
    if op == 'capabilities' and not args:
        from .peer_status import describe
        return describe(node, peer_id)
    if op=='peer_view' and set(args)<={'after','limit'}:
        from .openmesh import peer_view
        return peer_view(node,peer_id,**args)
    if op == "threads" and set(args)<={"thread","after","since_ms","until_ms","limit"}:
        from .conversations import page
        return page(node,peer_id,**args)
    if op == "thread_post" and {"post"}<=set(args)<={"post","admission"}:
        from .conversations import accept
        return accept(node,args["post"],peer_id,args.get("admission"))
    if op == "search" and set(args) <= {"query_text", "query_vector", "model", "k"}:
        return node.search(peer_id, **args)
    if op == "get" and set(args) == {"id"}:
        if not isinstance(args["id"], str):
            raise Invalid("invalid record ID")
        return node.get(args["id"], peer_id)
    if op == "retractions" and set(args) <= {"after"}:
        return node.retractions(peer_id, **args)
    if op == "message" and {"message"}<=set(args)<={"message","admission"}:
        return {"id": node.receive_message(args["message"], peer_id,args.get("admission"))}
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
                    if relay_only(node) and op not in ('paths', 'capabilities'):
                        # This refusal occurs before dispatch: retry on the indicated
                        # transport is safe even for a non-idempotent operation.
                        response = {'ok': False, 'error': 'transport_required',
                                    'paths': paths(node), 'executed': False}
                        result = None
                    else:
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
    def __init__(self, node, peer_id, *, timeout=110):
        self.node, self.peer_id = node, peer_id
        self.timeout = timeout

    def _ice_request(self, manager, op, args):
        if self.timeout == 110:
            return manager.request(self.peer_id, op, args)
        return manager.request(self.peer_id, op, args, timeout=self.timeout)

    def _direct(self, op, args):
        self.node.capability('network')
        if relay_only(self.node):
            raise Denied('relay-only policy prohibits direct TCP peer requests')
        card = self.node.peer(self.peer_id)["card"]
        if self.node.defense.blocked(peer=self.peer_id):
            raise Denied('peer endpoint blocked by local policy')
        ctx = context(self.node, server=False, peer_pem=card["certificate"])
        with peer_socket(self.node, self.peer_id, card['host'], card['port']) as raw:
            if endpoint_blocked(self.node, self.peer_id, raw.getpeername()[0]):
                raise Denied('peer endpoint blocked by local policy')
            with ctx.wrap_socket(raw, server_hostname=None) as conn:
                authenticate(conn, self.node, self.peer_id)
                try:
                    transmit(conn, {"op": op, "args": args})
                    response = receive(conn)
                except (OSError, Invalid):
                    if op in ('message', 'thread_post'):
                        raise Denied('delivery status unknown; inspect recipient state before another operation')
                    raise
        return response

    def request(self, op, **args):
        from .source_policy import require, allowed
        if op in ('search', 'get', 'threads'):
            require(self.node, 'sources', self.peer_id)
        result = self._permitted_request(op, **args)
        if op == 'get':
            body = self.node._verified_record(result)
            require(self.node, 'authors', body['origin'])
        elif op == 'search':
            hits = result.get('results') if isinstance(result, dict) else None
            if not isinstance(hits, list) or len(hits) > 20:
                raise Invalid('invalid search result bounds')
            kept = []
            for hit in hits:
                body = self.node._verified_record(hit['record'])
                if allowed(self.node, 'authors', body['origin']):kept.append(hit)
            result = {**result, 'results': kept, 'source_policy_filtered': len(hits)-len(kept)}
        elif op == 'threads':
            from .conversations import checked
            if result.get('root'):
                require(self.node, 'authors', checked(result['root'])['origin'])
            result = {**result, 'items': [entry for entry in result['items']
                if allowed(self.node, 'authors', checked(entry['object'])['origin'])
                and allowed(self.node, 'senders', checked(entry['object'])['origin'])]}
        return result

    def _permitted_request(self, op, **args):
        try:
            return self._request(op,**args)
        except Denied as exc:
            from .message_work import REQUIRED, solve_for
            if op not in ('message','thread_post') or str(exc)!=REQUIRED or 'admission' in args:
                raise
            obj=args['message' if op=='message' else 'post']
            if obj['body'].get('version')==3:
                raise
            admission=solve_for(self,op,obj)
            try:
                return self._request(op,**args,admission=admission)
            except Denied as failure:
                if str(failure)=='invalid or expired message work':
                    with self.node.transaction():
                        self.node.db.execute('UPDATE message_work_out SET ticket=NULL,nonce=NULL WHERE id=?',(obj['id'],))
                raise

    def _request(self, op, **args):
        self.node.capability("network")
        if op=="search":self.node.capability("search")
        if op=="get":self.node.capability("fetch")
        if op in ("message","thread_post","message_challenge"):self.node.capability("send")
        if op in ("threads","thread_post") or (op=="message_challenge" and args.get("operation")=="thread_post"):self.node.capability("threads")
        self.node.peer(self.peer_id)
        if self.node.defense.blocked(peer=self.peer_id):
            raise Denied('peer blocked by local policy')
        manager=self.node.connectivity
        if relay_only(self.node):
            if manager is None:
                from .connectivity import load_config
                manager = connectivity_manager(self.node, load_config(self.node))
            return self._result(self._ice_request(manager, op, args))
        if manager and manager.state['peers'].get(self.peer_id,{}).get('path') in ('direct-ice','relay'):
            response=self._ice_request(manager,op,args)
            return self._result(response)
        try:
            response=self._direct(op,args)
        except Denied:
            raise
        except OSError:
            from .connectivity import load_config
            config=load_config(self.node)
            if config is None:raise
            manager=connectivity_manager(self.node,config)
            future=__import__('asyncio').run_coroutine_threadsafe(manager.refresh(),manager.loop)
            try:future.result(timeout=20)
            except TimeoutError:future.cancel()
            try:response=self._direct(op,args)
            except Denied:raise
            except OSError:response=self._ice_request(manager,op,args)
        if (isinstance(response, dict) and response.get('error') == 'transport_required'
                and response.get('ok') is False and response.get('executed') is False
                and response.get('paths') == {'protocol': PATH_PROTOCOL,
                    'accepted': ['relay'], 'configured_ice': True, 'relay_only': True}):
            from .connectivity import load_config
            config = load_config(self.node)
            if config is None:
                raise Denied('peer requires relay; configure ICE and a compatible seed/relay path')
            manager = connectivity_manager(self.node, config)
            manager.state.setdefault('path_decisions', {})[self.peer_id] = {
                'attempted': 'direct-tcp', 'reason': 'peer_requires_relay',
                'accepted': ['relay'], 'operation_executed_on_tcp': False}
            response = self._ice_request(manager, op, args)
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
            for hit in result['results']:remember(self.node,hit['record'],source=self.peer_id)
            return result
        except (KeyError, TypeError) as exc:
            raise Invalid("malformed search response") from exc

    def peer_status(self):
        from .peer_status import checked
        try:
            result = self.request('capabilities')
        except Invalid as exc:
            if 'unsupported operation' not in str(exc):
                raise
            return {'peer': self.peer_id, 'supported': False,
                    'untrusted_data': True, 'permissions': None, 'operations': None,
                    'next_action': 'Peer uses an older protocol. Obtain compatibility and grants '
                        'through the owner-authorized provisioning channel; do not assume permission.'}
        result = checked(result, self.node, self.peer_id)
        if 'peer-paths-v1' in result['features']:
            info = self.request('paths')
            if (not isinstance(info, dict) or set(info) != {'protocol', 'accepted', 'configured_ice', 'relay_only'}
                    or info['protocol'] != PATH_PROTOCOL or type(info['configured_ice']) is not bool
                    or type(info['relay_only']) is not bool
                    or info['accepted'] not in (['direct-tcp'], ['relay'], ['direct-tcp', 'direct-ice', 'relay'])
                    or info['relay_only'] != (info['accepted'] == ['relay'])
                    or (not info['configured_ice'] and info['accepted'] != ['direct-tcp'])):
                raise Invalid('invalid peer path hints')
            result['paths'] = info
        else:
            result['paths'] = {'supported': False, 'accepted': None}
        return result

    def fetch(self, rid, *, refresh=False):
        if type(refresh) is not bool:raise Invalid('refresh must be boolean')
        self.node.capability('network');self.node.capability('fetch')
        self.node.peer(self.peer_id)
        if self.node.defense.blocked(peer=self.peer_id):raise Denied('peer blocked')
        from .source_policy import require
        require(self.node, 'sources', self.peer_id)
        from .cache import hit,remember,credit
        if not refresh and hit(self.node,rid):return rid
        obj = self.request("get", id=rid)
        if not isinstance(obj, dict) or obj.get("id") != rid:
            raise Invalid("peer returned the wrong record")
        body = self.node._verified_record(obj)
        if not self.node._visible(body, self.node.id):
            raise Denied('remote record outside audience')
        # A fetch reconciles the requested signed record and existing local
        # records before import, without adopting an unrelated lifetime history.
        self.sync_retractions(requested_record=obj)
        with self.node.transaction():
            remember(self.node,obj,source=self.peer_id)
            result=self.node.ingest(obj,source=self.peer_id)
            credit(self.node,self.peer_id,obj)
            return result

    def sync_retractions(self, *, requested_record=None):
        after, count, unknown, unrelated = "", 0, 0, 0
        requested = None
        if requested_record is not None:
            body = self.node._verified_record(requested_record)
            if not self.node._visible(body, self.node.id):
                raise Denied('remote record outside audience')
            requested = (requested_record['id'], body['origin'])
        # Each pass starts at the beginning; persistent tombstones are idempotent.
        # A bounded sweep cannot claim global freshness or partition-time safety.
        for page_number in range(61):
            if page_number:
                # Paginated sync must fit the default per-source connection budget.
                time.sleep(.5)
            page = self.request("retractions", after=after)
            if (not isinstance(page, dict) or set(page) != {"events", "next"}
                    or not isinstance(page["events"], list) or len(page['events']) > 500):
                raise Invalid("invalid retraction page")
            for event in page["events"]:
                try:
                    origin = event["body"]["origin"]
                    target = event['body']['target']
                    if requested is not None and (target, origin) != requested:
                        with self.node.lock:
                            row = self.node._row(target) if isinstance(target, str) else None
                            relevant = row is not None and decode(row['wire'].encode())['body']['origin'] == origin
                        if not relevant:
                            unrelated += 1
                            continue
                    self.node._key(origin, historical=True)
                except Denied:
                    unknown += 1
                    continue
                except (KeyError, TypeError) as exc:
                    raise Invalid("invalid retraction event") from exc
                self.node.ingest_retraction(event, supplier=self.peer_id, requested_record=requested_record)
                count += 1
            cursor = page["next"]
            if cursor is None:
                return {"verified_events": count, "unknown_origins_skipped": unknown,
                        "unrelated_events_skipped": unrelated,
                        "scope": 'requested_and_stored_records' if requested is not None else 'bounded_peer_history',
                        "network_complete": False}
            if not isinstance(cursor, str) or cursor <= after:
                raise Invalid("non-advancing retraction cursor")
            after = cursor
        raise Invalid("retraction sweep exceeded limit")

    def send(self, content):
        return self.request("message", message=self.node.make_message(self.peer_id, content, expires=int(time.time())+604800))
