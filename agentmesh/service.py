"""Local node lifetime and private Unix-socket bridge for persistent MCP clients."""
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
import os
import signal
import socket
import stat
import socketserver
import threading

from . import agent
from .crypto import Invalid, Denied, canonical
from .network import Server, receive, transmit
from .onboarding import load, policy, status

RESOURCES={
    'agentmesh://instructions':('Agent instructions','text/plain'),
    'agentmesh://reference':('Advanced agent reference','text/markdown'),
    'agentmesh://status':('Node status','application/json'),
    'agentmesh://policy':('Owner capability policy','application/json'),
}
REQUIRED=agent.REQUIRED


def enabled(node,name):
    from .source_policy import config
    if name == 'inbox' and config(node)['mode'] == 'provider':return False
    caps=policy(node)
    return name in agent.DEFINITIONS and all(caps[c] for c in REQUIRED.get(name,()))


@contextmanager
def runtime_lock(directory):
    # File locks release on exit/crash; stale lock files do not imply live daemons.
    try:import fcntl
    except ImportError:raise Invalid('managed node runtime currently requires POSIX file locking')
    fd=os.open(Path(directory)/'runtime.lock',os.O_CREAT|os.O_RDWR,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('node runtime already running; use mcp --attach')
        yield
    finally:os.close(fd)


@contextmanager
def running(node):
    value=load(node)
    if value is None:raise Invalid('run onboard with an owner-provided profile first')
    with runtime_lock(node.directory):
        server=Server(node,'0.0.0.0',value['connectivity'].get('listen_port',7443)) if policy(node)['network'] and not (node.directory/'connectivity-suspended').exists() else None
        thread=server.start() if server else None
        from .conversations import DeliveryWorker
        worker=DeliveryWorker(node);worker.start()
        from .routing import Worker as RoutingWorker
        router=RoutingWorker(node);router.start()
        try:yield
        finally:
            router.close()
            worker.close()
            if server:server.shutdown();thread.join();server.server_close()


class LocalBackend:
    def __init__(self,node):
        self.node=node
        self.operation=threading.Lock()

    def dispatch(self,request):
        if not isinstance(request,dict) or 'method' not in request:raise Invalid('invalid local request')
        method=request['method']
        if method=='tools/list' and set(request)=={'method'}:
            return [s for s in agent.schemas() if enabled(self.node,s['name'])]
        if method=='resource/read' and set(request)=={'method','uri'}:
            uri=request['uri']
            if uri not in RESOURCES:raise Invalid('unknown resource')
            if uri=='agentmesh://instructions':return files('agentmesh.assets').joinpath('llm.txt').read_text()
            if uri=='agentmesh://reference':return files('agentmesh.assets').joinpath('agent-reference.md').read_text()
            return status(self.node) if uri=='agentmesh://status' else policy(self.node)
        if method=='tool/call' and set(request)=={'method','request'}:
            obj=request['request']
            if not isinstance(obj,dict) or not isinstance(obj.get('tool'),str):raise Invalid('invalid tool call')
            if obj['tool'] not in agent.DEFINITIONS:raise Invalid('unknown tool')
            if not self.operation.acquire(blocking=False):raise Denied('node_busy: retry later with the same idempotency key')
            try:return agent.call(self.node,obj)
            finally:self.operation.release()
        raise Invalid('unsupported local request')


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(120)
        try:
            request=receive(self.request,128*1024)
            result=self.server.backend.dispatch(request)
            response={'ok':True,'result':result}
        except Exception as exc:response={'ok':False,'error':agent.error(exc)}
        try:transmit(self.request,response)
        except (OSError,Invalid):pass


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=False
    block_on_close=True
    def __init__(self,path,backend):
        self.backend=backend;self.slots=threading.BoundedSemaphore(8)
        mask=os.umask(0o077)
        try:super().__init__(str(path),_Handler)
        finally:os.umask(mask)
        os.chmod(path,0o600)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


class AttachedBackend:
    def __init__(self,directory,path=None):self.path=Path(path) if path else Path(directory)/'control.sock'
    def dispatch(self,request):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(120)
            try:conn.connect(str(self.path))
            except OSError as exc:raise OSError('local daemon unavailable; start daemon before mcp --attach') from exc
            transmit(conn,request)
            try:response=receive(conn,timeout=120)
            except (OSError,Invalid) as exc:
                if request.get('method')=='tool/call':
                    raise OSError('delivery status unknown; reconnect and retry with the SAME idempotency key') from exc
                raise
        if not response.get('ok'):
            detail=response['error']['detail']
            if response['error']['code']=='invalid_request':raise Invalid(detail)
            raise Denied(detail)
        return response['result']


def daemon(node,path=None):
    target=Path(path) if path else node.directory/'control.sock'
    # Lock the node runtime before recovering a same-owner, demonstrably stale socket.
    with running(node):
        if target.exists() or target.is_symlink():
            info=target.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():raise Denied('refuse to remove a foreign or non-socket control path')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                probe.settimeout(.5)
                try:probe.connect(str(target))
                except ConnectionRefusedError:target.unlink()
                except OSError:raise Denied('cannot establish that control socket is stale')
                else:raise Denied('control socket is live')
        control=ControlServer(target,LocalBackend(node));thread=threading.Thread(target=control.serve_forever,daemon=True)
        thread.start();stop=threading.Event()
        old={sig:signal.signal(sig,lambda *_:stop.set()) for sig in (signal.SIGINT,signal.SIGTERM)}
        try:stop.wait()
        finally:
            for sig,handler in old.items():signal.signal(sig,handler)
            control.shutdown();thread.join();control.server_close()
            target.unlink(missing_ok=True)
