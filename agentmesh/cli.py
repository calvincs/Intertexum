"""Local authorized-controller CLI. Authorization changes are never exposed as remote RPCs."""
import argparse
import json
import sys
from pathlib import Path

from .crypto import Invalid, Denied, decode
from .node import Node, PERMISSIONS
from .network import Server, Client


def parser():
    p = argparse.ArgumentParser(description="Intertexum local node")
    p.add_argument("--data", type=Path, help="node's private state directory (required for node operations)")
    sub = p.add_subparsers(dest="command", required=True)
    onboard=sub.add_parser('onboard',help='idempotently configure from an owner-provided public or private network profile')
    onboard.add_argument('--profile',required=True,type=Path)
    sub.add_parser('instructions',help='read the packaged agent instructions')
    mcp=sub.add_parser('mcp',help='official MCP stdio tools and resources')
    mcp.add_argument('--attach',action='store_true',help='attach to a persistent local daemon')
    mcp.add_argument('--socket',type=Path,help='custom Unix control socket (attach only)')
    mcp_config=sub.add_parser('mcp-config',help='emit a common mcpServers harness configuration')
    mcp_config.add_argument('--attach',action='store_true')
    mcp_config.add_argument('--socket',type=Path)
    daemon=sub.add_parser('daemon',help='persistent node with a private local tool socket')
    daemon.add_argument('--socket',type=Path)
    sub.add_parser('agent',help='run listener and JSON-lines agent tools until stdin closes')
    sub.add_parser('tools',help='machine-readable agent tool schemas')
    sub.add_parser('resume',help='owner-authorized resumption after deregistration')
    sub.add_parser('status',help='readiness, policy and recovery actions')
    create_profile=sub.add_parser('profile-create',help='operator: create a discovery profile (private invitation by default)')
    create_profile.add_argument('--public',action='store_true',help='public discovery profile; grants no private access')
    create_profile.add_argument('--seed',action='append',default=[],type=Path)
    create_profile.add_argument('--no-mdns',action='store_true',help='disable local multicast discovery')
    create_profile.add_argument('--output',required=True,type=Path)
    create_profile.add_argument('--network',default='agentmesh-demo-v1')
    create_profile.add_argument('--port',type=int,default=7443)
    create_profile.add_argument('--ice-config',type=Path,help='JSON array of configured STUN/TURN servers')
    backup=sub.add_parser('backup',help='offline private state backup; stop runtime first')
    backup.add_argument('--output',required=True,type=Path)
    restore=sub.add_parser('restore',help='restore to a new directory, with networking suspended')
    restore.add_argument('--source',required=True,type=Path)
    sub.add_parser('cert-renew',help='offline same-key certificate renewal')
    init = sub.add_parser("init")
    init.add_argument("--model", help='custom model namespace; omit for bundled CPU model')
    init.add_argument("--dimensions", type=int)
    for name in ("card", "serve"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--host", default="127.0.0.1")
        cmd.add_argument("--port", type=int, default=7443)
    trust = sub.add_parser("trust")
    trust.add_argument("card", type=Path)
    trust.add_argument("--allow", nargs="+", choices=sorted(PERMISSIONS), required=True)
    sub.add_parser("peers")
    block = sub.add_parser("block")
    block.add_argument("peer")
    write = sub.add_parser("write")
    write.add_argument("--text", required=True)
    write.add_argument("--vector", type=json.loads, help='omit to embed text locally')
    write.add_argument("--parent", action="append", default=[])
    publish = sub.add_parser("publish")
    publish.add_argument("id")
    publish.add_argument("--audience", nargs="+", required=True, help="peer IDs, or '*' for approved mesh readers")
    search = sub.add_parser("search")
    search.add_argument("--text", default="")
    search.add_argument("--vector", type=json.loads)
    search.add_argument("--peer")
    search.add_argument('--lexical-only', action='store_true')
    search.add_argument('--semantic-only', action='store_true')
    search.add_argument("-k", type=int, default=10)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("id")
    fetch.add_argument("--peer", required=True)
    fetch.add_argument("--refresh", action="store_true", help="bypass a live temporary cache")
    for name in ("get", "inspect", "approve", "retract"):
        cmd = sub.add_parser(name)
        cmd.add_argument("id")
    sub.add_parser("inventory")
    sync = sub.add_parser("sync")
    sync.add_argument("--peer", required=True)
    send = sub.add_parser("send")
    send.add_argument("--peer", required=True)
    send.add_argument("--text", required=True)
    sub.add_parser("inbox")
    seed = sub.add_parser('bootstrap-serve', help='run a separate discovery listener')
    seed.add_argument('--host', default='127.0.0.1')
    seed.add_argument('--port', type=int, default=7444)
    seed.add_argument('--network', default='agentmesh-demo-v1')
    seed.add_argument('--pow-bits', type=int, help='default: 18 for public-address mode, 0 for private demo')
    seed.add_argument('--public-addresses', action='store_true')
    for name in ('security-block','security-unblock'):
        cmd=sub.add_parser(name)
        group=cmd.add_mutually_exclusive_group(required=True)
        group.add_argument('--peer')
        group.add_argument('--cidr')
        if name=='security-block':
            cmd.add_argument('--seconds',type=int,default=0,help='0 means until manually removed')
    sub.add_parser('security-status')
    sub.add_parser('security-audit')
    sub.add_parser('security-evidence')
    configure=sub.add_parser('connectivity-config')
    configure.add_argument('file',type=Path)
    sub.add_parser('connectivity-status')
    review=sub.add_parser('security-clear-evidence')
    review.add_argument('--kind',choices=['peer','cidr'],required=True)
    review.add_argument('--target',required=True)
    review.add_argument('--reason',required=True)
    apply_removal=sub.add_parser('bootstrap-apply-removal')
    apply_removal.add_argument('request',type=Path)
    forget=sub.add_parser('bootstrap-forget')
    forget.add_argument('peer')
    for name in ('join','discover','deregister','deregister-request'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--seed', type=Path, action='append', required=True, help='pinned seed card; repeat for failover')
        cmd.add_argument('--network', default='agentmesh-demo-v1')
        if name == 'join':
            cmd.add_argument('--host', required=True, help='numeric IP to publish with your node ID and certificate to seed-directory readers')
            cmd.add_argument('--port', type=int, default=7443)
    return p


def run(args):
    if args.data is None and args.command not in ('instructions','tools','profile-create'):
        raise Invalid('--data is required for node operations')
    if args.command in ('backup','restore','cert-renew'):
        from .operations import backup,restore,renew
        if args.command=='backup':return backup(args.data,args.output)
        if args.command=='restore':return restore(args.source,args.data)
        return renew(args.data)
    if args.command=='mcp-config':
        if args.socket and not args.attach:raise Invalid('--socket requires --attach')
        command=['-m','agentmesh','--data',str(args.data.resolve()),'mcp']
        if args.attach:command.append('--attach')
        if args.socket:command.extend(['--socket',str(args.socket.resolve())])
        return {'mcpServers':{'agentmesh':{'command':sys.executable,'args':command}}}
    if args.command=='mcp' and args.attach:
        import asyncio
        from .service import AttachedBackend
        from .mcp_server import run as mcp_run
        asyncio.run(mcp_run(AttachedBackend(args.data,args.socket)))
        return None
    if args.command=='instructions':
        from importlib.resources import files
        return {'instructions':files('agentmesh.assets').joinpath('llm.txt').read_text()}
    if args.command=='tools':
        from .agent import schemas
        return {'protocol':'agentmesh-jsonl-v1','tools':schemas()}
    if args.command=='onboard':
        from .onboarding import setup
        return setup(args.data,decode(args.profile.read_bytes()))
    if args.command=='profile-create':
        import secrets
        from .onboarding import profile,private_write
        if args.output.exists():raise Denied('refuse to overwrite an existing invitation profile')
        value=profile({'version':1,'connectivity':{'network':args.network,'listen_port':args.port,
            'seeds':[decode(p.read_bytes()) for p in args.seed],'mdns':not args.no_mdns,
            'ice_servers':decode(args.ice_config.read_bytes()) if args.ice_config else []},
            'admission':{'mode':'public'} if args.public else {'key':secrets.token_hex(32),'permissions':['read','publish','message']}})
        private_write(args.output,value)
        return {'created':str(args.output),'private_invitation':not args.public,'next_action':'distribute profile; keep TURN credentials private if included'}
    node = (Node.create(args.data, model=args.model, dimensions=args.dimensions)
            if args.command == "init" else Node(args.data))
    try:
        cmd = args.command
        if cmd=='resume':
            from .onboarding import policy
            if not policy(node)['network']:raise Denied('capability_disabled:network')
            (node.directory/'connectivity-suspended').unlink(missing_ok=True)
            return {'resumed':True}
        if cmd=='status':
            from .onboarding import status
            return status(node)
        if cmd=='mcp':
            if args.socket:raise Invalid('--socket requires --attach')
            import asyncio
            from .service import LocalBackend,running
            from .mcp_server import run as mcp_run
            with running(node):asyncio.run(mcp_run(LocalBackend(node)))
            return None
        if cmd=='daemon':
            from .service import daemon
            daemon(node,args.socket)
            return None
        if cmd=='agent':
            from .agent import runtime
            runtime(node)
            return None
        if cmd == "init":
            return {"id": node.id, "data": str(args.data.resolve())}
        if cmd == "card":
            return node.card(args.host, args.port)
        if cmd=='connectivity-config':
            from .connectivity import configuration
            from .onboarding import load
            if load(node):raise Denied("profile-managed connectivity: edit through the owner provisioning process")
            import os
            config=configuration(decode(args.file.read_bytes()))
            target=node.directory/'connectivity.json'
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as f:json.dump(config,f,indent=2)
            (node.directory/'connectivity-suspended').unlink(missing_ok=True)
            return {'configured':True,'restart_listener_to_apply':True}
        if cmd=='connectivity-status':
            path=node.directory/'connectivity-status.json'
            if (node.directory/'connectivity-suspended').exists():return {'status':'suspended'}
            return decode(path.read_bytes()) if path.exists() else {'status':'not running or not yet reported'}
        if cmd == "serve":
            from .service import runtime_lock
            with runtime_lock(node.directory), Server(node, args.host, args.port) as server:
                print(json.dumps({"listening": server.server_address, "id": node.id}), flush=True)
                try:
                    server.serve_forever(poll_interval=.1)
                except KeyboardInterrupt:
                    pass
                return None
        if cmd == "trust":
            node.trust(decode(args.card.read_bytes()), args.allow)
            return {"approved": True}
        if cmd == "peers":
            return node.peers()
        if cmd == "block":
            node.block(args.peer)
            return {"blocked": args.peer}
        if cmd == "write":
            rid = (node.write_text(args.text,parents=args.parent) if args.vector is None else
                   node.write_private(args.text,args.vector,parents=args.parent))
            return {"id": rid, "state": "private"}
        if cmd == "publish":
            return {"id": node.publish(args.id, audience=args.audience), "state": "accepted"}
        if cmd == "search":
            if args.lexical_only and (args.semantic_only or args.vector is not None):
                raise Invalid('lexical-only cannot be combined with semantic search')
            query_vector = args.vector
            if query_vector is None and args.text and not args.lexical_only:
                from .embedding import encode_for, profile
                if node.model == profile()['id']:
                    query_vector = encode_for(node,args.text,query=True)
                elif args.semantic_only:
                    raise Invalid('custom profile requires an explicit vector for semantic search')
            kw = dict(query_text='' if args.semantic_only else args.text, query_vector=query_vector, k=args.k)
            return (Client(node, args.peer).search(**kw) if args.peer
                    else node.search(node.id, model=node.model, **kw))
        if cmd == "fetch":
            return {"id": Client(node, args.peer).fetch(args.id,refresh=args.refresh), "state": "imported; inspect before approval"}
        if cmd == "approve":
            node.approve(args.id)
            return {"approved": args.id}
        if cmd == "inspect":
            return node.inspect(args.id)
        if cmd == "get":
            return {"record": node.get(args.id, node.id), "untrusted_data": True}
        if cmd == "retract":
            return node.retract(args.id)
        if cmd == "inventory":
            return node.inventory()
        if cmd == "sync":
            return Client(node, args.peer).sync_retractions()
        if cmd == "send":
            return Client(node, args.peer).send(args.text)
        if cmd == "inbox":
            return node.inbox()
        if cmd in ('security-block','security-unblock'):
            kind,target=('peer',args.peer) if args.peer else ('cidr',args.cidr)
            if cmd=='security-block': node.defense.block(kind,target,seconds=args.seconds)
            else: node.defense.unblock(kind,target)
            return {'rules':node.defense.rules()}
        if cmd=='security-status': return {'rules':node.defense.rules(),'retention':node.defense.retention_status()}
        if cmd=='security-audit': return node.defense.events()
        if cmd=='security-evidence': return node.defense.evidence()
        if cmd=='security-clear-evidence':
            node.defense.clear_evidence(args.kind,args.target,args.reason)
            return {'reviewed':True,'blocks_unchanged':True}
        if cmd=='bootstrap-apply-removal':
            from .bootstrap import Directory
            import sqlite3
            path=node.directory/'bootstrap.sqlite'
            if not path.exists(): raise Invalid('no bootstrap directory')
            with sqlite3.connect(path) as db:
                network,public=json.loads(db.execute("SELECT value FROM settings WHERE key='policy'").fetchone()[0])
            directory=Directory(node,network=network,public=public)
            try: return directory.deregister(decode(args.request.read_bytes()))
            finally: directory.close()
        if cmd=='bootstrap-forget':
            from .crypto import valid_id
            import sqlite3
            if not valid_id(args.peer): raise Invalid('invalid peer ID')
            path=node.directory/'bootstrap.sqlite'
            if not path.exists(): raise Invalid('no bootstrap directory')
            with sqlite3.connect(path) as db:
                db.execute('DELETE FROM announcements WHERE peer=?',(args.peer,))
            node.defense.audit('directory_forget',peer=args.peer)
            return {'removed':args.peer,'note':'Does not revoke announcements already copied by others.'}
        if cmd == 'bootstrap-serve':
            from .bootstrap import Directory, BootstrapServer
            directory = Directory(node, network=args.network, bits=args.pow_bits, public=args.public_addresses)
            try:
                with BootstrapServer(directory,args.host,args.port) as server:
                    print(json.dumps({'listening':server.server_address,'id':node.id,
                        'network':args.network,'pow_bits':directory.issuer.bits}),flush=True)
                    try:
                        server.serve_forever(poll_interval=.1)
                    except KeyboardInterrupt:
                        pass
            finally:
                directory.close()
            return None
        if cmd in ('deregister','deregister-request'):
            from .bootstrap import BootstrapClient
            from .erasure import request
            # Prevent a running listener from renewing a removed registration.
            (node.directory/'connectivity-suspended').touch(mode=0o600)
            receipts,failures=[],[]
            for path in args.seed:
                try:
                    client=BootstrapClient(decode(path.read_bytes()),args.network)
                    receipts.append(client.deregister(node) if cmd=='deregister' else
                                    request(node,client.card['id'],args.network))
                except (Invalid,Denied,OSError) as exc:
                    failures.append({'seed':str(path),'error':str(exc)})
            return {'receipts' if cmd=='deregister' else 'requests':receipts,'failed_seeds':failures,
                    'all_seeds_acknowledged':not failures if cmd=='deregister' else False}
        if cmd in ('join','discover'):
            node.capability('network')
            from .bootstrap import BootstrapClient
            seeds, failures, found = [], [], {}
            for path in args.seed:
                try:
                    client = BootstrapClient(decode(path.read_bytes()),args.network)
                    if cmd == 'join':
                        client.register(node,args.host,args.port)
                    for obj in client.discover():
                        peer = obj['body']['card']['id']
                        if peer != node.id and (peer not in found or obj['body']['issued'] > found[peer]['body']['issued']):
                            found[peer] = obj
                    seeds.append(client.card['id'])
                except (OSError,Invalid,Denied) as exc:
                    failures.append({'seed':str(path),'error':str(exc)})
            if not seeds:
                raise Denied('no seed completed discovery: '+json.dumps(failures))
            return {'seeds':seeds,'failed_seeds':failures,'candidates':list(found.values()),
                    'permissions_granted':[], 'note':'Review candidate cards and approve locally with trust.'}
    finally:
        node.close()


def main():
    args = parser().parse_args()
    try:
        result = run(args)
        if result is not None:
            print(json.dumps(result, indent=2))
    except (Invalid, Denied, OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 1
    return 0
