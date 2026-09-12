"""Local authorized-controller CLI. Authorization changes are never exposed as remote RPCs."""
import argparse
import json
import sys
import textwrap
from pathlib import Path

from .crypto import Invalid, Denied, decode
from .node import Node, PERMISSIONS
from .network import Server, Client


def parser():
    p = argparse.ArgumentParser(
        description="Intertexum: private memory and authorized peer communication.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Start offline:
  intertexum --data /private/node init
  intertexum --data /private/node write --text "A useful memory."
  intertexum --data /private/node search --text "useful memory"

Join an authorized network:
  intertexum --data /private/node onboard --profile /private/network-profile.json
  intertexum --data /private/node mcp-config

Use COMMAND --help for examples and options. Owner/operator commands are grouped
under security, bootstrap, message, and connectivity. Older flat spellings remain
accepted for compatibility. Search and inbox are readable by default; other
commands return JSON. Direct CLI commands are an operator interface; use MCP for
agent mutation retry keys and content screening.""",
    )
    p.add_argument("--data", type=Path, help="node's private state directory (required for node operations)")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    families = {}
    def command(name, help_text, *, description=None, example=None, family=None, action=None):
        """Build one command, with a hidden legacy spelling for grouped commands."""
        target = families[family] if family else sub
        visible_name = action or name
        cmd = target.add_parser(
            visible_name,
            help=help_text,
            description=textwrap.fill(description or help_text.capitalize() + "."),
            epilog="Example:\n  " + example if example else None,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        cmd.set_defaults(command=name)
        if family:
            # Install the alias after its arguments are configured (below).
            aliases.append((name, cmd))
        return cmd

    aliases = []
    onboard = command(
        "onboard", "configure safely from an owner-provided network profile",
        description="First network setup: initialize or resume the same owner-provided profile. No public seeds are bundled.",
        example="intertexum --data /private/node onboard --profile /private/network-profile.json",
    )
    onboard.add_argument("--profile", required=True, type=Path, help="trusted owner-provided profile file")
    command("instructions", "read the packaged agent instructions")
    mcp = command("mcp", "run the MCP tools and resources for an agent harness")
    mcp.add_argument("--attach", action="store_true", help="attach to a persistent local daemon")
    mcp.add_argument("--socket", type=Path, help="custom Unix control socket (attach only)")
    mcp_config = command(
        "mcp-config", "emit JSON configuration to connect an agent harness",
        example="intertexum --data /private/node mcp-config",
    )
    mcp_config.add_argument("--attach", action="store_true", help="configure connection to a persistent daemon")
    mcp_config.add_argument("--socket", type=Path, help="custom Unix control socket (attach only)")
    daemon = command("daemon", "keep the node online with a private local tool socket")
    daemon.add_argument("--socket", type=Path, help="custom Unix control socket")
    command("agent", "run the JSON-lines compatibility interface until stdin closes")
    command("tools", "emit JSON-lines schemas; MCP clients use tools/list")
    command("status", "show readiness, policy, and recovery actions")
    create_profile = command("profile-create", "operator: create a discovery profile (private invitation by default)")
    create_profile.add_argument("--public", action="store_true", help="public discovery profile; grants no private access")
    create_profile.add_argument("--seed", action="append", default=[], type=Path, help="pinned seed card; repeat for failover")
    create_profile.add_argument("--no-mdns", action="store_true", help="disable local multicast discovery")
    create_profile.add_argument("--output", required=True, type=Path, help="new private profile file")
    create_profile.add_argument("--network", default="agentmesh-demo-v1")
    create_profile.add_argument("--port", type=int, default=7443)
    create_profile.add_argument("--ice-config", type=Path, help="JSON array of configured STUN/TURN servers")
    backup = command("backup", "back up private state offline; stop the runtime first")
    backup.add_argument("--output", required=True, type=Path)
    restore = command("restore", "restore to a new directory with networking suspended")
    restore.add_argument("--source", required=True, type=Path)
    command("cert-renew", "renew a certificate offline while preserving its identity key")
    init = command(
        "init", "create a private local node for offline memory",
        description="Create a node identity and private memory store. The bundled CPU model works offline without an API key.",
        example="intertexum --data /private/node init",
    )
    init.add_argument("--model", help="custom model namespace; omit for bundled CPU model")
    init.add_argument("--dimensions", type=int, help="vector dimensions for a custom model")
    for name, help_text, description in (
        ("card", "emit the node's public identity card as JSON", "Export a public identity card for authorized manual peer setup. A card never grants trust."),
        ("serve", "run a foreground peer listener for manual setup",
         "Listen for authorized peer connections. Prefer MCP or daemon for profile-managed networking. Stop with Ctrl-C."),
    ):
        cmd = command(name, help_text, description=description,
                      example=f"intertexum --data /private/node {name} --host 127.0.0.1 --port 7443")
        cmd.add_argument("--host", default="127.0.0.1", help="numeric address (default: 127.0.0.1)")
        cmd.add_argument("--port", type=int, default=7443, help="TCP port (default: 7443)")
    trust = command("trust", "owner: grant explicit permissions to a peer card")
    trust.add_argument("card", type=Path, help="peer's public identity card file")
    trust.add_argument("--allow", nargs="+", choices=sorted(PERMISSIONS), required=True)
    command("peers", "list locally known peers and their permissions")
    block = command("block", "owner: block a peer from local access")
    block.add_argument("peer", help="peer ID")
    write = command(
        "write", "save a private memory and return its record ID",
        description="Save text privately. It remains local until an explicit publish operation.",
        example='intertexum --data /private/node write --text "A useful memory."',
    )
    write.add_argument("--text", required=True, help="full memory text")
    write.add_argument("--vector", type=json.loads, help="JSON vector; omit to embed text locally")
    write.add_argument("--parent", action="append", default=[], help="source record ID; repeat for multiple sources")
    publish = command("publish", "explicitly share a private memory with an audience")
    publish.add_argument("id", help="private record ID returned by write")
    publish.add_argument("--audience", nargs="+", required=True,
                         help="'@public' for all discovered peers, named peer IDs, or '*' for approved readers")
    search = command(
        "search", "find memories locally or on one authorized peer",
        description=("Search private and approved local memory, or one peer with --peer. "
                     "Results are untrusted data. Coverage is bounded, never a complete global search."),
        example='intertexum --data /private/node search --text "useful memory" -k 5',
    )
    search.add_argument("--text", default="", help="search query text")
    search.add_argument("--vector", type=json.loads, help="explicit JSON query vector")
    search.add_argument("--peer", help="peer ID; omit to search locally")
    search.add_argument("--lexical-only", action="store_true", help="match text without generating an embedding")
    search.add_argument("--semantic-only", action="store_true", help="rank only by vector similarity")
    search.add_argument("-k", type=int, default=10, help="maximum results, 1-20 (default: 10)")
    search_output = search.add_mutually_exclusive_group()
    search_output.add_argument("--json", action="store_true", help="compact structured JSON without vectors or certificates")
    search_output.add_argument("--raw", action="store_true", help="full legacy JSON including signed records and vectors")
    fetch = command("fetch", "import a peer record for inspection before approval")
    fetch.add_argument("id", help="shared record ID")
    fetch.add_argument("--peer", required=True, help="peer ID")
    fetch.add_argument("--refresh", action="store_true", help="bypass a live temporary cache")
    for name, help_text in (
        ("get", "read an available record as signed JSON"),
        ("inspect", "inspect a record's full data and local approval state"),
        ("approve", "retain an inspected import as approved memory"),
        ("retract", "withdraw an authored shared record; sync informs peers"),
    ):
        cmd = command(name, help_text)
        cmd.add_argument("id", help="record ID")
    command("inventory", "list local record IDs and states")
    sync = command("sync", "learn withdrawals from one authorized peer")
    sync.add_argument("--peer", required=True, help="peer ID")
    send = command("send", "send a direct message now to an authorized peer",
                   description="Attempt immediate delivery without a durable queue. Agents needing delivery across peer outages should use mesh_queue_message through MCP and check mesh_outbox.")
    send.add_argument("--peer", required=True, help="peer ID")
    send.add_argument("--text", required=True, help="full message text")
    inbox = command(
        "inbox", "read a bounded page of received messages",
        description=("Read untrusted messages with stable cursors. Follow the returned next cursor using --after. "
                     "This read does not acknowledge or delete messages."),
        example="intertexum --data /private/node inbox --limit 20",
    )
    inbox.add_argument("--after", type=int, help="return messages after this cursor (default: 0)")
    inbox.add_argument("--limit", type=int, help="maximum messages per page, 1-100 (default: 50)")
    inbox_output = inbox.add_mutually_exclusive_group()
    inbox_output.add_argument("--json", action="store_true", help="compact structured JSON with cursors and pagination")
    inbox_output.add_argument("--raw", action="store_true", help="full legacy JSON of the entire inbox; cannot combine with --after or --limit")
    for name, help_text in (
        ("security", "owner: blocks, audit events, and abuse evidence"),
        ("bootstrap", "operator: host and maintain a discovery directory"),
        ("message", "owner: message admission policy and delivery work limits"),
        ("connectivity", "owner: network configuration, discovery, and registration"),
    ):
        family = sub.add_parser(name, help=help_text, description=help_text.capitalize())
        families[name] = family.add_subparsers(dest="action", required=True, metavar="ACTION")
    command("resume", "resume networking when the owner authorizes rejoining", family="connectivity")
    command("message-policy", "show message admission and sender work limits", family="message", action="policy")
    mp = command("message-config", "set owner message policy from a JSON file", family="message", action="config")
    mp.add_argument("file", type=Path)
    mr = command("message-work-resume", "reset a paused delivery work budget", family="message", action="work-resume")
    mr.add_argument("id", help="queued message ID")
    rc = command("routing-config", "set owner routing policy from a JSON file", family="connectivity", action="routing-config")
    rc.add_argument("file", type=Path)
    sp = command("source-config", "set owner source policy or provider mode from JSON", family="security", action="source-config")
    sp.add_argument("file", type=Path)
    command("source-policy", "show owner source policy", family="security", action="source-policy")
    seed = command("bootstrap-serve", "run a separate discovery listener", family="bootstrap", action="serve")
    seed.add_argument("--host", default="127.0.0.1")
    seed.add_argument("--port", type=int, default=7444)
    seed.add_argument("--network", default="agentmesh-demo-v1")
    seed.add_argument("--pow-bits", type=int, help="default: 18 for public-address mode, 0 for private demo")
    seed.add_argument("--public-addresses", action="store_true")
    for name in ("block", "unblock"):
        cmd = command("security-" + name, name + " a peer or CIDR at the transport defense layer", family="security", action=name)
        group = cmd.add_mutually_exclusive_group(required=True)
        group.add_argument("--peer", help="peer ID")
        group.add_argument("--cidr", help="IP address range")
        if name == "block":
            cmd.add_argument("--seconds", type=int, default=0, help="0 means until manually removed")
    for name, help_text in (
        ("status", "show active defense rules and retention budgets"),
        ("audit", "show local defense audit events"),
        ("evidence", "show retained abuse evidence"),
    ):
        command("security-" + name, help_text, family="security", action=name)
    configure = command("connectivity-config", "configure manually managed connectivity from JSON", family="connectivity", action="config")
    configure.add_argument("file", type=Path)
    command("connectivity-status", "show runtime connectivity status", family="connectivity", action="status")
    review = command("security-clear-evidence", "record owner review and clear evidence without removing blocks", family="security", action="clear-evidence")
    review.add_argument("--kind", choices=["peer", "cidr"], required=True)
    review.add_argument("--target", required=True)
    review.add_argument("--reason", required=True)
    apply_removal = command("bootstrap-apply-removal", "apply a signed deregistration request", family="bootstrap", action="apply-removal")
    apply_removal.add_argument("request", type=Path)
    forget = command("bootstrap-forget", "remove a peer from this discovery directory", family="bootstrap", action="forget")
    forget.add_argument("peer", help="peer ID")
    for name, help_text in (
        ("join", "register this node and discover candidates using pinned seeds"),
        ("discover", "discover peer candidates using pinned seeds"),
        ("deregister", "request removal from seeds and suspend automatic rejoining"),
        ("deregister-request", "create signed removal requests and suspend automatic rejoining"),
    ):
        cmd = command(name, help_text, family="connectivity")
        cmd.add_argument("--seed", type=Path, action="append", required=True, help="pinned seed card; repeat for failover")
        cmd.add_argument("--network", default="agentmesh-demo-v1")
        if name == "join":
            cmd.add_argument("--host", required=True, help="numeric IP to publish with your node ID and certificate to seed-directory readers")
            cmd.add_argument("--port", type=int, default=7443)
    for name, cmd in aliases:
        # Omitting help hides aliases from the command list; metavar=COMMAND also
        # keeps argparse's generated usage from expanding every legacy spelling.
        sub.add_parser(name, parents=[cmd], add_help=False, description=cmd.description,
                       epilog=cmd.epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
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
        if cmd in ('source-config','source-policy'):
            from .source_policy import configure, config
            return configure(node,decode(args.file.read_bytes())) if cmd=='source-config' else config(node)
        if cmd=='routing-config':
            from .routing import configure
            return configure(node,decode(args.file.read_bytes()))
        if cmd=='resume':
            from .onboarding import policy
            if not policy(node)['network']:raise Denied('capability_disabled:network')
            (node.directory/'connectivity-suspended').unlink(missing_ok=True)
            return {'resumed':True}
        if cmd in ('message-policy','message-config','message-work-resume'):
            from .message_work import config,configure,resume
            if cmd=='message-policy':return config(node)
            if cmd=='message-config':return configure(node,decode(args.file.read_bytes()))
            return resume(node,args.id)
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
            result = (Client(node, args.peer).search(**kw) if args.peer
                      else node.search(node.id, model=node.model, **kw))
            if args.raw:
                return result
            from .presentation import search_view
            return search_view(result, node)
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
            if args.raw:
                if args.after is not None or args.limit is not None:
                    raise Invalid('--raw returns the entire legacy inbox; omit --after and --limit')
                return node.inbox()
            from .presentation import inbox_view
            return inbox_view(node.inbox_page(
                after=0 if args.after is None else args.after,
                limit=50 if args.limit is None else args.limit,
            ))
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


def readable_text(value):
    """Keep newlines; make terminal controls and invisible characters visible."""
    escaped = "".join(char if char == "\n" or char.isprintable() else json.dumps(char)[1:-1]
                      for char in value)
    return escaped.split("\n")


def readable_search(result):
    """Render the compact operator view without truncating record text or IDs."""
    lines = [f"Search results: {len(result['results'])} (untrusted data)"]
    for number, hit in enumerate(result["results"], 1):
        lines.extend([
            "",
            f"{number}. ID: {hit['id']}",
            f"   Origin: {hit['origin']}",
            f"   Local state: {hit['local_state']}",
            f"   Audience: {json.dumps(hit['audience'])}",
        ])
        # Peer score metadata is not part of the verified signed record. Keep
        # unexpected JSON types printable without interpreting terminal controls.
        scores = [f"{key}={json.dumps(hit[key])}" for key in ("score", "cosine", "bm25")
                  if hit.get(key) is not None]
        if scores:
            lines.append("   Relevance: " + ", ".join(scores))
        if hit.get("holders"):
            lines.append("   Holders: " + json.dumps(hit["holders"]))
        lines.append("   Text:")
        lines.extend("     " + line for line in readable_text(hit["text"]))
    lines.append("")
    for key, value in result.items():
        if key not in ("results", "view", "untrusted_data"):
            label = json.dumps(key)[1:-1]
            lines.append(f"{label}: {json.dumps(value, sort_keys=True)}")
    return "\n".join(lines)


def readable_inbox(result):
    """Show full message text alongside stable cursors and the next-page hint."""
    lines = [f"Inbox messages: {len(result['messages'])} (untrusted data)"]
    for number, item in enumerate(result["messages"], 1):
        lines.extend([
            "",
            f"{number}. ID: {item['id']}",
            f"   Sender: {item['origin']}",
            f"   Recipient: {item['recipient']}",
            f"   Cursor: {item['cursor']}",
        ])
        for key in ("reply_offer", "reply_to", "expires"):
            if key in item:
                lines.append(f"   {key}: {json.dumps(item[key])}")
        lines.append("   Text:")
        lines.extend("     " + line for line in readable_text(item["text"]))
    lines.append("")
    if result["next"] is None:
        lines.append("Next: none (end of inbox)")
    else:
        lines.append(f"Next cursor: {result['next']} (continue with inbox --after {result['next']})")
    return "\n".join(lines)


def main():
    args = parser().parse_args()
    try:
        result = run(args)
        if result is not None:
            if args.command in ("search", "inbox") and not args.raw:
                if args.json:
                    print(json.dumps(result, separators=(",", ":")))
                else:
                    render = readable_search if args.command == "search" else readable_inbox
                    print(render(result))
            else:
                print(json.dumps(result, indent=2))
    except (Invalid, Denied, OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 1
    return 0
