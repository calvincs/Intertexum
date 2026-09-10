"""ICE/STUN/TURN with signed rendezvous and reliable DTLS/SCTP data channels.

Uses aiortc/aioice, not a home-grown UDP reliability or encryption protocol.
All async transport state belongs to one dedicated event-loop thread.
"""
import asyncio
from contextlib import nullcontext
import ipaddress
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer, RTCSessionDescription
from aiortc.rtcicetransport import parse_stun_turn_uri
from aioice.ice import TransportPolicy, get_host_addresses

from .bootstrap import BootstrapClient, check_announcement, validate_card
from .crypto import Invalid, Denied, canonical, decode, certificate, verify, valid_id
from .rendezvous import envelope, validate, DOMAIN

MAX_FRAME=16384
MAX_PAYLOAD=2*1024*1024


def configuration(obj):
    if not isinstance(obj,dict) or not set(obj)<={'network','seeds','ice_servers','relay_only','advertise_host','listen_port','mdns'}:
        raise Invalid('invalid connectivity configuration')
    out={'network':'agentmesh-demo-v1','ice_servers':[],'relay_only':False,**obj}
    if not isinstance(out['network'],str) or not 1<=len(out['network'])<=100:
        raise Invalid('invalid network')
    if not isinstance(out.get('seeds'),list) or not 0<=len(out['seeds'])<=3:
        raise Invalid('configure zero to three pinned seed cards')
    if type(out.get('mdns',True)) is not bool: raise Invalid('mdns must be boolean')
    if not out['seeds'] and (not out.get('mdns',True) or out['relay_only']): raise Invalid('seedless discovery requires mDNS without relay-only')
    if 'listen_port' in out and (type(out['listen_port']) is not int or not 1024<=out['listen_port']<=65535):raise Invalid('listen_port must be an unprivileged TCP port')
    for card in out['seeds']: validate_card(card)
    if type(out['relay_only']) is not bool: raise Invalid('relay_only must be boolean')
    if 'advertise_host' in out: ipaddress.ip_address(out['advertise_host'])
    if not isinstance(out['ice_servers'],list) or len(out['ice_servers'])>4:
        raise Invalid('at most four ICE server configurations')
    turns=0;stuns=0
    for server in out['ice_servers']:
        if not isinstance(server,dict) or not set(server)<={'urls','username','credential'} or not isinstance(server.get('urls'),str):
            raise Invalid('each ICE server needs one URL')
        try:uri=parse_stun_turn_uri(server['urls'])
        except ValueError as exc:raise Invalid('invalid ICE server URL') from exc
        if uri['scheme']=='stun':stuns+=1
        if uri['scheme']=='stuns': raise Invalid('this runtime supports STUN over UDP; use stun:')
        if uri['scheme'].startswith('turn'):
            turns+=1
            if not all(isinstance(server.get(k),str) and server[k] for k in ('username','credential')):
                raise Invalid('TURN requires authenticated username and credential')
    if turns>1 or stuns>1:raise Invalid('this runtime supports one STUN and one TURN server per node')
    if out['relay_only'] and not turns: raise Invalid('relay-only requires TURN')
    return out


def load_config(node):
    path=node.directory/'connectivity.json'
    return configuration(decode(path.read_bytes())) if path.exists() else None


def ice_connection(pc):
    # Narrow pinned-runtime adapter, also used for selected-path diagnostics.
    return pc.sctp.transport.transport._connection


def selected_path(pc):
    pairs=list(ice_connection(pc)._nominated.values())
    if not pairs: return {'path':'connecting'}
    pair=pairs[0]
    return {'path':'relay' if 'relay' in (pair.local_candidate.type,pair.remote_candidate.type) else 'direct-ice',
            'local_type':pair.local_candidate.type,'remote_type':pair.remote_candidate.type}


def check_sdp(sdp):
    if not isinstance(sdp,str) or len(sdp)>10000 or sdp.count('m=')!=1 or 'm=application ' not in sdp:
        raise Invalid('only one data-channel media section is allowed')
    count=0
    for line in sdp.splitlines():
        if line.startswith('a=candidate:'):
            count+=1
            fields=line.split()
            try:
                ip=ipaddress.ip_address(fields[4]);port=int(fields[5])
                if ip.is_unspecified or ip.is_multicast or not 1<=port<=65535: raise ValueError()
            except (IndexError,ValueError): raise Invalid('invalid numeric ICE candidate')
    if count>32 or 'a=fingerprint:sha-256 ' not in sdp:
        raise Invalid('bounded ICE candidates and SHA-256 DTLS fingerprint required')


class Session:
    def __init__(self, owner, peer, sid, pc):
        self.owner,self.peer,self.id,self.pc=owner,peer,sid,pc
        self.channel=None
        self.ready=asyncio.Event()
        self.pending={}
        self.incoming=None
        self.incoming_at=0
        self.bytes=0
        self.processing=False
        self.send_lock=asyncio.Lock()
        self.created=time.monotonic()

    def attach(self, channel):
        if self.channel is not None or channel.label!='agentmesh-rpc-v1':
            channel.close();return
        self.channel=channel
        @channel.on('open')
        def opened(): self.ready.set()
        @channel.on('message')
        def message(data):
            try:
                if not isinstance(data,bytes) or len(data)>MAX_FRAME: raise Invalid('invalid transport frame')
                self.bytes+=len(data)
                if self.bytes>16*1024*1024: raise Invalid('session byte budget exhausted')
                if data[:1]==b'S':
                    if self.incoming is not None or len(data)!=5: raise Invalid('invalid message start')
                    size=int.from_bytes(data[1:],'big')
                    if not 0<size<=MAX_PAYLOAD: raise Invalid('invalid message size')
                    self.incoming=(size,bytearray());self.incoming_at=time.monotonic()
                elif data[:1]==b'D' and self.incoming is not None:
                    size,buf=self.incoming
                    if time.monotonic()-self.incoming_at>5: raise Invalid('data-channel frame deadline')
                    buf.extend(data[1:])
                    if len(buf)>size: raise Invalid('excess message bytes')
                    if len(buf)==size:
                        self.incoming=None
                        obj=decode(bytes(buf))
                        if not isinstance(obj,dict): raise Invalid('invalid RPC envelope')
                        if set(obj)=={'response','body'}:
                            future=self.pending.get(obj['response'])
                            if future and not future.done(): future.set_result(obj['body'])
                        elif set(obj)=={'request','body'} and valid_id(obj['request']):
                            if self.processing:raise Invalid('one incoming RPC per session')
                            if len(buf)>128*1024: raise Invalid('request too large')
                            self.processing=True
                            asyncio.create_task(self.serve(obj))
                        else: raise Invalid('invalid data-channel RPC')
                else: raise Invalid('unexpected frame')
            except (Invalid,TypeError,KeyError): channel.close()
        if channel.readyState=='open': self.ready.set()

    async def send(self, obj):
        async with self.send_lock:
            await self._send(obj)

    async def _send(self, obj):
        data=canonical(obj)
        if len(data)>MAX_PAYLOAD: raise Invalid('RPC exceeds transport limit')
        if not self.channel or self.channel.readyState!='open': raise OSError('data channel closed')
        self.channel.send(b'S'+len(data).to_bytes(4,'big'))
        for start in range(0,len(data),MAX_FRAME-1):
            deadline=time.monotonic()+5
            while self.channel.bufferedAmount>65536:
                if time.monotonic()>deadline or self.channel.readyState!='open': raise OSError('send backpressure timeout')
                await asyncio.sleep(.01)
            self.channel.send(b'D'+data[start:start+MAX_FRAME-1])

    async def serve(self, obj):
        from .network import dispatch
        node=self.owner.node
        def execute():
            request=obj['body'];op=request.get('op') if isinstance(request,dict) else None
            # A relayed packet's address identifies a relay, not its origin.
            # Use verified identity for admission; never ban the relay's IP.
            source=''
            node.peer(self.peer)
            node.defense.operation(source,self.peer,op,'data')
            with node.defense.search(source,self.peer) if op=='search' else nullcontext():
                result=dispatch(node,self.peer,request)
            response={'ok':True,'result':result}
            if isinstance(result,dict) and 'results' in result and 'coverage' in result:
                while len(canonical(response))>MAX_PAYLOAD-256 and result['results']:
                    result['results'].pop();result['coverage']['results_limited_by_response_size']=True
            return response
        try:
            try: response=await asyncio.to_thread(execute)
            except Denied as exc: response={'ok':False,'error':'denied','detail':str(exc)}
            except (Invalid,TypeError,KeyError) as exc:
                node.defense.failure('',peer=self.peer,event='invalid_request')
                response={'ok':False,'error':'invalid','detail':str(exc)}
            await self.send({'response':obj['request'],'body':response})
        except (OSError,Invalid): pass
        finally: self.processing=False

    async def request(self, op, args):
        if self.pending: raise Denied('one outstanding RPC per session')
        rid=secrets.token_hex(32);future=asyncio.get_running_loop().create_future()
        self.pending[rid]=future
        try:
            await self.send({'request':rid,'body':{'op':op,'args':args}})
            return await asyncio.wait_for(future,10)
        finally:self.pending.pop(rid,None)


class Connectivity:
    def __init__(self, node, config, *, port=7443, passive=True, listen_host="0.0.0.0"):
        self.listen_host=listen_host
        self.node=node;self.config=configuration(config);self.port=port;self.passive=passive
        if not passive:self.port=self.config.get('listen_port',port)
        self.loop=asyncio.new_event_loop();self.thread=None
        self.sessions={};self.wanted=set();self.dialing=set();self.answers=set()
        self.state={'status':'starting','peers':{},'seeds':{},'reachability':'unknown'}
        self.stop_event=None;self.retry={};self.seed_retry={};self.registered={}
        self.observed={};self.last_observed={};self.last_refreshed={}
        self.db=sqlite3.connect(node.directory/'connectivity.sqlite',check_same_thread=False,isolation_level=None)
        self.db.executescript('CREATE TABLE IF NOT EXISTS generations(peer TEXT PRIMARY KEY,value INTEGER);'
            'CREATE TABLE IF NOT EXISTS endpoints(peer TEXT PRIMARY KEY,issued INTEGER,wire TEXT);')

    def start(self):
        self.thread=threading.Thread(target=self._run,daemon=True);self.thread.start()
        return self

    def _run(self):
        asyncio.set_event_loop(self.loop)
        try:self.loop.run_until_complete(self._main())
        except asyncio.CancelledError:pass
        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        self.loop.run_until_complete(self.loop.shutdown_default_executor())
        self.loop.close()

    async def _main(self):
        self.main_task=asyncio.current_task()
        self.stop_event=asyncio.Event()
        from .discovery import Discovery
        discovery=Discovery(self) if self.passive else None
        discovery_task=asyncio.create_task(discovery.run()) if discovery else None
        before=None;last_scan=0;last_exchange=0;exchange=None
        try:
            while not self.stop_event.is_set():
                if (self.node.directory/'connectivity-suspended').exists() or not __import__('agentmesh.onboarding',fromlist=['policy']).policy(self.node)['network']:
                    for s in list(self.sessions.values()):await asyncio.shield(s.pc.close())
                    self.sessions.clear();self.registered.clear();self.state['peers']={}
                    self.state['status']='suspended'
                    await asyncio.sleep(1)
                    continue
                await asyncio.gather(*(self._seed(card) for card in self.config['seeds']))
                now=time.monotonic()
                if now-last_exchange>30 and (exchange is None or exchange.done()):
                    last_exchange=now
                    exchange=asyncio.create_task(self.exchange_peers())
                if now-last_scan>10:
                    addresses=tuple(sorted(get_host_addresses(use_ipv4=True,use_ipv6=True)))
                    if before is not None and addresses!=before:
                        self.registered.clear()
                        for s in list(self.sessions.values()): await asyncio.shield(s.pc.close())
                    before=addresses;last_scan=now
                for sid,s in list(self.sessions.items()):
                    if s.pc.connectionState in ('failed','closed') or now-s.created>600 or (
                            not s.ready.is_set() and now-s.created>30):
                        await asyncio.shield(s.pc.close());self.sessions.pop(sid,None)
                        self.state['peers'].pop(s.peer,None)
                        continue
                    elif s.incoming is not None and now-s.incoming_at>5:
                        await asyncio.shield(s.pc.close())
                    if s.ready.is_set(): self.state['peers'][s.peer]=selected_path(s.pc)
                if self.passive:
                    for peer in self.wanted:
                        if self.node.id<peer and not any(s.peer==peer for s in self.sessions.values()) and peer not in self.dialing:
                            if now>=self.retry.get(peer,0): asyncio.create_task(self._reconnect(peer))
                self.state['status']='running'
                if self.passive:
                    self.state['updated_at']=int(time.time())
                    target=self.node.directory/'connectivity-status.json'
                    temp=target.with_suffix('.tmp')
                    temp.write_bytes(canonical(self.state));temp.replace(target)
                try: await asyncio.wait_for(self.stop_event.wait(),2)
                except asyncio.TimeoutError: pass
        finally:
            if discovery_task:
                discovery_task.cancel()
                await asyncio.gather(discovery_task,return_exceptions=True)
            for s in list(self.sessions.values()):await asyncio.shield(s.pc.close())
            tasks=[t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:t.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

    async def _reconnect(self, peer):
        try: await self.connect(peer)
        except (OSError,Invalid,Denied,asyncio.TimeoutError): self.retry[peer]=time.monotonic()+10

    async def _call(self, card, action, args):
        client=BootstrapClient(card,self.config['network'])
        obj=envelope(self.node,card['id'],self.config['network'],action,args)
        return await asyncio.to_thread(client.request,'connectivity',envelope=obj)

    async def _seed(self, card):
        if time.monotonic()<self.seed_retry.get(card['id'],0): return
        try:
            if time.monotonic()-self.last_observed.get(card['id'],-10000)>30:
                observed=await self._call(card,'observe',{})
                ipaddress.ip_address(observed['observed_ip'])
                old=self.observed.get(card['id'])
                self.observed[card['id']]=observed['observed_ip']
                self.last_observed[card['id']]=time.monotonic()
                self.state['observed_ip']=observed['observed_ip']
                if old is not None and old!=observed['observed_ip']:
                    self.registered.pop(card['id'],None)
                    for s in list(self.sessions.values()):await asyncio.shield(s.pc.close())
            if time.monotonic()-self.registered.get(card['id'],-10000)>300:
                host=self.config.get('advertise_host',self.observed[card['id']])
                await asyncio.to_thread(BootstrapClient(card,self.config['network']).register,self.node,host,self.port)
                self.registered[card['id']]=time.monotonic()
                if self.passive:
                    self.state['tcp_probe']=await self._call(card,'probe',{'port':self.port})
                    self.state['reachability']='tcp-reachable-from-seed' if self.state['tcp_probe']['tcp_reachable'] else 'direct-tcp-unreachable-from-seed'
            if time.monotonic()-self.last_refreshed.get(card['id'],-10000)>30:
                await self.refresh(card)
                self.last_refreshed[card['id']]=time.monotonic()
            result=await self._call(card,'poll',{'answers':list(self.answers)[:8],'offers':self.passive})
            for obj in result['messages']:
                try:await self._signal(card,obj)
                except Exception as exc:
                    # Malformed remote SDP can raise parser/transport exceptions
                    # beyond our schema errors. Isolate each mailbox item.
                    self.state['last_signal_error']=type(exc).__name__
            self.state['seeds'][card['id']]='connected'
        except (OSError,Invalid,Denied,KeyError,TypeError,ValueError) as exc:
            self.state['last_seed_error']=type(exc).__name__+': '+str(exc)[:120]
            self.state['seeds'][card['id']]='unavailable'
            self.seed_retry[card['id']]=time.monotonic()+5

    async def exchange_peers(self):
        from .network import Client
        from .openmesh import learn
        candidates=[p for p in self.node.peers() if not p['blocked']]
        for peer in __import__('random').SystemRandom().sample(candidates,min(3,len(candidates))):
            try:
                # Bounded direct RPC only: no recursive seed fallback on the loop thread.
                result=await asyncio.to_thread(Client(self.node,peer['card']['id'])._direct,'peer_view',{})
                for obj in result.get('result',{}).get('announcements',[]):
                    try:learn(self.node,obj,self.config['network'],source=peer['card']['id'])
                    except (Invalid,Denied):continue
            except (OSError,Invalid,Denied):continue

    async def refresh(self, card=None):
        for seed in [card] if card else self.config['seeds']:
            try: found=await asyncio.to_thread(BootstrapClient(seed,self.config['network']).discover)
            except (OSError,Invalid,Denied):continue
            for obj in found:
                body=check_announcement(obj,self.config['network']);peer=body['card']['id']
                if peer==self.node.id:continue
                from .openmesh import learn
                with self.node.lock:
                    watermark=self.db.execute('SELECT issued,wire FROM endpoints WHERE peer=?',(peer,)).fetchone()
                if watermark and (body['issued']<watermark[0] or (body['issued']==watermark[0] and canonical(body['card']).decode()!=watermark[1])):continue
                if not learn(self.node,obj,self.config['network']):continue
                try: current=self.node.peer(peer)['card']
                except Denied:continue
                if current['certificate']!=body['card']['certificate']:continue
                with self.node.lock:
                    old=self.db.execute('SELECT issued,wire FROM endpoints WHERE peer=?',(peer,)).fetchone()
                    wire=canonical(body['card']).decode()
                    if old and (body['issued']<old[0] or (body['issued']==old[0] and wire!=old[1])):continue
                    self.db.execute('INSERT OR REPLACE INTO endpoints VALUES(?,?,?)',(peer,body['issued'],wire))
                    self.node.db.execute('UPDATE peers SET card=? WHERE id=? AND blocked=0',(wire,peer))

    def generation(self, peer, value=None):
        # Durable across reconnects and process restarts. An old offer cannot
        # replace a newer accepted session even when a seed replays it.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old=self.db.execute('SELECT value FROM generations WHERE peer=?',(peer,)).fetchone()
            if value is None:value=(old[0] if old else 0)+1
            elif old and value<=old[0]:raise Invalid('replayed session generation')
            self.db.execute('INSERT OR REPLACE INTO generations VALUES(?,?)',(peer,value))
            self.db.execute('COMMIT');return value
        except Exception:self.db.execute('ROLLBACK');raise

    def make_session(self, peer, sid):
        if len(self.sessions)>=8:raise Denied('connection capacity reached')
        servers=[RTCIceServer(**x) for x in self.config['ice_servers']]
        pc=RTCPeerConnection(RTCConfiguration(iceServers=servers))
        s=Session(self,peer,sid,pc);self.sessions[sid]=s;self.wanted.add(peer)
        @pc.on('datachannel')
        def incoming(channel):s.attach(channel)
        return s

    def tune(self, pc):
        if self.config['relay_only']:
            conn=ice_connection(pc)
            conn._transport_policy=TransportPolicy.RELAY
            conn.stun_server=None
            # aioice's policy hides host candidates but otherwise still opens
            # host sockets. Do not create those paths in explicit relay-only mode.
            conn._use_ipv4=False;conn._use_ipv6=False

    async def _signal(self, seed, obj):
        b=validate(obj,seed['id'],self.config['network']);args=b['args'];peer=b['origin']
        known=self.node.peer(peer)['card']
        verify(obj,certificate(known['certificate']).public_key(),DOMAIN)
        if self.node.defense.blocked(peer=peer):raise Denied('signaling peer blocked')
        if b['action']!='send' or args.get('to')!=self.node.id:raise Invalid('wrong signal recipient')
        check_sdp(args.get('sdp'));sid=args['session']
        if args['type']=='answer':
            s=self.sessions.get(sid)
            if not s or s.peer!=peer or sid not in self.answers:raise Invalid('unsolicited answer')
            await s.pc.setRemoteDescription(RTCSessionDescription(args['sdp'],'answer'))
            self.answers.discard(sid)
        elif args['type']=='offer' and self.passive:
            if peer in self.dialing and self.node.id<peer:return
            self.generation(peer,args['generation'])
            for s in list(self.sessions.values()):
                if s.peer==peer:await asyncio.shield(s.pc.close());self.sessions.pop(s.id,None)
            s=self.make_session(peer,sid)
            await s.pc.setRemoteDescription(RTCSessionDescription(args['sdp'],'offer'))
            self.tune(s.pc)
            await s.pc.setLocalDescription(await s.pc.createAnswer())
            await self._call(seed,'send',dict(to=peer,session=sid,generation=args['generation'],
                type='answer',sdp=s.pc.localDescription.sdp))

    async def connect(self, peer):
        if (self.node.directory/'connectivity-suspended').exists() or not __import__('agentmesh.onboarding',fromlist=['policy']).policy(self.node)['network']:raise Denied('connectivity suspended after deregistration; configure again to resume')
        self.node.peer(peer)
        for s in self.sessions.values():
            if s.peer==peer and s.channel and s.channel.readyState=='open':return s
        if peer in self.dialing:
            deadline=time.monotonic()+30
            while peer in self.dialing and time.monotonic()<deadline:
                await asyncio.sleep(.1)
                for s in self.sessions.values():
                    if s.peer==peer and s.channel and s.channel.readyState=='open':return s
            if peer in self.dialing:raise OSError('connection establishment still in progress')
        self.dialing.add(peer)
        try:
            for seed in self.config['seeds']:
                if seed['id'] not in self.registered:
                    await self._seed(seed)
                sid=secrets.token_hex(32);s=self.make_session(peer,sid)
                try:
                    s.attach(s.pc.createDataChannel('agentmesh-rpc-v1',ordered=True))
                    self.tune(s.pc)
                    await s.pc.setLocalDescription(await s.pc.createOffer())
                    self.state['candidate_types']=sorted({c.type for c in ice_connection(s.pc).local_candidates})
                    reflexive=[c for c in ice_connection(s.pc).local_candidates if c.type=='srflx']
                    self.state['nat_mapping_observed']=(any((c.host,c.port)!=(c.related_address,c.related_port)
                        for c in reflexive) if reflexive else None)
                    self.answers.add(sid)
                    await self._call(seed,'send',dict(to=peer,session=sid,generation=self.generation('self'),
                        type='offer',sdp=s.pc.localDescription.sdp))
                    deadline=time.monotonic()+25
                    while not s.ready.is_set():
                        # Simultaneous offers resolve in favor of the smaller ID.
                        # The other incoming session may finish our pending dial.
                        for active in self.sessions.values():
                            if active.peer==peer and active.channel and active.channel.readyState=='open':
                                self.answers.discard(sid)
                                return active
                        if time.monotonic()>deadline:raise asyncio.TimeoutError()
                        await asyncio.sleep(.05)
                    self.state['peers'][peer]=selected_path(s.pc)
                    return s
                except (OSError,Invalid,Denied,asyncio.TimeoutError) as exc:
                    self.state['last_connection_error']=type(exc).__name__+': '+str(exc)[:120]
                    self.answers.discard(sid);await asyncio.shield(s.pc.close());self.sessions.pop(sid,None)
            raise OSError('direct ICE and configured relays/seeds could not connect')
        finally:self.dialing.discard(peer)

    async def rpc(self, peer, op, args):
        session=await self.connect(peer)
        try:return await session.request(op,args)
        except (OSError,asyncio.TimeoutError):
            await asyncio.shield(session.pc.close())
            # Never silently replay a possibly delivered operation.
            raise OSError('delivery status unknown; connection will be re-established for the next request')

    def request(self, peer, op, args):
        f=asyncio.run_coroutine_threadsafe(self.rpc(peer,op,args),self.loop)
        try:return f.result(timeout=110)
        except TimeoutError:
            f.cancel();raise OSError('connectivity operation timed out')

    def close(self):
        if self.thread and self.thread.is_alive():
            if self.stop_event:self.loop.call_soon_threadsafe(self.stop_event.set)
            if getattr(self,'main_task',None):self.loop.call_soon_threadsafe(self.main_task.cancel)
            self.thread.join(timeout=15)
            if self.thread.is_alive():raise OSError('connectivity shutdown timed out')
        self.db.close()
