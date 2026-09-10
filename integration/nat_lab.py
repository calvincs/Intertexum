"""Real Linux NAT routers + coturn, entirely inside unshared user/net namespaces.

Run: unshare -Urn .venv/bin/python -m integration.nat_lab --turnserver PATH
The parent namespace must already be isolated; never run against host networking.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time

from agentmesh.node import Node
from agentmesh.bootstrap import Directory,BootstrapServer


def command(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout


def inside(pid,*args):return command('nsenter','-t',str(pid),'-n',*args)


def read(process,timeout=60):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(timeout):raise RuntimeError('worker response timeout')
    line=process.stdout.readline()
    if not line:raise RuntimeError('worker exited')
    result=json.loads(line)
    if result.get('ok') is False:raise RuntimeError(str(result))
    return result


def rpc(p,op,**args):
    p.stdin.write(json.dumps(dict(op=op,**args))+'\n');p.stdin.flush()
    return read(p)['result']


def wait_ready(workers,seedid):
    end=time.monotonic()+40
    while time.monotonic()<end:
        states=[rpc(w,'status') for w in workers]
        if all(s['seeds'].get(seedid)=='connected' for s in states):return states
        time.sleep(1)
    raise RuntimeError('registration/signaling not ready: '+json.dumps(states))


def run(turnserver,root):
    # User namespaces give scoped root, not host root. Require nonidentity uid mapping.
    mapping=Path('/proc/self/uid_map').read_text().split()
    if os.geteuid()!=0 or len(mapping)!=3 or mapping[0]!='0' or mapping[2]!='1':
        raise RuntimeError('run inside unshare -Urn; refusing host network changes')
    ns=[];workers=[];turn=None;nodes=[];seedserver=None
    try:
        command('ip','link','set','lo','up')
        command('sysctl','-w','net.ipv4.ip_forward=1')
        for _ in range(4):
            p=subprocess.Popen(['unshare','-n','sleep','600']);ns.append(p)
            for _ in range(100):
                if os.readlink(f'/proc/{p.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
                time.sleep(.01)
            inside(p.pid,'ip','link','set','lo','up')
        routers=[ns[0].pid,ns[1].pid];clients=[ns[2].pid,ns[3].pid]
        for i,(r,c) in enumerate(zip(routers,clients),1):
            command('ip','link','add',f'w{i}','type','veth','peer','name',f'e{i}')
            command('ip','link','set',f'e{i}','netns',str(r))
            command('ip','addr','add',f'10.20.{i}.1/24','dev',f'w{i}')
            command('ip','link','set',f'w{i}','up')
            inside(r,'ip','link','set',f'e{i}','name','ext0')
            inside(r,'ip','addr','add',f'10.20.{i}.2/24','dev','ext0')
            inside(r,'ip','link','set','ext0','up')
            inside(r,'ip','route','add','default','via',f'10.20.{i}.1')
            command('ip','link','add',f'l{i}','type','veth','peer','name',f'c{i}')
            command('ip','link','set',f'l{i}','netns',str(r))
            command('ip','link','set',f'c{i}','netns',str(c))
            inside(r,'ip','link','set',f'l{i}','name','lan0')
            inside(r,'ip','addr','add','192.168.1.1/24','dev','lan0')
            inside(r,'ip','link','set','lan0','up')
            inside(c,'ip','link','set',f'c{i}','name','eth0')
            inside(c,'ip','addr','add','192.168.1.2/24','dev','eth0')
            inside(c,'ip','link','set','eth0','up')
            inside(c,'ip','route','add','default','via','192.168.1.1')
            inside(r,'sysctl','-w','net.ipv4.ip_forward=1')
            inside(r,'iptables','-t','nat','-A','POSTROUTING','-o','ext0','-j','MASQUERADE')
            # Port-preserving NAT with stateful filtering, like a cone router.
            inside(r,'iptables','-t','nat','-A','PREROUTING','-i','ext0','-p','udp','-j','DNAT','--to-destination','192.168.1.2')
            inside(r,'iptables','-P','FORWARD','DROP')
            inside(r,'iptables','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
            inside(r,'iptables','-A','FORWARD','-i','lan0','-o','ext0','-j','ACCEPT')
        # A WAN host has a default route: unroutable private candidates must
        # time out, not kill coturn allocations with immediate ENETUNREACH.
        command('ip','route','add','default','via','10.20.1.254')
        cfg=root/'turn.conf'
        cfg.write_text('listening-ip=10.20.1.1\nrelay-ip=10.20.1.1\nlistening-port=3478\n'
            'realm=agentmesh-test\nlt-cred-mech\nuser=mesh:test-password\nfingerprint\n'
            'no-tls\nno-dtls\nno-cli\nno-multicast-peers\n'
            'min-port=50000\nmax-port=50050\ntotal-quota=16\nuser-quota=16\n'
            'relay-threads=1\nverbose\n')
        log=(root/'turn.log').open('w')
        turn=subprocess.Popen([turnserver,'-c',str(cfg),'--pidfile',str(root/'turn.pid'),'--log-file','stdout'],stdout=log,stderr=log)
        time.sleep(.4)
        if turn.poll() is not None:raise RuntimeError('coturn failed; '+(root/'turn.log').read_text()[-2000:])
        for name in ('seed','alice','bob'):nodes.append(Node.create(root/name,model='nat-lab',dimensions=3))
        seed,a,b=nodes;directory=Directory(seed)
        seedserver=BootstrapServer(directory,'0.0.0.0',7444);thread=seedserver.start()
        config={'seeds':[seed.card('10.20.1.1',7444)],
            'ice_candidate_cidrs':['10.20.0.0/16'],'ice_servers':[
            {'urls':'stun:10.20.1.1:3478'},
            {'urls':'turn:10.20.1.1:3478?transport=tcp','username':'mesh','credential':'test-password'}]}
        for i,(n,other,net) in enumerate(((a,b,clients[0]),(b,a,clients[1])),1):
            n.trust(other.card(f'10.20.{3-i}.2',7443),['read','publish','message'])
            (n.directory/'connectivity.json').write_text(json.dumps(config))
            err=(root/f'{i}-worker.log').open('w')
            p=subprocess.Popen(['nsenter','-t',str(net),'-n',sys.executable,'-m','integration.worker',str(n.directory)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True);workers.append(p)
            read(p)
        states=wait_ready(workers,seed.id)
        assert rpc(workers[0],'bad-relay-credentials')['relay_allocated'] is False
        print('PASS: TURN rejects incorrect relay credentials',flush=True)
        assert all(s['tcp_probe']['tcp_reachable'] is False for s in states),states
        print('TCP reachability: both peers behind NAT, no inbound forwarding',flush=True)
        rpc(workers[0],'send',peer=b.id,text='Real NAT hole punching')
        state=rpc(workers[0],'status')
        assert state['peers'][b.id]['path']=='direct-ice',state
        assert 'srflx' in state['candidate_types'],state
        print('PASS: ICE/STUN hole punching through two independent NAT routers',flush=True)
        # Force direct UDP failure, while outbound TURN/TCP remains available.
        for r in routers:inside(r,'iptables','-I','FORWARD','1','-p','udp','-j','DROP')
        rpc(workers[0],'close-connections')
        rpc(workers[0],'send',peer=b.id,text='Authenticated TURN fallback')
        state=rpc(workers[0],'status')
        assert state['peers'][b.id]['path']=='relay',state
        print('PASS: UDP blocked; encrypted data uses authenticated TURN over TCP',flush=True)
        # Restore UDP, change the external NAT address, and allow periodic
        # observation / ICE consent failure to trigger new candidates.
        for r in routers:inside(r,'iptables','-D','FORWARD','1')
        inside(routers[0],'ip','addr','del','10.20.1.2/24','dev','ext0')
        inside(routers[0],'ip','addr','add','10.20.1.3/24','dev','ext0')
        end=time.monotonic()+150
        while time.monotonic()<end:
            state=rpc(workers[0],'status')
            if state.get('observed_ip')=='10.20.1.3':break
            time.sleep(1)
        else:raise AssertionError('external address change was not detected')
        # Request waits for any proactive connection rebuild already in flight.
        time.sleep(5)
        rpc(workers[0],'send',peer=b.id,text='Reconnected after address migration')
        assert rpc(workers[1],'inbox')['count']==3
        print('PASS: changed NAT address detected; signed message delivered after reconnect',flush=True)
        for worker in workers:rpc(worker,'relay-only')
        rpc(workers[0],'close-connections')
        rpc(workers[0],'send',peer=b.id,text='Explicit relay-only policy')
        state=rpc(workers[0],'status')
        assert state['peers'][b.id]['path']=='relay',state
        assert state['candidate_types']==['relay'],state
        print('PASS: explicit relay-only policy gathers no host or STUN candidates',flush=True)
        return {'status':'passed','checks':['TCP inbound reachability detection','real two-NAT ICE hole punching',
            'TURN TCP fallback with UDP blocked','external-address migration and reconnection','explicit relay-only policy'],
            'topology':'two port-preserving stateful NAT routers, overlapping private subnets',
            'relay_auth_negative':'incorrect password denied allocation',
            'worker_pids':[p.pid for p in workers],'turn_version':command(turnserver,'--version').strip()}
    except BaseException:
        for i,p in enumerate(workers):
            try:print('WORKER STATE',i,rpc(p,'status'),flush=True)
            except Exception:pass
        for path in root.glob('*worker.log'):
            print(path.name,path.read_text()[-3000:],flush=True)
        if (root/'turn.log').exists():print('TURN LOG',(root/'turn.log').read_text()[-3000:],flush=True)
        raise
    finally:
        for p in workers:
            if p.poll() is None:
                p.terminate()
                try:p.wait(5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        if seedserver:
            seedserver.shutdown();thread.join();seedserver.server_close();directory.close()
        for n in nodes:n.close()
        if turn:turn.terminate();turn.wait(5)
        for p in ns:p.terminate();p.wait(5)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--turnserver',required=True);p.add_argument('--output',type=Path)
    args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='agentmesh-nat-lab-') as directory:
        result=run(args.turnserver,Path(directory))
        if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
