"""Two seed processes, two data processes, a new peer and seed failure."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from agentmesh.bootstrap import BootstrapClient
from agentmesh.crypto import Denied
from agentmesh.node import Node
from agentmesh.network import Client
from examples.three_node import Process, REPO


def run_demo(root):
    nodes, processes = [], []
    try:
        for name in ('seed1','seed2','alice','bob'):
            nodes.append(Node.create(root/name,model='bootstrap-demo-v1',dimensions=3))
        for index,node in enumerate(nodes):
            processes.append(Process(node,'bootstrap-serve' if index<2 else 'serve',
                                     ('--pow-bits','12') if index<2 else ()))
        seeds = [node.card(*process.address) for node,process in zip(nodes[:2],processes[:2])]
        seed_paths=[]
        for index,card in enumerate(seeds):
            path=root/f'seed{index}.json';path.write_text(json.dumps(card));seed_paths.append(path)
        alice,bob = nodes[2:]
        for card in seeds:
            BootstrapClient(card).register(alice,*processes[2].address)
        processes[0].stop()
        # The actual CLI falls through an unavailable seed and registers with another.
        result=subprocess.run([sys.executable,'-m','agentmesh','--data',str(bob.directory),'join',
            '--seed',str(seed_paths[0]),'--seed',str(seed_paths[1]),
            '--host',processes[3].address[0],'--port',str(processes[3].address[1])],
            cwd=REPO,capture_output=True,text=True,timeout=20,check=True)
        joined=json.loads(result.stdout)
        assert joined['failed_seeds'] and len(joined['seeds'])==1
        assert joined['candidates'][0]['body']['card']['id']==alice.id
        assert not alice.peers() and not bob.peers()
        try:
            Client(bob,alice.id).send('unauthorized')
        except Denied:
            pass
        else:
            raise AssertionError('discovery unexpectedly granted permission')
        # Explicit private-demo admission after inspecting signed referrals.
        bob.trust(joined['candidates'][0]['body']['card'],['read','publish','message'])
        found=BootstrapClient(seeds[1]).discover()
        alice.trust(next(x['body']['card'] for x in found if x['body']['card']['id']==bob.id),
                    ['read','publish','message'])
        Client(bob,alice.id).send('Joined through the surviving seed.')
        assert len(alice.inbox())==1
        return {'status':'passed','server_pids':[p.process.pid for p in processes],
                'checks':['signed registration with work','two independent seeds','seed outage failover',
                          'new identity discovery','no trust granted by discovery',
                          'mutual TLS messaging after explicit admission']}
    finally:
        for p in reversed(processes): p.stop()
        for n in nodes: n.close()


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='agentmesh-bootstrap-') as root:
        print(json.dumps(run_demo(Path(root)),indent=2))
