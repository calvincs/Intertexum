import copy
import json
import time
import pytest
from agentmesh.node import Node
from agentmesh.bootstrap import Directory,BootstrapServer,announcement,check_announcement
from agentmesh.network import Server
from agentmesh.onboarding import setup,private_write,admit,status
from agentmesh.agent import call
from agentmesh.crypto import Denied,Invalid


def invitation(seed,port):
    return {'version':1,'connectivity':{'seeds':[seed.card(port=port)],'listen_port':7443},
            'admission':{'key':'ab'*32,'permissions':['read','publish','message']}}


def invoke(node,rid,tool,**args):
    return call(node,{'id':rid,'tool':tool,'arguments':args})


def test_resume_limits_receipts_and_membership(tmp_path):
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    p=invitation(seed,7444)
    first=setup(tmp_path/'a',p)
    assert setup(tmp_path/'a',p)['id']==first['id']
    a=Node(tmp_path/'a')
    b=Node.create(tmp_path/'b',model='test',dimensions=3)
    try:
        altered=copy.deepcopy(p);altered['admission']['key']='cd'*32
        with pytest.raises(Denied,match='profile_changed'):setup(a.directory,altered)
        assert not admit(a,check_announcement(announcement(b,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1'))
        private_write(b.directory/'network-profile.json',__import__('agentmesh.onboarding',fromlist=['profile']).profile(p))
        body=check_announcement(announcement(b,'127.0.0.1',7443,'agentmesh-demo-v1'),'agentmesh-demo-v1')
        assert admit(a,body)
        assert set(a.peer(b.id)['permissions'])=={'read','publish','message'}
        # Signature-verified but incorrect membership proof never enrolls.
        forged=copy.deepcopy(body);forged['membership']='00'*32
        assert not admit(a,forged)
        a.db.execute('UPDATE admissions SET expires=0')
        with pytest.raises(Denied,match='membership_expired'):a.peer(b.id)
        assert admit(a,body)
        a.block(b.id)
        assert not admit(a,body)
        with pytest.raises(Denied):a.peer(b.id)
        a.trust(b.card(port=7443),['read'])
        assert not admit(a,body)
        assert a.peer(b.id)['permissions']==['read']
        private_write(a.directory/'policy.json',{'write':False,'network':False})
        result=invoke(a,'blocked-write','write',text='must not be written')
        assert result['error']['code']=='denied'
        assert status(a)['readiness']=='disabled'
        assert invoke(a,'blocked-write','write',text='must not be written')==result
        assert invoke(a,'blocked-write','write',text='changed')['error']['code']=='invalid_request'
        with pytest.raises(Denied):a.write_private('also denied',[0]*384)
        (a.directory/'connectivity-suspended').touch()
        with pytest.raises(Denied):setup(a.directory,p)
    finally:a.close();b.close();seed.close()


def test_agents_join_share_and_message_without_manual_trust(tmp_path):
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    directory=Directory(seed);bootstrap=BootstrapServer(directory);bt=bootstrap.start()
    profile=invitation(seed,bootstrap.server_address[1]);nodes=[];servers=[]
    try:
        for name in ('a','b'):
            setup(tmp_path/name,profile);node=Node(tmp_path/name);nodes.append(node)
            server=Server(node);servers.append((server,server.start()))
        a,b=nodes
        deadline=time.monotonic()+55
        while time.monotonic()<deadline:
            if all(status(n)['readiness']=='ready' for n in nodes):break
            time.sleep(.1)
        else:raise AssertionError([status(n) for n in nodes])
        written=invoke(a,'write-1','write',text='Agent Mesh shares signed research memories.')
        assert written['ok'],written
        assert invoke(a,'write-1','write',text='Agent Mesh shares signed research memories.')==written
        published=invoke(a,'publish-1','publish',id=written['result']['id'],audience=['*'])
        assert published['ok'],published
        found=invoke(b,'search-1','search',peer=a.id,text='signed research memories')
        assert found['ok'] and found['result']['results'],found
        rid=published['result']['id']
        assert invoke(b,'fetch-1','fetch',id=rid,peer=a.id)['ok']
        assert invoke(b,'inspect-1','inspect',id=rid)['result']['untrusted_data']
        assert invoke(b,'approve-1','approve',id=rid)['ok']
        sent=invoke(a,'send-1','send',peer=b.id,text='Autonomous enrollment complete.')
        assert sent['ok'],sent
        assert invoke(a,'send-1','send',peer=b.id,text='Autonomous enrollment complete.')==sent
        assert len(b.inbox())==1
        private_write(b.directory/'policy.json',{'receive':False,'serve_memory':False})
        assert not invoke(a,'send-2','send',peer=b.id,text='Must be denied')['ok']
        assert not invoke(a,'search-2','search',peer=b.id,text='research')['ok']
        assert len(b.inbox())==1
    finally:
        for server,thread in servers:server.shutdown();thread.join();server.server_close()
        for n in nodes:n.close()
        bootstrap.shutdown();bt.join();bootstrap.server_close();directory.close();seed.close()


def test_jsonl_subprocess_and_durable_receipts(tmp_path):
    import subprocess
    import socket
    import sys
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    p=invitation(seed,9);p['connectivity']['listen_port']=port
    setup(tmp_path/'agent',p)
    private_write(tmp_path/'agent'/'policy.json',{'write':False})
    requests=[{'id':'status','tool':'status','arguments':{}},
              {'id':'write-once','tool':'write','arguments':{'text':'owner disabled writing'}},
              {'id':'unknown','tool':'trust','arguments':{}}]
    try:
        command=[sys.executable,'-m','agentmesh','--data',str(tmp_path/'agent'),'agent']
        result=subprocess.run(command,input=''.join(json.dumps(x)+'\n' for x in requests),text=True,capture_output=True,timeout=25)
        assert result.returncode==0,result.stderr
        responses=[json.loads(x) for x in result.stdout.splitlines()]
        assert len(responses)==3
        assert responses[0]['result']['capabilities']['write'] is False
        assert responses[1]['error']['code']=='denied'
        assert responses[2]['error']['code']=='invalid_request'
        node=Node(tmp_path/'agent')
        try:
            # Even after owner re-enables the capability, a completed request ID
            # returns its durable prior result instead of becoming a new write.
            private_write(node.directory/'policy.json',{})
            assert call(node,requests[1])==responses[1]
            node.db.execute("INSERT INTO tool_receipts VALUES('crashed','placeholder',NULL)")
            from agentmesh.crypto import digest,canonical
            payload={'tool':'send','arguments':{'peer':'0'*64,'text':'uncertain'}}
            node.db.execute("UPDATE tool_receipts SET fingerprint=? WHERE id='crashed'",(digest(canonical(payload)),))
            result=call(node,{'id':'crashed',**payload})
            assert result['error']['code']=='delivery_unknown'
            assert not result['error']['retryable']
        finally:node.close()
    finally:seed.close()


def test_agent_entry_commands_without_node_directory(tmp_path):
    from agentmesh.cli import parser,run
    parse=parser().parse_args
    assert run(parse(['instructions']))['instructions'].startswith('# Intertexum:')
    assert run(parse(['tools']))['tools']
    target=tmp_path/'lan.json'
    result=run(parse(['profile-create','--public','--network','test-lan','--output',str(target)]))
    assert result['created']==str(target)
    assert json.loads(target.read_text())['connectivity']['seeds']==[]
    assert list(tmp_path.iterdir())==[target]
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(Invalid,match='--data is required'):
        run(parse(['status']))
