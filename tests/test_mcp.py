import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client

from agentmesh.crypto import Denied
from agentmesh.node import Node
from agentmesh.onboarding import setup,private_write
from agentmesh.service import AttachedBackend,LocalBackend
from agentmesh.agent import call


@asynccontextmanager
async def client(directory,*args,message_handler=None):
    params=StdioServerParameters(command=sys.executable,args=['-m','agentmesh','--data',str(directory),'mcp',*args])
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer,message_handler=message_handler) as session:
            init=await session.initialize()
            assert init.server_info.name=='agentmesh'
            yield session


def prepared(tmp_path, *, network=False):
    seed=Node.create(tmp_path/'seed',model='test',dimensions=3)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    value={'version':1,'connectivity':{'seeds':[seed.card(port=9)],'listen_port':port},
        'admission':{'key':'ac'*32,'permissions':['read','publish','message']}}
    setup(tmp_path/'node',value);seed.close()
    private_write(tmp_path/'node'/'policy.json',{'network':network})
    return tmp_path/'node',port


def test_official_stdio_client_tools_resources_policy_and_retry(tmp_path):
    directory,_=prepared(tmp_path)
    async def scenario():
        changed=asyncio.Event()
        async def notifications(message):
            if getattr(message,'method',None)=='notifications/tools/list_changed':changed.set()
        async with client(directory,message_handler=notifications) as session:
            tools=(await session.list_tools()).tools
            names={x.name for x in tools}
            assert 'mesh_write' in names and 'mesh_send' not in names
            assert not any('admin' in x or 'trust' in x for x in names)
            write=next(t for t in tools if t.name=='mesh_write')
            assert 'idempotency_key' in write.input_schema['required']
            assert (await session.list_resources()).resources
            policy=await session.read_resource('agentmesh://policy')
            assert json.loads(policy.contents[0].text)['network'] is False
            instructions=await session.read_resource('agentmesh://instructions')
            assert instructions.contents[0].text.startswith('# Intertexum:')
            missing=await session.call_tool('mesh_write',{'text':'No key.'})
            assert missing.is_error and missing.structured_content['error']['code']=='invalid_request'
            first=await session.call_tool('mesh_write',{'text':'MCP remembers across sessions.','idempotency_key':'once'})
            assert not first.is_error,first
            result=first.structured_content
            again=await session.call_tool('mesh_write',{'text':'MCP remembers across sessions.','idempotency_key':'once'})
            assert again.structured_content==result
            conflict=await session.call_tool('mesh_write',{'text':'Different payload.','idempotency_key':'once'})
            assert conflict.is_error
            private_write(directory/'policy.json',{'network':False,'write':False})
            await asyncio.wait_for(changed.wait(),6)
            assert 'mesh_write' not in {x.name for x in (await session.list_tools()).tools}
            denied=await session.call_tool('mesh_write',{'text':'No bypass.','idempotency_key':'blocked'})
            assert denied.is_error and denied.structured_content['error']['code']=='denied'
        private_write(directory/'policy.json',{'network':False})
        async with client(directory) as session:
            resumed=await session.call_tool('mesh_write',{'text':'MCP remembers across sessions.','idempotency_key':'once'})
            assert resumed.structured_content==result
            status=await session.call_tool('mesh_status',{})
            assert status.structured_content['result']['readiness']=='disabled'
    asyncio.run(scenario())


def test_daemon_survives_mcp_disconnect_and_receives_peer_message(tmp_path):
    directory,port=prepared(tmp_path,network=True)
    target=tmp_path/'ctl.sock'
    daemon=subprocess.Popen([sys.executable,'-m','agentmesh','--data',str(directory),'daemon','--socket',str(target)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+15
        while not target.exists() and time.monotonic()<deadline:
            assert daemon.poll() is None
            time.sleep(.05)
        assert target.exists()
        assert os.stat(target).st_mode & 0o777 == 0o600
        async def first():
            async with client(directory,'--attach','--socket',str(target)) as session:
                result=await session.call_tool('mesh_status',{})
                assert not result.is_error
        asyncio.run(first())
        assert daemon.poll() is None
        # A peer can deliver while no MCP client exists. No direct DB injection
        # of messages: this goes through the live mutual-TLS listener.
        local=Node(directory);peer=Node.create(tmp_path/'peer')
        try:
            local.trust(peer.card(port=7443),['read','publish','message'])
            peer.trust(local.card(port=port),['read','publish','message'])
            from agentmesh.network import Client
            Client(peer,local.id).send('Arrived while the agent was away.')
        finally:peer.close();local.close()
        async def second():
            async with client(directory,'--attach','--socket',str(target)) as session:
                result=await session.call_tool('mesh_inbox',{})
                assert not result.is_error
                assert len(result.structured_content['result']['messages'])==1
        asyncio.run(second())
        assert daemon.poll() is None
        # Embedded runtimes cannot take over a daemon's identity/listener.
        duplicate=subprocess.run([sys.executable,'-m','agentmesh','--data',str(directory),'mcp'],
            input='',capture_output=True,text=True,timeout=10)
        assert duplicate.returncode!=0 and 'already running' in duplicate.stderr
    finally:
        daemon.terminate()
        out,err=daemon.communicate(timeout=25)
        assert daemon.returncode==0,(out,err)
        assert not target.exists()


def test_daemon_recovers_owned_socket_after_sigkill(tmp_path):
    directory,_=prepared(tmp_path,network=False)
    target=directory/'control.sock'
    command=[sys.executable,'-m','agentmesh','--data',str(directory),'daemon']
    processes=[]
    try:
        first=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(first)
        deadline=time.monotonic()+10
        while not target.exists() and time.monotonic()<deadline:
            assert first.poll() is None;time.sleep(.05)
        assert target.exists()
        first.kill();first.communicate(timeout=10);assert target.exists()
        second=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(second)
        from agentmesh.service import AttachedBackend
        deadline=time.monotonic()+10
        while True:
            try:
                result=AttachedBackend(directory).dispatch({'method':'resource/read','uri':'agentmesh://status'})
                assert result['id'];break
            except (OSError,Denied):
                assert second.poll() is None and time.monotonic()<deadline;time.sleep(.05)
        second.terminate();out,err=second.communicate(timeout=10)
        assert second.returncode==0,(out,err)
        assert not target.exists()
        target.write_text('never remove regular files')
        refused=subprocess.run(command,capture_output=True,text=True,timeout=10)
        assert refused.returncode!=0 and target.read_text()=='never remove regular files'
    finally:
        for process in processes:
            if process.poll() is None:process.kill();process.communicate(timeout=10)


def test_mcp_thread_tools_and_large_inbox_pages(tmp_path):
    directory,_=prepared(tmp_path,network=False)
    node=Node(directory);sender=Node.create(tmp_path/'sender')
    try:
        node.trust(sender.card(port=7443),['message']);sender.trust(node.card(port=7443),['message'])
        for i in range(70):node.receive_message(sender.make_message(node.id,'x'*32768,expires=int(time.time())+3600),sender.id)
    finally:node.close();sender.close()
    async def scenario():
        async with client(directory) as session:
            created=await session.call_tool('mesh_thread_create',{'content':'Coordinate safely','members':['@public'],'idempotency_key':'e0:root'})
            assert not created.is_error
            root=created.structured_content['result']['id']
            status=await session.call_tool('mesh_status',{})
            host=status.structured_content['result']['id']
            reply=await session.call_tool('mesh_thread_reply',{'peer':host,'thread':root,'content':'A signed response','idempotency_key':'e0:reply'})
            assert not reply.is_error
            page=await session.call_tool('mesh_thread_read',{'thread':root})
            assert len(page.structured_content['result']['items'])==1
            after=0;seen=0;last=0
            while True:
                result=await session.call_tool('mesh_inbox',{'after':after,'limit':100})
                assert not result.is_error
                page=result.structured_content['result'];seen+=len(page['messages'])
                last=page['messages'][-1]['cursor']
                if page['next'] is None:break
                after=page['next']
            assert seen==70
            ack=await session.call_tool('mesh_maintenance',{'ack_before':last,'idempotency_key':'e0:ack'})
            assert not ack.is_error and ack.structured_content['result']['messages_acknowledged']==70
    asyncio.run(scenario())


def test_legacy_wire_client_keeps_camel_case_results(tmp_path):
    """Older harnesses must still work after the Python SDK's snake_case migration."""
    import select
    directory,_=prepared(tmp_path)
    process=subprocess.Popen([sys.executable,'-m','agentmesh','--data',str(directory),'mcp'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def send(message):
        process.stdin.write(json.dumps({'jsonrpc':'2.0',**message})+'\n');process.stdin.flush()
    def receive():
        assert select.select([process.stdout],[],[],10)[0], 'MCP response timed out'
        return json.loads(process.stdout.readline())
    try:
        send({'id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25',
            'capabilities':{},'clientInfo':{'name':'legacy-wire-test','version':'1'}}})
        initialized=receive()['result']
        assert initialized['protocolVersion']=='2025-11-25'
        assert initialized['serverInfo']['name']=='agentmesh'
        send({'method':'notifications/initialized'})
        send({'id':2,'method':'tools/list'})
        write=next(t for t in receive()['result']['tools'] if t['name']=='mesh_write')
        assert 'idempotency_key' in write['inputSchema']['required']
        assert write['annotations']['readOnlyHint'] is False
        send({'id':3,'method':'tools/call','params':{'name':'mesh_write','arguments':{'text':'Missing key'}}})
        result=receive()['result']
        assert result['isError'] is True
        assert result['structuredContent']['error']['code']=='invalid_request'
        send({'id':4,'method':'resources/read','params':{'uri':'agentmesh://policy'}})
        resource=receive()['result']['contents'][0]
        assert resource['mimeType']=='application/json'
        assert json.loads(resource['text'])['network'] is False
    finally:
        process.terminate();process.communicate(timeout=15)
