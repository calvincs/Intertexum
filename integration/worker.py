import logging
logging.basicConfig(level=logging.WARNING)
import json
import sys
from pathlib import Path
from agentmesh.node import Node
from agentmesh.network import Server,Client


def main():
    node=Node(Path(sys.argv[1]))
    with Server(node,'0.0.0.0',7443) as server:
        thread=server.start()
        print(json.dumps({'ready':node.id}),flush=True)
        try:
            for line in sys.stdin:
                args=json.loads(line)
                try:
                    if args['op']=='status':result=node.connectivity.state
                    elif args['op']=='send':result=Client(node,args['peer']).send(args['text'])
                    elif args['op']=='reply':
                        from agentmesh.message_work import reply_message
                        from agentmesh.conversations import deliver,deliveries
                        queued=reply_message(node,args['peer'],args['request'],args['text'])
                        deliver(node)
                        result=next(x for x in deliveries(node)['items'] if x['id']==queued['id'])
                    elif args['op']=='relay-only':
                        node.connectivity.config['relay_only']=True
                        result={'configured':True}
                    elif args['op']=='bad-relay-credentials':
                        import asyncio
                        from aiortc import RTCPeerConnection,RTCConfiguration,RTCIceServer
                        from agentmesh.connectivity import ice_connection
                        async def reject():
                            config=dict(next(x for x in node.connectivity.config['ice_servers'] if x['urls'].startswith('turn:')))
                            config['credential']='deliberately-wrong-password'
                            pc=RTCPeerConnection(RTCConfiguration(iceServers=[RTCIceServer(**config)]))
                            try:
                                pc.createDataChannel('test')
                                await pc.setLocalDescription(await pc.createOffer())
                                return {'relay_allocated':any(c.type=='relay' for c in ice_connection(pc).local_candidates)}
                            finally:await pc.close()
                        result=asyncio.run_coroutine_threadsafe(reject(),node.connectivity.loop).result(15)
                    elif args['op']=='inbox':result={'count':len(node.inbox())}
                    elif args['op']=='close-connections':
                        import asyncio
                        async def close():
                            for s in list(node.connectivity.sessions.values()):await s.pc.close()
                        asyncio.run_coroutine_threadsafe(close(),node.connectivity.loop).result(10)
                        result={'closed':True}
                    elif args['op']=='stop':break
                    else:raise ValueError('unsupported lab command')
                    print(json.dumps({'ok':True,'result':result}),flush=True)
                except Exception as exc:print(json.dumps({'ok':False,'error':type(exc).__name__+': '+str(exc)}),flush=True)
        finally:server.shutdown();thread.join()
    node.close()


if __name__=='__main__':main()
