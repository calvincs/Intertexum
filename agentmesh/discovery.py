"""Bounded IPv4 LAN introductions over mDNS; normal signed admission still applies."""
import asyncio
import hashlib
import ipaddress
import time

from aioice.ice import get_host_addresses
from zeroconf import Error as ZeroconfError, IPVersion, ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from .bootstrap import announcement, check_announcement
from .crypto import Denied, Invalid, canonical, decode

SERVICE = '_agentmesh._tcp.local.'  # Stable protocol name, independent of branding.
LAN = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'))


def local_address(host):
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in LAN)
    except ValueError:
        return False


def properties(obj):
    wire = canonical(obj)
    if len(wire) > 4096:
        raise Invalid('LAN announcement too large')
    return {str(i).encode(): wire[start:start+200] for i, start in enumerate(range(0, len(wire), 200))}


def introduction(node, info, network):
    """No connection to an advertised endpoint before validating its signed card."""
    props = info.properties
    if not 1 <= len(props) <= 21 or set(props) != {str(i).encode() for i in range(len(props))}:
        raise Invalid('invalid LAN announcement chunks')
    if any(not isinstance(v, bytes) or not 1 <= len(v) <= 200 for v in props.values()):
        raise Invalid('invalid LAN announcement chunk')
    wire = b''.join(props[str(i).encode()] for i in range(len(props)))
    if len(wire) > 4096:
        raise Invalid('LAN announcement too large')
    obj = decode(wire)
    body = check_announcement(obj, network)
    card = body['card']
    if (not local_address(card['host']) or card['host'] not in info.parsed_addresses(IPVersion.V4Only)
            or card['port'] != info.port or info.name != service_name(card['id'], network)):
        raise Invalid('LAN service does not match signed endpoint')
    from .openmesh import learn
    return learn(node, obj, network, lan=True)


def service_name(peer, network):
    scope = hashlib.sha256(network.encode()).hexdigest()[:16]
    return f'{peer[:32]}-{scope}.{SERVICE}'


class Discovery:
    def __init__(self, owner):
        self.owner = owner
        self.node = owner.node
        self.zc = self.browser = self.info = None
        self.pending = {}
        self.attempts = 0
        self.window = 0
        self.state = owner.state['mdns'] = {'status': 'starting', 'accepted': 0}

    def enabled(self):
        from .onboarding import policy
        caps = policy(self.node)
        return (caps['network'] and caps['mdns'] and self.owner.config.get('mdns', True)
                and not self.owner.config['relay_only']
                and not (self.node.directory/'connectivity-suspended').exists())

    def changed(self, zeroconf, service_type, name, state_change):
        if state_change == ServiceStateChange.Removed or not self.enabled():
            return
        if name == service_name(self.node.id, self.owner.config['network']) or name in self.pending:
            return
        now = time.monotonic()
        if now-self.window >= 60:
            self.window = now
            self.attempts = 0
        if len(self.pending) >= 4 or self.attempts >= 30:
            return
        self.attempts += 1
        self.pending[name] = asyncio.create_task(self.resolve(name))

    async def resolve(self, name):
        try:
            info = await self.zc.async_get_service_info(SERVICE, name, timeout=1500)
            if info and self.enabled() and introduction(self.node, info, self.owner.config['network']):
                self.state['accepted'] += 1
        except (Invalid, Denied, ValueError, TypeError, OSError):
            self.state['rejected'] = self.state.get('rejected', 0)+1
        finally:
            self.pending.pop(name, None)

    async def close(self):
        if self.browser:
            await self.browser.async_cancel()
            self.browser = None
        tasks = list(self.pending.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.zc:
            await self.zc.async_close()
            self.zc = None
        self.info = None

    async def run(self):
        before = None
        updated = 0
        retry = 0
        try:
            while True:
                addresses = sorted(a for a in get_host_addresses(use_ipv4=True, use_ipv6=False) if local_address(a))
                if self.owner.listen_host != '0.0.0.0':
                    addresses = [a for a in addresses if a == self.owner.listen_host]
                if not self.enabled() or not addresses:
                    await self.close()
                    self.state['status'] = 'disabled' if not self.enabled() else 'no_lan_interface'
                elif time.monotonic() >= retry:
                    try:
                        if addresses != before:
                            await self.close()
                        if self.zc is None:
                            self.zc = AsyncZeroconf(interfaces=addresses, ip_version=IPVersion.V4Only)
                            self.browser = AsyncServiceBrowser(self.zc.zeroconf, SERVICE, handlers=[self.changed])
                            before = addresses
                        if self.info is None or time.monotonic()-updated >= 60:
                            host = addresses[0]
                            obj = announcement(self.node, host, self.owner.port, self.owner.config['network'], ttl=120)
                            info = ServiceInfo(SERVICE, service_name(self.node.id, self.owner.config['network']),
                                port=self.owner.port, properties=properties(obj),
                                server=f'{self.node.id[:32]}.local.', parsed_addresses=[host], host_ttl=120, other_ttl=120)
                            send = self.zc.async_register_service if self.info is None else self.zc.async_update_service
                            await (await send(info))
                            self.info = info
                            updated = time.monotonic()
                        self.state['status'] = 'running'
                    except (OSError, ValueError, Invalid, ZeroconfError) as exc:
                        await self.close()
                        self.state['status'] = 'unavailable'
                        self.state['error'] = type(exc).__name__
                        retry = time.monotonic()+30
                await asyncio.sleep(1)
        finally:
            await self.close()
