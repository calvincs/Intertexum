# NAT and connectivity

A **bootstrap node** introduces peers and exchanges signed connection setup
signals. It is called a **seed** in configuration (`seeds`) and CLI options
(`--seed`). A TURN relay has a different job: forwarding encrypted peer traffic.
See the [glossary](GLOSSARY.md#network-connections) for ICE, STUN, NAT and the other
connection terms used here.

Nodes now have an optional background ICE transport using pinned aiortc 1.15.0
and aioice 0.10.2. Existing direct mutual-TLS connections continue to work.
When TCP cannot connect, the client refreshes its approved peer's signed endpoint,
then establishes a reliable SCTP data channel over DTLS using ICE. ICE prefers
working direct candidate pairs; authenticated TURN provides a relay path when
those checks fail. Neither discovery nor rendezvous grants permissions.

## Agent-managed setup

For autonomous nodes, use `onboard` and the `agent` runtime described in
[AGENT_SETUP.md](AGENT_SETUP.md) and the repository `llm.txt`. The manual
configuration below remains available for explicit-card deployments. Profile
members enroll automatically within the owner-provisioned permission ceiling.

## Configure a node

Run your bootstrap-node listener as described in [BOOTSTRAP.md](BOOTSTRAP.md). Obtain its public
card through an authenticated channel. Place the actual card object in `seeds`
in a JSON file like this (the placeholder is intentionally not a usable card):

```json
{
  "network": "agentmesh-demo-v1",
  "seeds": ["REPLACE WITH THE PINNED SEED CARD OBJECT"],
  "listen_port": 7443,
  "ice_servers": [
    {"urls": "stun:turn.example.org:3478"},
    {
      "urls": "turns:turn.example.org:5349?transport=tcp",
      "username": "YOUR_NODE_USERNAME",
      "credential": "YOUR_NODE_RELAY_PASSWORD"
    }
  ],
  "relay_only": false
}
```

```bash
.venv/bin/intertexum --data /path/to/node connectivity-config /path/to/config.json
.venv/bin/intertexum --data /path/to/node serve --host 0.0.0.0 --port 7443
.venv/bin/intertexum --data /path/to/node connectivity-status
```

Configure both peers, approve their cards and permissions on both sides, and keep
their listeners running. The existing search, fetch, retraction and message APIs
use the fallback automatically. For a custom TCP port, match `listen_port` to
`serve --port` so separate CLI clients advertise the same endpoint. `advertise_host`
can override the advertised numeric IP when a reverse proxy or explicit mapping
is in use. It does not change what the seed actually observes or probes.

Zero to three seed cards are supported; zero requires mDNS and allows LAN-only discovery. This ICE runtime accepts one STUN server
and one TURN server per node; extra servers are rejected instead of silently
ignored. There are no default third-party servers or bundled relay credentials.
An empty `ice_servers` list works on directly reachable LAN paths but offers no
STUN discovery or TURN fallback. `relay_only: true` requires TURN, restricts
locally advertised candidates to relays, and prohibits direct TCP peer data in
both directions. Seed signaling remains direct; endpoint metadata is still visible. Restart the listener after configuration
or credential changes. The configuration file is written with mode 0600.

## What is detected and how recovery works

- A signed observation request obtains the source IP seen by each seed. A bounded
  TCP callback probes only that same source IP and the registered unprivileged
  port. It reports reachability from that seed, not proof of service identity.
- ICE gathers host, STUN server-reflexive and authenticated TURN relay candidates.
  Status reports candidate types and the selected direct/relay path. A reflexive
  candidate provides a server-observed endpoint. `nat_mapping_observed` compares
  it to the local endpoint (null if no STUN candidate exists); this is not a full NAT taxonomy
  or a promise that every peer can reach it.
- Interface addresses are checked every 10 seconds and seed-observed external
  addresses every 120 seconds. Changes close old sessions, renew announcements,
  and allow fresh candidate gathering. ICE consent checks also detect dead paths.
  Session lifetimes are bounded to 10 minutes; failed sessions are replaced.
- Discovery advances one bounded 50-entry page every 24–36 seconds, rotating
  seeds; local registration renews every 5 minutes. Idle mailbox polling backs
  off to about 10 seconds with jitter; pending answers use two-second polling.
  Failures use bounded exponential backoff and honor seed retry-after hints. Signed endpoint timestamps and durable local watermarks
  reject older updates. Offers use persistent monotonic generations plus random
  session IDs to reject replay after restart.
- Previously used peers reconnect in the background (the smaller peer ID initiates
  to avoid both sides repeatedly dialing). A request can also initiate recovery.
  Connection setup is bounded, but network outages still return an error.
  A possibly delivered operation is never silently replayed. Inspect the inbox
  before retrying a message whose delivery status is unknown.

The live `updated_at` timestamp distinguishes current status from an old file
left by a stopped process. De-registering, including generating an offline removal
request, creates a local suspension marker: background transport stops renewing
or reconnecting. Use the owner-authorized `resume` command to resume a profile-managed node.
For manual configurations, re-running `connectivity-config` also resumes it. Stop the
TCP listener too if the intent is to stop all peer communication.

## Trust, privacy and limits

A seed queues signed offer/answer envelopes for at most 90 seconds. The envelope
binds origin, recipient, seed, network, session, generation and SDP. Each endpoint
checks the existing approved identity before accepting the SDP; its signed DTLS
fingerprints authenticate the ephemeral transport certificate. A seed cannot
substitute its own fingerprint to decrypt peer traffic. TURN authenticates relay
allocation separately, and forwards DTLS ciphertext. Existing per-peer permissions,
blocks, request limits and search budgets apply inside the data channel too.

Seeds see SDP addresses, ephemeral ICE credentials and connection metadata. TURN
operators see addresses, allocation identity, timing and byte volume. Avoid debug
logging SDP in production. Search content and results use direct peers or TURN;
**the bootstrap rendezvous API does not carry search RPCs**. Revocation of trust is
checked again for each RPC. IP bans on the TCP listener cannot identify a relayed
origin: relay traffic uses the verified peer's quotas, never the relay IP as the
attacker's identity.

Bounds: 128 queued signaling envelopes per seed, 8 per origin; at most 8 sessions
per node, 32 candidate lines, one incoming and one outgoing RPC per session,
128 KiB requests, 2 MiB responses, 16 KiB transport frames and 16 MiB received
per session. Registration work and existing seed admission limits remain in force.
These quotas are tested for 30 already registered idle nodes, including a shared
NAT, with a simulated clock; larger or mixed workloads require load testing.
Remote ICE destinations must be globally routable by default. The owner may
provision ice_candidate_cidrs with up to 32 explicit numeric ranges for an
authorized private network or loopback lab. mDNS-introduced peers may use only
their signed LAN endpoint while mDNS remains enabled. Local peer/CIDR blocks
override all exceptions, including IPv4-mapped IPv6; unspecified and multicast
candidates are always rejected. Disallowed candidates are removed before ICE
processing; an offer with no permitted candidates is refused.
Public discovery alone never grants an internal-address exception.
See [OPERATING_LIMITS.md](OPERATING_LIMITS.md) for routing/privacy semantics.

## Host the relay

`ops/coturn/turnserver.conf.example` is a starting configuration for a separately
hosted coturn service. Give it a public IP, DNS, a valid TLS certificate, unique
per-node credentials, allocation/bandwidth quotas and a bounded UDP relay-port
range. Open TCP 5349 for TURN/TLS, UDP 3478 for STUN, and the configured UDP relay
range. For a server itself behind NAT, configure coturn's external/private IP
mapping and firewall accordingly. Credential provisioning and rotation are
operator-managed in this version; a public anonymous relay is not enabled.

## Reproducible integration lab

Linux `ip`, `iptables`, `nsenter`, unprivileged user/network namespaces and a
coturn executable are required. Nothing installs a service or changes host routes.

```bash
unshare -Urn .venv/bin/python -m integration.nat_lab \
  --turnserver /path/to/turnserver --output /tmp/nat-result.json
```

The lab creates two routers and two independent node processes on overlapping
private subnets. It models port-preserving, statefully filtered NAT with no TCP
forwarding; then blocks all forwarded UDP to force TURN over TCP, and changes
one router's external IP. It also checks rejection of incorrect TURN credentials.
This is a real kernel/packet test, not proof of compatibility with all consumer
routers, CGNATs, IPv6 networks or restrictive HTTP-only firewalls. Symmetric NATs
may require the relay. TURN/TLS deployment with a public certificate still needs
an operator-run WAN smoke test.

Implementation references: [aiortc API](https://aiortc.readthedocs.io/en/latest/api.html),
[coturn configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf).

## Automatic local discovery

Managed node listeners advertise and browse `_agentmesh._tcp.local.` using
python-zeroconf. mDNS defaults to enabled. It works on IPv4 RFC1918 and
link-local interfaces; IPv6-only LAN discovery is not implemented. A listener
bound only to loopback does not advertise. Multicast must be permitted on the
LAN (UDP 5353); Wi-Fi client isolation or multicast filtering may prevent discovery.
No bootstrap is needed for peers on the same LAN with matching network profiles:

```bash
intertexum profile-create --public --network my-lan --output /private/lan-profile.json
intertexum --data /private/node onboard --profile /private/lan-profile.json
intertexum --data /private/node agent
```

Use the same network name on both nodes, separate node directories and distinct
listen ports when running on one machine (`profile-create --port`). For a private
LAN, omit `--public` and provision both nodes with the same generated invitation.
Matching network names alone grant no private rights. Seedless profiles cannot
use rendezvous or relay fallback; provision seeds for connections beyond the LAN.

Advertisements contain the signed identity card, endpoint, network and short-lived
membership proof where applicable; they contain no memory, messages or invitation
key. Nearby devices can observe this identity and network metadata. Discovery
validates the signature, network, expiry and endpoint before admitting a peer.
Public profiles grant only public access; private profiles retain their invitation
permissions. Subsequent requests use the existing pinned mutual TLS transport.
Peer and IP-range blocks apply. Discovery never grants trust based on proximity.

Each runtime allows four concurrent resolutions and 30 attempts per minute, with
4 KiB signed advertisements and 128 distinct persisted LAN introductions. This
bounds work and peer growth, but cannot guarantee discovery on a flooded LAN.
Advertisements renew every 60 seconds with a 120-second lifetime; interface
changes refresh the advertiser. Expiry/removal does not revoke existing peer
grants or erase audit records. Discovery hints do not prove current reachability.

Set `{"mdns":false}` in the owner's `policy.json` to stop advertising and browsing
without stopping other networking. It takes effect on the next discovery loop
(about a second). A profile can disable it with `profile-create --no-mdns`
(requires seeds), or `mdns:false` in connectivity configuration followed by restart.
Network suspension and relay-only mode also suppress local discovery. Status
includes `connectivity.mdns`; a running browser is not proof of remote access.
The feature uses the [python-zeroconf async API](https://python-zeroconf.readthedocs.io/en/stable/api.html).
