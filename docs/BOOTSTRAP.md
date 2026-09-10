# Bootstrap, public joining, and admission work

Updated defense policy: see [DEFENSE.md](DEFENSE.md) for shared blocks, audit,
temporary bans, search protection and tighter registration quotas. Public-address
mode now defaults to 18-bit work (minimum 16); private-demo default stays zero.
Searches are sent directly to data peers, never through the bootstrap protocol.
The newer defense policy supersedes the original rate/default discussion below.
See [PRIVACY.md](PRIVACY.md) for metadata disclosure considerations.

There are two separate listeners. The data listener uses pinned mutual TLS and
local read/publish/message permissions. The bootstrap listener accepts unknown
registrants over server-authenticated TLS, stores self-signed endpoint
announcements, and returns candidate peers. Registering is open; data permissions
remain explicit. A successful puzzle grants no data permission or endorsement.

## Demonstration

```bash
.venv/bin/python -m examples.bootstrap_mesh
```

This starts two independent bootstrap processes and two data-node processes.
Alice advertises through both seeds. The first seed stops. New node Bob uses the
actual `join` CLI to fall through the unavailable seed, register with the second,
and discover Alice. Both trust stores remain empty. After explicit local
approval, Bob sends Alice a signed message over mutual TLS. Temporary directories
and processes are cleaned up. The demo uses 12-bit work to exercise admission;
ordinary messages carry no work requirement.

## Run a seed

```bash
.venv/bin/agentmesh --data /tmp/seed1 init
.venv/bin/agentmesh --data /tmp/seed1 card --host 127.0.0.1 --port 7444 > /tmp/seed1-card.json
.venv/bin/agentmesh --data /tmp/seed1 bootstrap-serve --port 7444 --network agentmesh-demo-v1
```

Create another seed with another directory and port. Distribute seed cards
through a trusted channel; the exact TLS certificate is pinned. Any node can
host this separate service; seeds do not have memory-access privileges.

```bash
.venv/bin/agentmesh --data /tmp/alice init
.venv/bin/agentmesh --data /tmp/alice join \
  --seed /tmp/seed1-card.json --seed /tmp/seed2-card.json \
  --host 127.0.0.1 --port 7443 --network agentmesh-demo-v1
.venv/bin/agentmesh --data /tmp/alice discover \
  --seed /tmp/seed1-card.json --seed /tmp/seed2-card.json
```

`join` advertises and discovers; it does not start the data listener. Run `serve`
separately. Review returned signed candidates, save a candidate's `body.card`,
then use `trust CARD --allow ...` on the appropriate nodes. Output lists failed
seeds and never claims complete global discovery. Existing data connections do
not require an available seed.

For a reachable hosted seed, bind `bootstrap-serve --host 0.0.0.0`, advertise its
real numeric public IP in the seed card, choose an explicit network name, and
use `--public-addresses` to reject non-global advertised peer addresses. This
implementation's listener is IPv4; it does not yet offer IPv6 listening or DNS
endpoint resolution. A public seed is hostable, but no host has been deployed.

## Bounds and proof of work

Private demo default: `--pow-bits 0` (no search effort). Optional registration
friction: `--pow-bits 16`. The server issues a 120-second HMAC-authenticated
challenge bound to server identity, network, `register` action, peer identity,
and signed announcement hash. The client finds a SHA-256 nonce. Verification
checks the MAC, binding, expiry, difficulty, and hash; registration consumes the
challenge atomically with the directory update. Reuse fails. A restart rotates
the challenge key and invalidates outstanding challenges. New announcements and
renewals each require a new ticket; normal search, messaging, and cache fetches
do not. A client refuses more than 20 bits or more than two seconds of work.

This is not a coin, consensus protocol, trust score, or proof of personhood.
GPU/ASIC users and botnets can buy disproportionately cheap hashes. A fixed
hash difficulty does not promise a fixed delay, especially on weaker CPUs.
Renewal work is opt-in with the seed's difficulty; use zero for the private demo.
Before enabling it publicly, measure p95 solve time on the slowest supported
device and keep work out of emergency revocation and established-peer traffic.

Local calibration on the benchmark machine, single Python solver:

| Difficulty | Trials | Solve p50 | Solve p95 | Verify p50 |
|---|---:|---:|---:|---:|
| 12 bits | 32 | 3.7 ms | 11.5 ms | .018 ms |
| 16 bits | 64 | 23.3 ms | 114.2 ms | .061 ms |
| 18 bits | 32 | 108.2 ms | 592.7 ms | .068 ms |

No trial hit the two-second client budget. These are random-work samples, not
guarantees; the 16-bit maximum was 298.6 ms. Verification timing covers the work
ticket, not TLS, signature checks, or SQLite writes. See
`benchmarks/results/work.json` (generated locally by `python -m benchmarks.work`). Start the private demo with
work disabled; 16 bits is a candidate for a measured public admission experiment.

The seed also caps concurrent handlers at 16, requests at 16 KiB, announcements
at 8 KiB, directory entries at 1,000, replay tickets at 10,000, and discovery pages
at 50 entries. Connections are limited before TLS to a global bucket (20/sec,
burst 40) and per-source-IP bucket (2/sec, burst 10); the IP map is capped at
4,096 entries and expires idle buckets after 60 seconds. These limits share
capacity across clients behind a NAT. Handshake and frame deadlines are five
seconds each. This is a bounded prototype, not volumetric DDoS protection.

## What public networking still needs

An unknown node can register with a reachable seed and discover the network
today. It cannot automatically read, publish, or message arbitrary nodes. The
next policy decision is whether public peers get narrowly scoped public-read
access, introductions/invitations, or some other admission mechanism. Private
content must remain protected in all cases. Solved work must never be that
authorization mechanism.

Announcements expire after 15 minutes by default, with a maximum one-hour
lifetime. Registration checks signatures, certificate validity, network name,
and timestamps; a live directory rejects backwards timestamp updates and
conflicting announcements in the same second. It does not persist a per-peer
sequence watermark after expiry, so old still-valid announcements can be replayed
to a fresh directory. Entries are unverified reachability claims. Optional reachability probes dial only the caller socket IP and its registered
unprivileged port. Configured clients refresh peers and renew registrations. Open profiles admit
new identities for public access only; private invitation profiles require their
membership proof. Ordinary peer exchange is implemented. Seed-to-seed gossip
and fully seedless initial discovery are not implemented. A malicious seed can omit peers; several operator-independent
seeds reduce dependence but do not prove completeness or eclipse resistance.

Consumer machines behind NAT can enable [signed rendezvous, ICE hole punching
and authenticated relay fallback](CONNECTIVITY.md). Bootstrap alone does not make an inbound port
reachable. We also still need hosted-process supervision, key renewal/recovery,
monitoring, and abuse/load testing before calling this a production public mesh.

Sources: [libp2p discovery/DHT](https://libp2p.io/docs/dht/),
[connection and resource limits](https://libp2p.io/docs/dos-mitigation/), and
[NAT hole punching](https://docs.libp2p.io/concepts/hole-punching/).
