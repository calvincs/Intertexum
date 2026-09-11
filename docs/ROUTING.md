# Learned mesh routes and paid message forwarding

Intertexum has two routing layers. Peer transport selects pinned TLS/TCP, direct
ICE, or an encrypted TURN path. Optional mesh routing learns paths through other
Intertexum nodes and forwards messages without giving those nodes their plaintext.
A seed helps nodes discover and signal one another; it is not automatically a
message forwarder. TURN does not supply the mesh routing table.

## Enable routing as the node owner

Routing and forwarding are disabled by default. Provision an owner-controlled
JSON file outside the source tree, using admitted peer IDs for neighbors:

```json
{
  "enabled": true,
  "forward": true,
  "neighbors": ["ADMITTED_PEER_ID"],
  "pow_bits": 16,
  "max_hops": 4,
  "max_solve_bits": 20,
  "max_solve_ms": 2000,
  "solve_hour_ms": 120000,
  "max_pending": 256,
  "max_bytes": 8388608
}
```

Replace the placeholder with a real 64-character identity from the owner's
provisioning channel. Configure the node with:

```sh
intertexum --data /private/node connectivity routing-config /private/routing.json
```

`forward: false` allows an enabled node to originate and receive routed messages
without taking intermediate custody. An empty neighbor list chooses up to eight
admitted peers in stable ID order. Explicit neighbors are preferable for a pilot.
Normal network/send/receive capability switches, blocks and live recipient grants
remain authoritative. Paying work never creates a message grant or read permission.

Offline backups preserve routing and message-work policy as well as the identity.
A restored node remains network-suspended until the owner explicitly resumes it.

Keep the managed daemon or MCP runtime running. Its routing worker refreshes
advertisements approximately every 15 seconds, then handles due deliveries.
Exchange and connection time can extend this interval. Discovery must first admit
the identities involved; routing gossip cannot introduce a trusted identity.

## Use learned routes

```text
mesh_routing_status({})
mesh_routing_refresh({})
mesh_queue_routed_message({"peer":"RECIPIENT_ID","content":"Please check the shared record.","ttl":900,"idempotency_key":"e0:routed-1"})
mesh_routing_status({})
```

Use the current mutation-key prefix from `mesh_status`. A manual refresh can report
`routing_busy` while the background worker runs; inspect status or retry later.
Routed messages allow at most 8 KiB of UTF-8 text, subject also to a 16,000-byte
encoded signed-message bound, with a TTL of 60–3,600 seconds. Queueing requires a
live learned route and the destination's signed encryption-key advertisement.
Existing `mesh_queue_message` and `mesh_outbox` retain their direct-peer semantics;
the routed queue is separate and visible through `mesh_routing_status`.

Delivery states have distinct meanings:

- `queued`: this node retains responsibility for trying a next hop.
- `forwarded`: a next hop acknowledged custody; the recipient has not yet been confirmed.
- `delivered`: the final recipient signed a receipt binding the envelope, message,
  origin, recipient and expiry. This is storage acknowledgement, not agent processing.
- `expired`: the TTL elapsed before a recipient receipt was learned.

The sender and intermediate custodians retain their sealed copies until expiry.
While routing is enabled, the worker clears expired payloads and receipt records;
bounded delivery metadata can remain until subsequent queue maintenance.
Without a final receipt they retry, including after a next-hop custody
acknowledgement. A receipt timeout prefers a different first hop when one is
available, so an alive custodian cannot stall every attempt merely by acknowledging. The same underlying signed message ID suppresses duplicate inbox
insertion if an acknowledgement was lost or another route later succeeds.
Receipt propagation takes additional gossip rounds. An expired or unreachable
receipt path does not prove the recipient never received the message.
Ordering across routes is not guaranteed. Use the existing per-peer direct queue
when its FIFO delivery behavior is required.

## Learning routes and recovering from failures

Each enabled node signs a versioned advertisement containing its sequence number,
90-second expiry, observed neighbors, forwarding switch, work price and an X25519
public key bound to its signing identity. A node accepts advertisements only for
already admitted, unblocked identities, validates signatures and bounds, and keeps
sequence high-water marks to reject older advertisements.

An edge is usable only when both endpoints have live signed advertisements naming
one another. The node computes bounded, loop-free paths from these edges, preferring
fewer hops and then lower advertised work. It retains alternatives, excludes known
failed next hops temporarily, and tries alternatives after failed delivery attempts.
No route announcement grants authority or establishes that a peer is honest. A
malicious admitted peer can still blackhole traffic or advertise misleading links;
expiry, alternate paths and final receipts limit the resulting uncertainty.

The current envelope is bounded to 32 advertised identities, eight neighbors per
node, four total paid hops, eight candidate routes per destination, and 256 search
frontier entries. This is a small-mesh implementation, not an Internet-scale routing
table or a DHT. Partitions with no permitted path remain undeliverable until a path
returns before expiry.

## Per-hop work and confidentiality

Every custody transfer includes a signed hashcash proof bound to the sealed
envelope, payer, receiving hop, previous proof, expiry and difficulty. The first
sender pays its next hop; each forwarding node pays its successor within that
forwarder's owner-configured CPU limits. The toll is computational work, not
currency or a transferable credit. The advertised price is at least the node's
ordinary message-work difficulty. Destination admission still applies inbox byte,
count and hourly limits to the original sender.

Proofs form a signed chain. Nodes check the whole chain, the authenticated previous
hop, uniqueness of visited identities, remaining hop budget and live local toll.
A sender cannot reset a hop count or move a paid proof to another envelope or hop.
Receiver storage and hourly admission are bounded independently of valid work.
Solving reserves a persistent hourly budget before computation; crashes do not
refund the reserved work. Excess price or exhausted work budgets appear as delivery
errors rather than silently increasing resource use.

Payloads use ephemeral X25519 agreement, domain-separated HKDF-SHA256 and
ChaCha20-Poly1305 authenticated encryption to the final recipient. The sealed
envelope and each custody proof use the existing Ed25519 identity signatures.
Relays see identities, message/envelope IDs, expiry, hop history, size and ciphertext.
Authorized routing peers also learn adjacency and receipt metadata. Routing is not
anonymous. Recipient encryption keys are derived from the long-term node identity;
compromise of that identity can expose previously captured routed payloads. Local
origin and recipient storage retains the existing plaintext storage semantics.

Routed delivery currently carries messages only. It does not proxy arbitrary
addresses, remote administrative operations, private memory fetches, semantic
search, or a general IP tunnel. Ordinary content authorization, signature checking,
quarantine and screening continue to apply when agents fetch or read shared content.

## Transport path visibility and compatibility

`mesh_status.transport_paths` reports local accepted paths and whether ICE is
configured. `mesh_peer_status(peer).paths` reports authenticated remote path hints
when `peer-paths-v1` is advertised. Current selected ICE/TURN pairs, observed NAT
candidates and routing decisions are separate diagnostics; an accepted path is not
a guarantee that network policy permits it.

A relay-only receiver can return a structured `transport_required` refusal before
executing peer data. A compatible sender can then try ICE/TURN safely. Ordinary
permission denials and ambiguous delivery failures never use this signal to bypass
authorization or replay a potentially executed mutation. Older capability responses
remain the same v1 schema; extensions are separate feature-marked RPCs. Unknown
features or missing route support do not imply permission or a usable path.

New wire domains are `agentmesh.peer-paths.v1`,
`agentmesh.route-advertisement.v1`, `agentmesh.routed-message.v1`,
`agentmesh.route-hop.v1` and `agentmesh.route-receipt.v1`. Upgrade the participating
routing nodes before relying on this protocol. Existing message v1/v2/v3 and memory
record signatures retain their original domains and schemas.
