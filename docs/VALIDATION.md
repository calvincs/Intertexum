# Validation

The release suite exercises memory authorization and ancestry, quarantine,
withdrawal relay, pinned TLS, bounded listeners, proof of work, erasure,
ICE/reconnection, onboarding, JSONL, official MCP clients, daemon crash recovery,
public/private grants, threaded conversation access and pagination, durable
delivery, retention, receipt reconciliation, backup/restore, certificate renewal,
and offline document embeddings.

Run from a checkout:

```sh
uv sync --locked --extra test --python 3.13
uv run pytest -q -W error
python3 scripts/check_release.py
uv build
python3 scripts/check_release.py --artifacts dist
```

Tests use temporary directories and loopback sockets. A sandbox must permit local
TCP/Unix sockets for integration tests. No live public mesh is needed.

The audit regressions cover owner capability enforcement through every adapter,
private-memory search, cold search across 10,000 short records with 384-dimensional
vectors, live authorization after cached signature verification, independent
withdrawal budgets, long-lived origins with unrelated withdrawal history, and
bounded authenticated peer capability responses. Delivery checks include
same-key certificate renewal, completed-error receipts, concurrent destinations,
per-peer ordering, and 30 queued deliveries through real TLS without self-banning.
Connectivity checks include blocked/private ICE destinations, mapped-address and
DNS endpoint blocks, relay-only TCP rejection, immediate shutdown, and the actual
idle polling scheduler for 30 registered nodes using a simulated clock.

Process demos separately exercise three-node memory/messaging, restart,
withdrawal relay, and two-seed discovery with an outage. These passed alongside
the isolated NAT lab after the audit fixes. Tests run with warnings treated as
errors to catch background-task cleanup failures.
Website validation is maintained separately on the gh-pages branch.
CI reports the current count and result; historical local tool transcripts and
machine-specific raw outputs are not distributed.

## Isolated real-NAT lab

`integration/nat_lab.py` exercises two port-preserving NAT routers with overlapping
private subnets, inbound TCP reachability detection, ICE hole punching, incorrect
TURN-password rejection, TURN/TCP fallback with UDP blocked, external-IP migration,
and relay-only gathering. These checks passed in the local namespace lab.

Run only inside an isolated user/network namespace as described in
[CONNECTIVITY.md](CONNECTIVITY.md), with a locally installed coturn binary. It must
not modify the host's networking. Results are local artifacts and should be written
outside the source tree or under `.scratch/`.

This demonstrates the selected test topologies, not Internet-wide compatibility,
production resilience, or a formal security audit. Broader WAN/CGNAT and extended
operator-pilot validation remain release-stage work.

Additional machines on the same LAN can validate process supervision, restart,
host differences and sustained traffic. They do not reproduce independent ISP
paths or carrier-grade NAT. Task usefulness, receiving-harness behavior and
extended WAN deployment remain separate validation work.

## Message admission and free replies

The messaging suite covers required work, ticket binding/tampering, expiry, live
policy changes, sender computation limits, storage/hourly quotas, atomic permit
redemption, restart/cleanup replay protection, and refusal to chain free replies.
Real local TLS and ICE tests exercise paid requests and free responses. The
isolated two-NAT coturn lab also verifies message work and a one-use free response
through TURN/TCP with direct UDP blocked, alongside reconnect and relay-only tests.
Fixtures use deliberately low difficulty for functional coverage, not production
cost calibration. These checks are not a security audit or a load certification.

Inbox/thread screening tests cover per-entry withholding, retained benign content,
cross-entry/metadata attacks and fail-closed shared scan budgets. Raw signed
objects and delivery/permit state remain unchanged by tool-output screening.

## Owned four-machine WAN pilot, September 2026

A private pilot used one real-NAT local machine and three owned public cloud
machines. Operational addresses, identities and raw logs are excluded from source.
The initial revision passed 283 tests with warnings as errors on each machine.
The tested WAN behaviors included all 12 directed message pairs, scoped public and
private access, quarantine/approval/retraction, private threads, proof-priced
requests and free replies, sender/receiver restart recovery, and discovery through
a surviving seed with the primary seed stopped.

Both explicit STUN-only ICE and forced authenticated TURN/TLS worked through the
local NAT. Wrong relay credentials and wrong certificate hostname were rejected.
The pilot found and corrected missing mixed-policy fallback: a normal sender can
now interpret a pre-dispatch transport refusal and reach a relay-only receiver.
Accepted paths and observed/selected paths are reported separately.

Bounded load and hostile-input checks included:

- 100 ordinary queued messages arrived in order with one copy each. The 219.6s
  run included prior queue backoff and is not a clean throughput benchmark.
- A 96-connection burst accepted 22 and refused 74 requests. An independent source
  completed all 18 probes, with maximum measured latency 0.164s.
- A 32-search burst accepted eight and refused 24. An independent source completed
  all 18 probes, with maximum measured latency 0.471s.
- All 18 idle plaintext connections closed within seven seconds; a legitimate
  client succeeded after recovery.
- Unknown TLS identity, signature tampering/forgery, wrong recipient, unsupported
  message version, expiry, unauthorized administration, duplicate JSON keys and
  oversized frames failed closed. A valid replay created no extra inbox copy.
  Storage-budget refusal left inbox insertion unchanged.

The routing build learned two alternative two-hop paths. Stopping its preferred
forwarder led to successful alternate delivery and a recipient receipt in 42.55s.
A three-hop path crossed all four machines; 20 messages traversed that path with
all final receipts and exactly one recipient copy each in 30.45s. Forwarders held
sealed payloads and each transfer included a paid proof. These figures include
MCP/SSH and receipt-gossip time; routed messages do not promise ordering.

The baseline also exposed test setup issues: initial cloud ingress rules blocked
cross-host traffic, and the first test CA lacked extensions required by strict
Python verification. Both were corrected without disabling certificate validation.
The 20-second shutdown fixture allowance was too short for an in-flight transport
attempt; actual bounded shutdown and durable restart recovery passed.

The new routing regressions additionally exercise three real TLS hops, learning,
expiry, alternate next hops, a live custodian that withholds delivery, malformed
metadata, invalid work, forged receipts, remaining-hop checks, recipient grants and
stable custody/encryption identity across restart. See CI for the final suite count.

The hardened routing build also passed live WAN rejection of invalid/underpriced
work, malformed identity types, altered AEAD headers and excessive hop chains,
without extra inbox or custody rows. In a separate adversarial fixture, an alive
forwarder accepted custody but deliberately did no forwarding. The origin obtained
a signed recipient receipt through its alternate first hop in 47.22s. This test
distinguishes next-hop liveness from end-to-end delivery. Backup regressions verify
that routing policy, message-work limits and encryption identity survive restore,
with restored networking still suspended.
