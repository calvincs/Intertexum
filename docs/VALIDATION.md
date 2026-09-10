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
production resilience, or a formal security audit. Hosted WAN/CGNAT and extended
operator-pilot validation remain release-stage work.

Additional machines on the same LAN can validate process supervision, restart,
host differences and sustained traffic. They do not reproduce independent ISP
paths or carrier-grade NAT. Task usefulness, receiving-harness behavior and
extended WAN deployment remain separate validation work.
