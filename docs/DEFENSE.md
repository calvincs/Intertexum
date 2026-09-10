# Listener defense and search saturation

Retention update: [ERASURE.md](ERASURE.md) adds signed seed de-registration and
segregated persistent security summaries. Routine audit still expires; security
summaries do not automatically expire. Repeat ban incidents now escalate up to a
one-day temporary ban. A documented local retention-review path remains available.

Bootstrap discovery introduces peers. Searches go directly to a chosen **data
peer**. The bootstrap protocol accepts registration, discovery, removal and bounded
signaling operations; it neither receives nor forwards searches. One host may run both
listeners as separate roles. Federated search caps fan-out at eight peers and four concurrent requests.

## Shared baseline

Both listener roles use `agentmesh.defense.Defense`: local persistent peer-ID and
IP/CIDR blocks, bounded rate accounting, automatic 300-second bans, and a bounded
local audit database. Rules are read from SQLite on requests, so local CLI edits
take effect without restarting either listener. Blocks are not broadcast; an
untrusted accusation cannot create a network-wide ban.

Before TLS, source-IP blocks and connection quotas apply. Source means the
accepted socket address, never an announcement's advertised IP or a request
header. There are 16 concurrent connection handlers, existing handshake/frame
deadlines, and a global connection bucket of 20/sec for data and 40/sec for
bootstrap, with burst 40 per role.
Data listeners allow 4 connections/sec per source, burst 20; bootstrap listeners
allow 10/sec, burst 16, for aggregate shared-NAT traffic. Data request frames now cap at 128 KiB; responses remain
bounded by the existing 2 MiB protocol maximum. Bootstrap requests cap at 16 KiB.

An authenticated data request also checks the peer-ID block. Eight attributable
failures within a 60-second window trigger a five-minute ban. Examples include
invalid requests and exceeding that client's own allowance. Authenticated abuse
is attributed to the verified peer ID; pre-authentication failures are attributed
to the observed source IP. Global capacity rejection and a busy search worker do
not count as client abuse. No ban is created from an unverified claimed peer ID.

IP quotas necessarily share capacity behind NAT. Data-listener pre-TLS abuse can still cause
a shared-IP ban; separating authenticated identities does not solve that earlier
stage. Bootstrap quota congestion instead returns backpressure without counting
normal shared-NAT overload as abuse. Verified signaling identities have their own
2/sec, burst-eight budget and attributable repeated abuse can still trigger a
peer ban. Signaling also has global 10/sec and shared-IP 8/sec budgets. Structured
seed rate-limit replies include retry_after seconds for bounded client backoff.
There are no automatic subnet bans. Operators may explicitly block CIDRs.
At most 1,000 live block rules, 4,096 quota entries and 4,096 failure counters are
held. Expired bans are removed during checks and maintenance. Quotas/counters
are per process and reset at restart; active bans and manual rules persist.

## Search-specific defense

Search uses separate buckets: 2 requests/sec per verified peer (burst 8),
4/sec per source IP (burst 16), and 4/sec globally (burst 16). It also has one
nonblocking concurrent-search slot per node process. Excess callers receive a
denial before entering search, rather than forming a search queue. Other RPCs
use separate request buckets (10/sec per peer, burst 30; global 20/sec, burst 40).

Each admitted search token includes 50 ms of thread CPU time. More expensive
searches debit additional tokens from peer/IP/global search budgets after
completion, capped at 20 extra tokens. This prevents a client from sustaining
expensive searches merely by staying below a requests-per-second threshold.
The search CPU charge includes failed searches and does not require proof of
work. Clients must back off after denial; the CLI does not automatically retry.

Remote searches have a cooperative 500 ms wall-clock evaluation budget. Checks
occur during provenance traversal and scoring. Exhaustion returns a denial,
never an apparently complete empty or partial result. This is not hard CPU
preemption: an individual signature check, regex operation, sort, SQLite wait or
Python scheduling can overrun a checkpoint. Local operator search is exempt.
An incremental lexical/vector index bounds full provenance verification to 256
candidates; candidate_limited coverage exposes that retrieval limit. The immutable
wire verification cache never caches grants or other access decisions.
The existing node lock still serializes database operations, so an in-flight
search can delay other data work until it finishes or reaches its budget.
Production scale needs worker isolation/indexes and measured fairness under load.

## Registration costs

Private demo mode retains zero-bit work unless configured. Public-address mode
now defaults to **18 bits**, requires at least 16, and retains the client's
20-bit/two-second maximum. This is an admission friction policy, not a promise
that every weak CPU completes a puzzle. Test weaker devices before deployment.

Challenge and registration have distinct source-IP buckets: each allows one
request per ten seconds with burst four. Each has a global bucket of one/sec,
burst eight. Successful cryptographic verification also precedes an identity
quota of one registration per minute, burst two. Every renewal consumes a new
work ticket. Changing peer IDs does not reset the source-IP budgets. Existing
work binding, expiry and atomic replay-consumption rules remain in force.

Blocked peer IDs and advertised IP ranges are refused at registration and
filtered from discovery responses. Advertised addresses are used for filtering,
never for automatic punishment. The directory still caps at 1,000 entries; work
and quotas do not prove Sybil resistance or prevent a distributed attacker from
occupying the directory. Admission reservations/eviction and load tests remain
future work. Bootstrap discovery responses are separately limited to 2/sec per
source, burst 10, and 5/sec globally, burst 20. A rapid full-directory enumeration
may be denied; no completeness claim is made.

## Operator controls and audit

```bash
intertexum --data /path/to/node security-block --peer PEER_ID
intertexum --data /path/to/node security-block --cidr 203.0.113.0/24 --seconds 3600
intertexum --data /path/to/node security-status
intertexum --data /path/to/node security-audit
intertexum --data /path/to/node security-unblock --cidr 203.0.113.0/24
intertexum --data /path/to/node security-unblock --peer PEER_ID
intertexum --data /path/to/node bootstrap-forget PEER_ID
```

These commands are local-only. `security-block` denies direct activity and
referrals; use the existing `block PEER_ID` command as well when withdrawing
origin trust for previously cached memory and its descendants. `bootstrap-forget`
removes the current directory entry; block that peer too to prevent registration
again under that identity. Neither operation erases copies already obtained by
other nodes, and key rotation creates a different identity.

The audit stores timestamp, event category, observed source address when relevant,
verified peer ID when available and a short controlled detail. It excludes search
terms, vectors, memories, message bodies and raw requests. Only the first failure
in a window and subsequent ban are recorded, plus registration/admin events.
The database retains at most 2,000 events and 24 hours; the CLI displays the newest
200. Live listeners purge expired audit/bans every minute. Live seeds also purge
expired announcements/tickets every minute, even without registration traffic.
Logical SQL deletion does not guarantee forensic erasure from WAL or backups.

Application bans are built in and require no root access. Optional host Fail2Ban
examples are under `ops/fail2ban/`. They match a fixed stderr line emitted only
after the application bans an **observed source IP**. Advertised addresses,
exception strings and peer-supplied content never become the ban target. The
example jail is disabled by default; review service name, ports, administrator
access and your host firewall before enabling it. We did not install Fail2Ban
or change host firewall rules. The external integration template has not been
validated against an installed Fail2Ban daemon here.

Application defense cannot stop link saturation or protect SSH and other host
services. A public host still needs OS patching, service supervision, host/network
firewalling and upstream DDoS handling. Local quotas are prototype defaults, not
an Internet-resilience certification. See the [Fail2Ban project](https://github.com/fail2ban/fail2ban)
and its [filter-safety guidance](https://fail2ban.readthedocs.io/en/latest/filters.html).
