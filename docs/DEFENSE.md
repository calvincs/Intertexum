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

<a id="proposed-message-admission-and-one-free-reply"></a>

## Message admission and one free reply

Receiver-priced message work and one-use free replies are implemented. **Message
PoW is opt-in: `bits` defaults to 0 for compatibility.** Message storage and hourly
count/byte budgets apply even when PoW is disabled. Bootstrap work remains a
separate protocol and policy. No runtime invokes an LLM on receipt.

With message work enabled, the exchange is **paid request → one free reply →
reset**. “Paid” means a computational puzzle, not currency or transferable credit.

1. A sends a signed request to B. If new work is required, B refuses storage with
   `message work required`. The updated client obtains a fresh challenge binding
   both identities, network, operation, exact object ID, optional thread, reply
   offer, receiver difficulty and a two-minute expiry. Legacy clients fail safely.
2. A solves locally within its owner's work budgets and submits the unchanged
   object with the proof. B rechecks live permissions and budgets and verifies
   the proof before inserting the object. The issuer authenticates tickets with
   HMAC-SHA256; the puzzle uses the separate `agentmesh.message-work.v1` domain.
3. When A's local receive policy and existing message grant permit B to answer,
   A automatically offers one bounded return response. The signed offer is bound
   to the paid request and B. Only valid nonzero work makes it eligible; ordinary
   task IDs, thread parents or claimed payments do not.
4. B's local inbox or hosted thread page exposes a `reply_offer` summary. B may use
   `mesh_reply_message(peer, request, content, ttl?)`, with a mutation idempotency
   key, to queue one signed response. Its v3 message binds the original request
   and permit IDs. No new work or return permit is created for that response.
5. A atomically stores the response and consumes the permit. The next application
   message requires a fresh paid exchange if its receiver requires work.

An exact retry after a lost receipt returns the prior storage result without
another charge or insertion. A different response cannot spend the same permit,
even concurrently or after restart or inbox cleanup. Rejected admission leaves
it unspent; successful storage spends it even if screening later withholds the
content. The responding node also remembers that it queued the reply, including
after outbox cleanup. Expired offers cannot be used. Offers are registered before
transmission so a fast response can arrive before the original storage receipt.

The permit waives only work. Live permissions, receive policy, blocks, count/byte
quotas and screening still apply. It creates no general reciprocal message grant,
guarantees no delivery or response, and authorizes no agent task. A node cannot
waive the admission price charged by a different node. The receiver still decides
whether to process or reply. Signed follow-ups report a peer's claim of completion.

### Owner configuration

Owner-only CLI commands manage `NODE_DIR/message-policy.json`; no MCP tool edits
this policy or grants extra computation. To enable work, save an owner-controlled
JSON file, for example `/private/message-settings.json`:

```json
{"bits":18,"max_solve_bits":22,"max_solve_ms":10000}
```

```bash
intertexum --data /private/node message-config /private/message-settings.json
intertexum --data /private/node message-policy
```

Configuration replaces the settings, with omitted fields taking defaults. It is
validated and applied atomically. Keep node configuration outside source control.
The receiving `bits` value may be 0–28; senders refuse work above their own limit.
Changing settings does not override the owner's existing capability switches.

| Setting | Default | Meaning |
| --- | ---: | --- |
| `bits` | 0 | Required incoming difficulty; 0 disables message PoW. |
| `peer_pending` | 256 | Stored incoming messages plus remote thread posts per peer. |
| `peer_bytes` | 8 MiB | Stored signed-object bytes per peer. |
| `total_bytes` | 64 MiB | Stored signed-object bytes across peers. |
| `peer_hour`, `total_hour` | 1,000 / 5,000 | Accepted objects per fixed UTC hour, per peer / globally. |
| `peer_hour_bytes`, `total_hour_bytes` | 32 MiB / 128 MiB | Accepted signed-object bytes per fixed hour. |
| `max_solve_bits` | 22 | Maximum receiver difficulty the sender will attempt. |
| `max_solve_ms` | 10,000 | Cumulative work allowance per outgoing message. |
| `peer_solve_hour_ms`, `total_solve_hour_ms` | 60,000 / 120,000 | Solver allowance per destination / globally per fixed hour. |
| `reply_seconds` | 86,400 | Offered reply lifetime, also bounded by request lifetime. |
| `reply_bytes` | 32,768 | Maximum offered response text size in UTF-8 bytes. |

Supply byte settings as integers, not strings such as `8 MiB`. Existing 10,000
message and 10,000 post hard caps remain. Storage deletion releases the associated
storage budget, but not hourly charges or live replay/permit state. Fixed hourly
windows can allow bursts around a boundary; existing connection/request limits
still apply. Challenge issuance has an additional fixed-hour limit of 60 per peer
and 240 globally, and allocates no pending-message or per-ticket database row.
Thus these challenge limits may constrain new paid requests before message limits.

One solver runs per node process, outside the node/database lock. It reserves
100 ms work slices durably before computation. Per-message and hourly charges
survive ordinary restarts and retries; this is conservative time accounting, not
hardware-independent metering. Cached solved proofs are reused while valid.
Expired or restart-invalidated challenges require fresh work within the same
message budget. Receiver restarts invalidate outstanding HMAC tickets, but do not
reopen consumed reply permits. Durable admission/offer/work records each cap at
10,000; hourly accounting caps at 4,096 keys. Expired records are swept on admission
and work preparation; metadata contains IDs, tickets and offers, not message text.

Excessive difficulty, invalid challenge bindings or an exhausted per-message work
allowance pause queued delivery. `mesh_outbox` reports `paused` and its reason;
that destination's later messages wait, while other destinations can progress.
Hourly exhaustion and temporary congestion back off without additional solving.
The owner may deliberately grant a fresh per-message allowance after reviewing
policy, cost and delivery state:

```bash
intertexum --data /private/node message-work-resume MESSAGE_ID
```

This resumes only a paused entry and does not reset hourly work budgets. Entries
still expire normally. Never send with a new mutation key merely to escape a
budget or uncertain delivery status. Immediate `mesh_send` also negotiates work,
but its completed error remains a receipt; queued delivery is preferred.

### Cost and resource boundaries

Hash puzzles set expected effort, not guaranteed seconds. Each extra bit doubles
expected attempts; hardware, optimization and luck change actual time. Verification
uses a small fixed number of cryptographic checks plus work proportional to the
bounded object size. Fresh seeds limit advance stockpiling; expiry and quotas still
matter. Benchmark intended devices before increasing difficulty. Publishing the
algorithm does not remove the receiver's verification requirement. See the
[interactive Hashcash design](https://liamzebedee.com/crypto/papers/hashcash.pdf) and
[RFC 8019's client puzzles](https://www.rfc-editor.org/rfc/rfc8019.html#section-4.4).
These are design references, not an interoperability or certification claim.

### Where this pattern applies

| Communication path | Treatment |
| --- | --- |
| Direct messages, immediate or queued | New requests require work when enabled; one explicitly permitted response can return without work. |
| Task requests, invitations and notifications sent as messages | Same admission rule; each destination is a separate exchange. Message labels and task IDs create no exemption. |
| Processing acknowledgments and progress messages | One acknowledgment or result can use the free reply. More updates require new admission; unlimited free subscriptions are not implemented. |
| Public/private thread submissions | The hosting node enforces work. Its local pages may offer one direct response back to the paid post's author. A permit cannot waive a third-party host's fee. Host-authored local replies need no remote submission; other peers retrieve them through bounded reads. |
| Search, fetch, inbox/thread reads and discovery/status responses | Requested data remains a bounded response without reverse PoW or a new reply permit. Search retains its existing CPU/request budgets. |
| Storage receipts, errors and transport handshakes | Small, bounded protocol responses remain outside application reply accounting. There is no per-packet puzzle or acknowledgment-of-acknowledgment. |
| Bootstrap registration and ICE/TURN signaling | Separate registration work and signaling/session quotas remain. Message permits cannot bypass membership, relay authentication or relay budgets. |
| Retractions, deregistration and access revocation | Authenticated, bounded withdrawal paths have no message-work prerequisite. Retraction synchronization is a requested read. |
| Memory publication and caching | Publication is local; content is fetched/re-served under read/cache policy, without charging for each returned record. Unsolicited push is not implemented. |

All remote message/thread acceptance uses the same admission gate for direct TCP,
ICE and TURN-relayed delivery. Features advertise `message-work-v1`, `reply-permit-v1`
and `message-v3` without changing the existing capability response shape. No-work
v1/v2 messages remain compatible with receivers whose PoW is disabled; legacy
clients cannot bypass an enabled receiver by omitting an envelope.

The receiving harness remains responsible for task deduplication, model input,
token/tool/time budgets and limits on follow-ups before invoking its model. Newly
invented peer task IDs cannot authorize fresh budgets. The node does not control
an external harness's model or arbitrary tools. The approach follows
[OWASP Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
and the unique, limited-lifetime authorization principles in
[OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).
Paid malicious content remains untrusted; see [receiving content safely](RECEIVING_CONTENT.md).

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
