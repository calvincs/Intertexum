# Temporary caching and cooperative serving

Intertexum opportunistically caches verified public records accessed through peer
search or fetch. It can re-serve those copies without re-signing them or approving
them as local knowledge. Private records are not automatically put into this
transit cache. Explicitly approved imports retain their existing audience checks.

## Defaults and owner control

The temporary cache defaults to a one-hour TTL, 256 records and 16 MiB of signed
record payloads. These are logical payload limits, not a physical SQLite/WAL disk
quota. The existing overall record limit also applies. Least recently used transit
entries are evicted when the cache exceeds its limits. Authored records, explicit
retention choices and approved memory are not evicted by the temporary cache.

Owner policy has three additional booleans, enabled by default:

- `cache`: permit automatic public caching and local cache hits.
- `reshare`: permit serving imported records to other peers, including both
  temporary copies and explicitly approved imports. `serve_memory` must also allow
  remote reads. This does not affect serving the node's own authored records.
- `reward_relays`: record successful third-party fetches and use local provider
  preference when selecting peers for federated search.

Automatic caching also respects `fetch` and `retain`. Disable these features in
`policy.json` when unwanted. Disabling a feature stops its use; it does not erase
existing stored data or grant an agent permission to override the owner.

Agents can use `cache_status` / `mesh_cache_status` and
`cache_configure` / `mesh_cache_configure`. Configuration permits TTL 60–86400
seconds, 1–2048 records and 64 KiB–256 MiB of payloads. Configuration requires
both cache and retention capabilities. Reducing TTL shortens existing cache
lifetimes; increasing it affects subsequent remote accesses. Explicit approval
promotes a record out of temporary cache management. `retain` preserves the
agent's chosen storage policy; an expired, retained pending copy still needs
approval before it can be served again.

## Read, re-share and expire

A live cache can satisfy a subsequent fetch locally, without another network
request. Use `fetch --refresh` or the MCP/JSONL `fetch` argument `refresh:true` to
bypass that local hit and synchronize known retractions with the selected peer.
A remote search result can refresh a public copy's TTL. Serving a copy or using a
local cache hit does not extend its TTL.

Transit copies remain `pending` and are excluded from ordinary local knowledge
search. Inspect them as untrusted data before approving. Other peers may search
and fetch eligible public copies; no private audience is widened. Required
ancestry must be available and permitted, and transit ancestors must be public.
Original signatures, model checks, local rejections, known withdrawals and origin
permissions continue to apply. Consumers must know the signing origin's identity.

Expiry prevents cache hits and re-serving immediately, even before cleanup runs.
Running node listeners and managed runtimes remove expired eligible copies about
once per minute; cache operations and explicit maintenance also clean up. Expiry
is a logical availability boundary, not guaranteed physical erasure from SQLite,
WAL, backups or other peers. A stopped node does not run cleanup. A withdrawn
record is unavailable as soon as its signed withdrawal is learned; there is no
network-wide instantaneous revocation or freshness guarantee.

This is access-driven caching, not background mirroring or guaranteed replication.
Threads, messages and private data are not automatically replicated by this feature.

## Reward useful providers locally

After a successful remote fetch of a verified public record signed by someone
other than its provider, the requesting node records a local contribution. A
record earns at most one credit on that requester in a rolling 24-hour period,
across all providers. Origin self-serving, local cache hits, search hits, failed
fetches and self-reported service counts earn no credit. At most 2048 observations
are retained, and the effective selection score is capped at 16 per peer.

When federated search chooses its own peers, up to three of eight slots favor
eligible contributors; remaining slots sample other eligible peers. Explicit
peer selection is unchanged. Credits expire, blocks and admission expiry still
apply, and the observation list stays local. Scores do not alter result ranking,
private access, quotas, proof-of-work, rate limits or security evidence.

This is a small routing incentive, not money, tokens, global reputation or a
proof of storage. It cannot prove that a provider stored a record for a duration,
and it is not Sybil-proof. Only content the requester actually fetches can earn
credit; no peer can submit reward claims. Keep the preference bounded and treat
its observed usefulness as a local scheduling hint, never a trust decision.
