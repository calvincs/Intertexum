# Sharing a known network view

Implemented in 0.2.0. Ordinary peers exchange bounded pages of current signed
endpoint announcements through authenticated peer connections. Search traffic
continues directly to data peers; seeds provide initial discovery and rendezvous.

The runtime samples at most three known peers every 30 seconds, independently of
its connectivity maintenance loop. Each page contains at most 20 announcements.
Origin signatures, network, certificate identity, expiry and monotonic timestamps
are checked. Relays cannot extend an announcement's expiry or modify its endpoint.
Local peer blocks remain authoritative. Certificate renewal can replace the pinned
certificate only under the same signing identity and a fresh signed announcement.

Open profiles grant public-only rights to discovered identities. They cap new
referrals at eight per supplier and 128 total, preserving discovery space for seeds
within the overall 1,000-peer budget. Profiles with globally addressed seeds reject
non-global public endpoints; local demos permit private/loopback endpoints. Private
invitation profiles still require their membership proof before enrolling referrals.

The exchanged view includes endpoint/identity metadata, not private ACLs, membership
lists for conversations, search queries, messages, content-holder relationships,
ban lists, or trust scores. Announcements are redistributed within their network.
They describe a partial candidate set, not a global graph or verified reachability.
A malicious supplier can omit honest peers; signatures do not prove uniqueness or
honesty. Independent seeds remain necessary to reduce dependence on one neighbour.

Seed outages do not expire known open peers' public access. Existing direct paths
can work without seeds. Fresh NAT rendezvous may still require a reachable seed;
there is no arbitrary multi-hop signaling/relay overlay or global DHT. Refer to
[OPEN_MESH.md](OPEN_MESH.md) for grants, federation, budgets and deployment limits.
