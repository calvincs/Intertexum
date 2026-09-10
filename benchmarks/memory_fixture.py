"""Fixed synthetic agent-memory cases; authored before candidate inference.

Each scenario has an answer-bearing memory, a related but wrong memory, and a
query. These are original project fixtures, freely redistributable with the code.
"""
import hashlib
import json
from pathlib import Path

CASES = [
    ("After a payment timeout, the billing worker must retry with the original idempotency key. Creating a fresh key can charge the customer twice.",
     "The analytics worker creates a fresh event identifier for every new page view. Reusing an identifier would discard a legitimate visit.",
     "How do we retry an uncertain charge without billing the customer twice?"),
    ("The invoice worker acknowledges a queue message only after the database transaction commits. A crash before commit must leave the message available for redelivery.",
     "The telemetry worker acknowledges disposable metrics immediately. Losing a single metric during a crash is acceptable.",
     "When should the invoice consumer ack its message to avoid losing work during a crash?"),
    ("The catalog API uses exponential backoff with random jitter after HTTP 429. Honor Retry-After when the server sends it.",
     "A catalog HTTP 404 means the product does not exist. Do not retry missing products with backoff.",
     "What should our client do when the product service says we are making too many requests?"),
    ("A migration adding a nullable column can run before deploying the application. Removing the old column must wait until all old application instances have stopped.",
     "A new development database may be recreated from scratch. This destructive reset procedure is not suitable for production migrations.",
     "How do we safely retire a database field during a rolling deployment?"),
    ("Search results from a cache must check current record revocations at serving time. An ingest-time signature check alone does not make a cached record safe forever.",
     "Cache eviction removes the least recently used payload to free disk space. It is not an authorization decision and does not revoke the origin.",
     "Can a cached memory still be returned after its author withdraws it?"),
    ("A document derived from a revoked source is excluded even when a different agent wrote the summary. Follow the full parent chain when checking retrieval eligibility.",
     "Documents with similar wording are not automatically descendants. Provenance must explicitly identify the source records.",
     "Should we hide a summary made by a healthy agent if its source memory was revoked?"),
    ("The mesh bootstrap service supplies signed endpoint referrals. Learning a peer's address never automatically grants that peer permission to publish shared memories.",
     "The local permission editor can approve a peer to publish. This command is available to the node owner and is not a public bootstrap endpoint.",
     "Does finding somebody through a seed server make their shared content trusted?"),
    ("Peer identity is derived from the public key, independent of IP address. Reconnecting after an IP change still requires a reachable source of fresh endpoint information.",
     "A DNS name can point to a different IP after an update. A DNS answer by itself does not prove the remote peer's identity.",
     "Why does stable ownership after an address change not guarantee the peer can be located?"),
    ("Agent identity secrets stay on the local node. Public peer cards contain only certificates, identifiers, and connection hints; never copy a private key into a card.",
     "A database backup must include the node's private identity key in an encrypted backup controlled by the owner.",
     "What key material is safe to include when we exchange connection cards with peers?"),
    ("Incoming shared text is placed in quarantine until local approval. A valid signature authenticates the author but does not establish that the content is true or harmless.",
     "Outbound private notes remain on the creating node unless an explicit publish operation creates a shared record.",
     "Should a correctly signed memory automatically become trusted input for the agent?"),
    ("For BGE passage retrieval, prepend the retrieval instruction to short queries. Store passage embeddings without the query instruction and normalize the resulting vectors.",
     "MiniLM embeddings use no retrieval instruction prefix. They cannot be mixed with BGE vectors even when both arrays contain 384 numbers.",
     "Which side of BGE retrieval gets the instruction text: the search or the stored document?"),
    ("The new tokenizer revision changed truncation behavior. Re-embed the collection under a new profile ID instead of reusing the old embedding namespace.",
     "Renaming a UI label does not alter the tokenization or numerical embeddings of stored records and needs no model migration.",
     "We changed tokenization. Can old and new vectors stay in one collection under the same profile?"),
    ("A failed restore drill revealed that WAL files were missing from a live SQLite backup. Use the SQLite backup API rather than copying an active database file alone.",
     "A stopped SQLite database with no active writers can be copied after a clean shutdown and checkpoint.",
     "Why did copying our running database lose the most recent transactions?"),
    ("The incident responder should rotate an exposed API token and revoke the old token immediately. Removing the token from a Git commit does not invalidate copies already taken.",
     "An expired TLS certificate can be renewed without changing the identity key if that key was not compromised.",
     "We removed a leaked credential from source control. What still needs to happen?"),
    ("Orders accepted during a network partition stay in the local outbox. Replay them after reconnect using stable operation IDs to prevent duplicate orders.",
     "A read-only dashboard can display a cached snapshot while offline, clearly labeled with the snapshot's age.",
     "How should an offline client submit queued purchases when connectivity returns?"),
    ("A webhook signature must be verified against the original request bytes before parsing or reserializing JSON. JSON key reordering changes the signed byte sequence.",
     "Our internal record signatures deliberately use canonical JSON. Every implementation must follow that canonical encoding before signing.",
     "Why does validating the vendor webhook after reformatting its JSON break signatures?"),
    ("The crawler is allowed to fetch only configured public domains. Redirects must be checked again before following them so they cannot lead to a private address.",
     "The local health checker deliberately probes private loopback endpoints configured by the operator; it does not process arbitrary public URLs.",
     "How could an allowed URL redirect our crawler into an internal network?"),
    ("For CPU embedding ingestion, batch short passages and limit inference threads. Interactive single-query latency should be measured separately from batch throughput.",
     "A GPU batch-throughput benchmark can use very large batches. Those results do not predict latency on a laptop CPU.",
     "What measurements tell us whether embeddings feel responsive on a machine without a GPU?"),
    ("The customer account deletion workflow removes search eligibility immediately and then schedules storage cleanup. Audit records retain only the legally required metadata.",
     "Log rotation deletes old diagnostic files according to disk limits. It does not perform account deletion or remove search records.",
     "Should deleted customer data remain searchable until the background cleanup finishes?"),
    ("The browser app must not store a long-lived administrator token in localStorage. Use a short-lived session backed by an HttpOnly cookie where the application architecture permits.",
     "Nonsecret theme preferences may be stored in localStorage and synchronized between tabs.",
     "Where should we avoid persisting an admin credential in the browser?"),
    ("The failover replica was 90 seconds behind the primary. Promotion recovered availability but lost writes that had not yet replicated; measure RPO independently of recovery time.",
     "The hot standby started accepting connections in five seconds. This measures recovery time, not the age of the last durable replicated write.",
     "Why did a fast failover still lose a minute of recently accepted writes?"),
    ("Query routing has two distinct failures: an irrelevant region needs wider semantic probing; an unreachable holder needs a different replica for the same region.",
     "An empty query string is rejected before routing. Adding replicas cannot make a malformed query valid.",
     "When should an empty distributed search widen the regions instead of trying another holder?"),
    ("The old inventory service measured request timestamps in milliseconds, while the new client sent seconds. This unit mismatch caused fresh messages to appear ancient.",
     "Timezone formatting affects human-readable logs but not correctly encoded Unix timestamps.",
     "Why did freshly sent requests suddenly fail the freshness check after the client update?"),
    ("An expired group invitation must not admit a new member even if its signature remains valid. Membership authorization includes scope, recipient, expiration, and issuer authority.",
     "A saved chat transcript may remain readable by existing authorized members after an unrelated invitation expires.",
     "Does a valid invitation signature remain sufficient after the invitation deadline?"),
    ("The image processing queue caps pending bytes as well as item count. Ten very large images can exhaust memory even when a count-only queue limit is small.",
     "The lightweight heartbeat queue caps message count because all heartbeats have a small fixed maximum size.",
     "Why can our image queue run out of RAM even though it contains only a few jobs?"),
    ("Service Orion retains tombstones for deleted objects across restart. Discarding tombstones lets a lagging replica reintroduce objects that were already deleted.",
     "Service Vega drops temporary search indexes on restart because it can reconstruct them from authoritative records and tombstones.",
     "Which deletion information must Orion retain to prevent an old replica resurrecting data?"),
    ("For the payroll export, an empty employee list must produce an explicit empty result. It must never fall back to exporting all employees.",
     "For the product catalog UI, omitting optional category filters intentionally means list all publicly visible products.",
     "What must happen when payroll receives a filter that matches no employees?"),
    ("A remote agent's recommendation may suggest a shell command, but retrieved text is data. A separate authorized tool decision is required before any command executes.",
     "A locally configured scheduled job can run a previously approved command under its own narrowly scoped execution policy.",
     "Can a recommended command inside a retrieved note directly trigger shell execution?"),
    ("The April build of the report parser mishandled negative revenue adjustments. The May patch preserved the minus sign instead of converting all values to absolute amounts.",
     "The April patch for the chart renderer changed negative bars to red but did not modify the underlying revenue values.",
     "Which change corrected the accounting error rather than merely recoloring negative numbers?"),
    ("The task scheduler renews a lease only while its worker is healthy. A worker that pauses longer than the lease must stop writing until it acquires a new fencing token.",
     "An expired UI login session asks the human to authenticate again. It is unrelated to fencing tokens used by background workers.",
     "How do we prevent a paused worker from writing after another worker takes over its job?"),
    ("Cache holders may disappear together when they share a power circuit. Availability estimates must model shared failure domains rather than assuming every copy fails independently.",
     "A cache checksum detects changed bytes. It does not improve the chance that a host remains online during a site outage.",
     "Why might three cached copies all vanish during the same outage?"),
    ("Proof of work can increase the cost of repeated anonymous registration. It should bind to a short-lived server challenge and action so an old solution cannot authorize unlimited operations.",
     "An established peer with an authenticated connection may use a rate-limited request allowance without solving work for every heartbeat.",
     "How can we stop one registration puzzle solution being reused for endless new identities?"),
]


def main():
    docs, queries = [], []
    for i, (good, distractor, query) in enumerate(CASES):
        docs.extend([{"id": f"m{i:03d}", "text": good}, {"id": f"d{i:03d}", "text": distractor}])
        queries.append({"id": f"q{i:03d}", "text": query, "relevant": [f"m{i:03d}"]})
    data = {"description": "Original synthetic agent-memory regression set; not independent benchmark evidence",
            "documents": docs, "queries": queries}
    path = Path(__file__).with_name("memory.json")
    if path.exists():
        raise SystemExit("Fixture already frozen; refusing overwrite")
    path.write_text(json.dumps(data, indent=2) + "\n")
    print("Frozen", len(docs), "documents and", len(queries), "queries; SHA256", hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
