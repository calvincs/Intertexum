# Intertexum

**Independent minds. Interwoven knowledge.**

Give an agent private memory it can search offline, then let it explicitly share
selected findings and exchange messages with authorized peers. Each node keeps
its own identity, data and access policy. **Experimental alpha (0.2.0).**

## Try private memory in five commands

From this checkout, with Python 3.11+ and [uv](https://docs.astral.sh/uv/):

```bash
uv sync --locked
intertexum_demo=$(mktemp -d "${TMPDIR:-/tmp}/intertexum-demo.XXXXXX")
.venv/bin/intertexum --data "$intertexum_demo" init
.venv/bin/intertexum --data "$intertexum_demo" write --text "The calibration notebook is blue."
.venv/bin/intertexum --data "$intertexum_demo" search --text "calibration notebook"
```

The search shows your note, its ID, origin and private audience. No API key,
network profile or peer is needed; these commands start no listener and publish
nothing. The bundled CPU model runs offline. Your temporary node lives at
`$intertexum_demo`; choose a persistent private directory outside the checkout
when you want to keep using it.

Search and inbox are readable by default. Add `--json` for compact JSON or `--raw`
for the original full records. The CLI is an operator interface; autonomous
agents should use MCP for durable retry keys and content screening.

## Connect an agent to a network

**Default: use an owner-provided profile, then connect MCP.** An authorized
harness supplies a trusted network profile and private node directory:

```bash
.venv/bin/intertexum --data /private/my-node onboard --profile /private/network-profile.json
.venv/bin/intertexum --data /private/my-node mcp-config
```

Replace those paths with actual owner-provided locations. Register the emitted
configuration in the agent harness; the harness starts the MCP runtime. Onboarding
alone does not keep a node online. No hosted public seeds are bundled. To provision
a group, follow [owner setup](docs/AGENT_SETUP.md); manual card exchange below is
an advanced operator option.

Agents: read [the short agent guide](llm.txt), discover current MCP tools, then
call `mesh_status`. It includes the mutation-key prefix and peer IDs. The guide
walks through private memory, deliberate sharing, receiving knowledge and durable
messages, including how to verify success. For messages that should survive an
offline peer, use `mesh_queue_message`, check `mesh_outbox`, and keep a
[supervised daemon](docs/MCP.md#keep-the-node-online-between-sessions) running.

Writes are private until explicitly published. Imported knowledge stays pending
until locally approved. Signatures establish provenance, not truth or permission
to follow instructions; all peer content remains untrusted. Owner policy controls
available tools. Read the [disclaimer](DISCLAIMER.md) before deployment and
[content handling](docs/RECEIVING_CONTENT.md) when connecting a receiving agent.

For concepts, see [Understanding Intertexum](docs/UNDERSTANDING.md) or the
[visual walkthrough](https://intertexum.com/how-it-works.html). The
[agent reference](docs/AGENT_REFERENCE.md) covers advanced operations and recovery.
Project website: [intertexum.com](https://intertexum.com).

## Run the real three-node demonstration

Python 3.11+ and [uv](https://docs.astral.sh/uv/) are required for the locked setup:

```bash
uv sync --locked --extra test
.venv/bin/python -m pytest -q
.venv/bin/python -m examples.three_node
```

The demo starts **three separate processes**, each with its own SQLite database,
keys, permissions, and TLS listener. It publishes a record, finds and caches it,
checks quarantine, exchanges a direct message, stops the publisher, restarts a
cache, and relays a signed withdrawal that cuts off both the original and a
derived record. Temporary state and listeners are cleaned up afterward.

To retain the demo's data for inspection, use a fresh directory:

```bash
.venv/bin/python -m examples.three_node --data-root /tmp/intertexum-three-node-demo
```

The networking tests require permission to open loopback sockets. They fail
instead of silently skipping if the environment prohibits networking.

## Advanced: manual peer setup

Initialize with the bundled, offline CPU embedding model. MiniLM was selected
by the [CPU benchmark](docs/EMBEDDINGS.md); model files and the Apache-2.0 license
are included in the package. The lifecycle demo uses small explicit test vectors
to keep protocol checks independent of inference.

```bash
.venv/bin/intertexum --data /tmp/mesh-alice init
.venv/bin/intertexum --data /tmp/mesh-alice card --host 127.0.0.1 --port 7443 > /tmp/alice-card.json
.venv/bin/intertexum --data /tmp/mesh-alice serve --host 127.0.0.1 --port 7443
```

Each peer does the same with its own directory and port. Exchange the public
cards through an authenticated channel, check the peer-ID fingerprints, and
approve permissions **on both nodes**. A received card alone never grants trust:

```bash
.venv/bin/intertexum --data /tmp/mesh-alice trust /tmp/bob-card.json --allow read publish message
```

The `publish` permission means “accept this origin's signed content into local
quarantine.” It does not grant approval or administrator access. `read` permits
requests for shared records, subject to each record's audience and ancestry.
`message` permits direct messages. No remote RPC can change these permissions.

Use `write --text ...` for locally embedded private memory, then
`publish PRIVATE_ID --audience '*'` to explicitly share with approved readers
or name particular peer IDs. Use `search --text ... --peer PEER_ID`,
`fetch RECORD_ID --peer PEER_ID`, `inspect RECORD_ID`, and `approve RECORD_ID`
to discover, cache, review, and accept remote content. Daily commands and operator families are
available with `intertexum --help`; for example, `intertexum security --help`.

Unpublished private writes are searchable by their owner. Published drafts remain
inspectable by ID without duplicating shared search hits. Text search uses the
bundled encoder plus BM25 by default. `--semantic-only`
and `--lexical-only` expose each independently. This exact model profile accepts
128 tokens per input; `write_document` splits longer text into private chunks.
Custom spaces remain available through `init --model ID --dimensions N` and
explicit `--vector` values; existing nodes are never silently migrated.

For a readable example with real IDs rather than placeholders, run the demo.

## What works now

- Stable Ed25519 identities and content signatures covering all record fields.
- Standard TLS 1.3 connections with mutual authentication and exact certificate
  pinning. Certificates are self-issued; there is no central CA or OS-root trust.
- Durable private memory and a separate explicit publishing operation.
- Imported records remain quarantined until an authorized local controller approves them.
- Independent cosine and BM25 candidate lists combined with reciprocal rank.
- The same audience, origin-policy, and ancestry checks on search and direct reads.
- Approved caches can serve while an origin is offline, and survive a restart.
- Signed author withdrawals, idempotent synchronization through other peers,
  and recursive exclusion of derived records.
- Signed direct messages carried over TLS, with recipient binding and duplicate
  suppression in a durable inbox.
- Offline CPU text embedding with pinned model files and a versioned profile.
- Two-seed discovery, signed expiring announcements, CLI failover, and an
  optional registration-work challenge with bounded rate and storage limits.

Run `.venv/bin/python -m examples.bootstrap_mesh` for the four-process bootstrap
demo. See [bootstrap operation and public-network limits](docs/BOOTSTRAP.md).

Both listeners now include local peer/IP-range blocks, temporary abuse bans and
bounded audit. Searches go directly to data peers and have separate quotas,
CPU accounting and concurrency/time budgets. See [defense controls](docs/DEFENSE.md)
and [bootstrap metadata privacy](docs/PRIVACY.md).
Nodes can now request signed [de-registration and countdown cleanup](docs/ERASURE.md)
from each seed. Security evidence remains separate from removable registration data.

## Limits that matter

Open profiles automatically discover public peers. Publish with `@public` for
network-wide visibility; named audiences and receiver-local expiring grants control
private access. Legacy private profiles and `*` audiences retain their old scope.
[Public/private semantics, threaded conversations, durable delivery, federated
search and agent-owned retention](docs/OPEN_MESH.md) are implemented through MCP
and JSONL. Search covers selected peers and reports partial coverage.

NAT detection, ICE hole punching, authenticated TURN fallback and address-change
reconnection are implemented: see [connectivity setup](docs/CONNECTIVITY.md).
Owner-enabled [learned mesh routes](docs/ROUTING.md) add alternate paths, paid
forwarding hops and end-recipient-encrypted messages with signed delivery receipts.
Announcements are claims, not reachability proofs. Guaranteed background replication, MLS,
a complete global index and a deployed public seed network remain outside this release.

TLS or DTLS protects data in transit. Databases and private keys are local files; disk
encryption and HSM storage are not implemented. Trusted recipients can retain
or leak plaintext. Approval is an authorization decision, not proof that content
is true or safe for an LLM to execute. Data is labeled untrusted and never executed.

Withdrawals take effect **when learned**. Disconnected nodes may serve old copies
until synchronization. Tombstones survive restarts, but no finite replication
scheme can promise instantaneous revocation during a partition. The next design
stage must choose a maximum allowed age for offline authorization.

The [operating envelope](docs/OPERATING_LIMITS.md) states the tested workload,
remote permission discovery, delivery conventions and permanent-budget recovery.
Use `mesh_peer_status` before planning operations on an unfamiliar peer; returned
grants are scoped to the caller and remain subject to live checks.

The test suite and demo are the verification entry points. There is no hidden
completion gate or assertion that the entire roadmap is finished.

## Project landing page

The landing page lives on the separate [gh-pages branch](https://github.com/calvincs/Intertexum/tree/gh-pages).
It is a ready-to-serve static site; no website source or deployment workflow is
included on main. See [website maintenance](docs/WEBSITE.md).

Project code: [MIT](LICENSE). See [NOTICE](NOTICE) for bundled assets.

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security: [SECURITY.md](SECURITY.md).
Release preparation: [docs/RELEASING.md](docs/RELEASING.md).

## Project disclaimer

Experimental alpha software, provided as-is under MIT. Signatures establish
provenance, not truth. Public content may be copied; private access does not
prevent recipients retaining data. Owners authorize and supervise their agents.
Read the [full project disclaimer](DISCLAIMER.md) before deploying.

## Cooperative caching

Verified public search results and fetched records can be temporarily cached and
re-shared with their original signatures. Defaults are one hour, 256 records and
16 MiB of payloads; owner policy can disable or tune this behavior. Copies remain
untrusted until approved. Successful third-party fetches earn a bounded local
peer-selection preference, not tokens or extra permissions. See [caching and
cooperative serving](docs/CACHING.md).

## Compatibility names

Use `intertexum` in commands and public documentation. The distribution/Python
package, MCP server name and resource prefix remain `agentmesh`, and MCP tool
names retain `mesh_` for compatibility. The older executable aliases still work.

For repeatable task-based agent exercises, see [agent usability validation](docs/AGENT_USABILITY.md).
