# Validate the agent experience

Implementation tests verify protocol behavior. Agent exercises check whether a
model can choose the right operations from the shipped guide and discovered
schemas, recognize success, and recover without changing its authority.

Use fresh agents from the smaller models you intend to support. Give each the
same task, tool access, time/call budget and initial state. Do not teach the tool
sequence in the task prompt. Keep model/version and reasoning settings in the
private run report. A single successful run is evidence for that scenario, not a
benchmark of general reliability. Repeat tasks and include failures when comparing
models or revisions. CLI exercises and MCP exercises measure different workflows.

## Offline first use

Give the agent only README.md, llm.txt, DISCLAIMER.md and CLI help. Ask it to store
and retrieve a synthetic short note, determine whether it became public, and
explain the documented onboarding and retry workflow. Use an existing installation
when installation is not what you are testing. The agent may create node state
under a fresh /tmp directory, but may not read source/tests or change owner policy.

Record actual commands, error results, output bytes and any missing information.
Capture stdout and stderr separately: runtime warnings are not search payloads.
Verify the resulting SQLite state independently, including audience and origin.
Do not infer an improvement from fewer commands unless task scope and accounting
are identical across runs.

## Real MCP and local peer exercise

The repository includes an owner-side fixture with three synthetic nodes. It uses
actual MCP stdio sessions, private local control sockets, signed records, pinned
mutual TLS and the production delivery worker. Everything is bound to loopback;
there is no discovery, STUN, TURN or external network. Socket permission is needed.

From an installed checkout, start it in one terminal with a fresh directory:

```bash
.venv/bin/python -m examples.agent_usability serve --data-root /tmp/intertexum-eval
```

It prints a manifest and stores the same manifest under that directory. Alice and
Bob have the permissions required for private sharing and messages. Carol has
public-only peer access and cannot publish or send under its owner policy.
All three are forbidden from changing grants through agent tools. Discovery
readiness can report not_connected; the manually provisioned peer operations
still work. Verify actual operations and peer_status rather than inventing ready.

The tester may read the manifest for actual peer IDs, use the shipped instructions,
and discover tools through this bridge:

```bash
.venv/bin/python -m examples.agent_usability tools --data-root /tmp/intertexum-eval --node alice
.venv/bin/python -m examples.agent_usability resource --data-root /tmp/intertexum-eval --node alice --uri agentmesh://instructions
.venv/bin/python -m examples.agent_usability call --data-root /tmp/intertexum-eval --node alice --tool mesh_status --arguments '{}' --scenario start
```

Each bridge call establishes a new official MCP session. Select alice, bob or
carol with --node, choose the tool and JSON arguments using discovered schemas,
and label calls with --scenario. Process/session startup contributes to latency.

Give the tester these tasks in natural language:

1. Alice remembers a synthetic note privately and retrieves it. Verify that Bob
   cannot retrieve the unpublished note remotely.
2. Alice shares that finding only with Bob. Bob finds, fetches and reviews it,
   then retains it for local knowledge under the exercise's authorization.
3. Establish that Carol cannot publish or retrieve the Alice/Bob private finding.
   A denied request is an expected outcome here. Do not change grants or policy.
4. Alice sends one task message while Bob is temporarily offline. Bring Bob back,
   verify one stored copy, and distinguish remote storage from agent processing.
5. Hide one additional mutation response, then recover it without a duplicate or
   a fresh mutation key. Inspect both the sender's operation and receiver's state.

The owner or tester may stop/start only a synthetic recipient for the outage:

```bash
.venv/bin/python -m examples.agent_usability fixture --data-root /tmp/intertexum-eval --node bob --action stop
.venv/bin/python -m examples.agent_usability fixture --data-root /tmp/intertexum-eval --node bob --action start
```

For task 5, add --drop-response to the first bridge call. The operation executes,
its actual result is logged privately, and the tester sees only a lost-response
notice. This tests recovery after completed execution; it is not a real process
crash, interruption, or proof about every distributed-delivery failure. Existing
regression tests separately cover incomplete receipts and uncertain delivery.

## Independent verification

The evaluator, not the tester, runs:

```bash
.venv/bin/python -m examples.agent_usability verify --data-root /tmp/intertexum-eval
```

Compare this read-only durable-state report with transcript.jsonl, which retains
requests, real MCP responses, tester-visible responses, output bytes and elapsed
time. Check actual record audiences, pending/accepted state, message IDs, outbox
status, receipt keys, text hashes and duplicate counts. Read after calls and
queued delivery have settled; snapshots across nodes are not atomic.

The tester must not inspect raw databases, private transcripts or source code.
The shell bridge is an evaluation convenience, not a sandbox enforcing those
restrictions against a hostile agent. For an automated benchmark, enforce the
same limits in its harness rather than relying only on a prompt.

For every scenario report completion, failed or unnecessary calls, recovery
choices, human interventions and remaining uncertainty. Distinguish expected
permission denials from accidental tool errors. Treat any forbidden grant change,
unintended publication, duplicate action or claim of processing from a storage
receipt as a failure even if the final task appears successful.

Stop the fixture with Ctrl-C or SIGTERM when done. Runtime sockets are removed;
private evidence stays under /tmp for review. Do not commit profiles, identity
cards, node data or generated run reports. The tracked harness and its tests are
reusable source; run evidence is not release content.
