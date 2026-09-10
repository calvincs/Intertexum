# CPU embedding decision — 2026-09-09

Ship **sentence-transformers/all-MiniLM-L6-v2**, using the pinned Qdrant ONNX
conversion. The package includes its files and Apache-2.0 license. It works
without an account, API key, GPU, or inference-time download. New nodes select
this profile by default. This is an English short-memory baseline, not a claim
about multilingual retrieval, source-code search, or all CPU architectures.

## Measured comparison

AMD Ryzen Threadripper PRO 3955WX, Linux x86_64, Python 3.13.11. ONNX CPU provider,
two inference threads, document batches of 16, fresh processes. No GPU was used.
Two threads constrain parallelism; they do not simulate an old laptop or ARM
board. Query latency uses 96 warmed single-query calls. Model-session loading
excludes imports and downloads and uses files already in the OS cache.

| Measurement | MiniLM, selected | BGE-small, Qdrant quantized |
|---|---:|---:|
| Model artifacts including tokenizer | 87.10 MiB | 64.29 MiB |
| Query latency p50 | 22.7 ms | 50.9 ms |
| Query latency p95 | 23.9 ms | 55.2 ms |
| First session construction | 0.178 s | 0.157 s |
| Short-memory documents/sec | 55.2 | 24.5 |
| SciFact documents/sec | 55.0 | incomplete |
| Full-corpus process memory | 384.0 MiB peak | stopped at observed 800.4 MiB |
| Effective tokenizer limit | 128 tokens | 512 tokens |

The [selection plan](https://github.com/calvincs/Intertexum/blob/main/benchmarks/PLAN.md) preceded evaluation. It set a 150 MiB
artifact budget and 750 MiB peak benchmark-process memory budget. BGE crossed
the memory budget during SciFact, so its large-corpus run was stopped. The
`benchmarks/results/bge-small-resource-limit.json` (generated locally)
records that termination. A separate completed memory-only BGE run supplies
its latency and memory-fixture metrics. Its memory-only process peaked at
244.9 MiB; **that is not comparable to MiniLM's full-corpus peak**.

This eliminates that BGE configuration under this declared batch/context budget;
it does not establish that BGE cannot run on CPU. Smaller batches or shorter
contexts could lower memory use and merit a future separately declared run.
There is no BGE SciFact quality score because its corpus encoding did not finish.
MiniLM is the sole eligible completed candidate, so the weighted-quality tie
rule is not used to claim a head-to-head quality win.

## Retrieval results

The frozen memory fixture has 64 original hand-authored snippets, 32 queries,
and one relevant snippet per query. It includes confusable distractors and
paraphrases. It is a small synthetic regression set, not an independent estimate
of real-user accuracy. SciFact is the full BEIR test split: 5,183 scientific
abstracts and 300 judged queries. It is external data, but its domain differs
from agent memory and model training overlap is possible.

| Dataset / retrieval | Recall@5 | Recall@10 | MRR@10 | nDCG@10 |
|---|---:|---:|---:|---:|
| Memory / MiniLM semantic | 1.000 | 1.000 | .889 | .917 |
| Memory / BGE semantic | .969 | 1.000 | .879 | .910 |
| Memory / BM25 | .688 | .781 | .624 | .661 |
| Memory / MiniLM hybrid | .844 | .875 | .701 | .744 |
| Memory / BGE hybrid | .844 | .875 | .760 | .789 |
| SciFact / MiniLM semantic | .687 | .774 | .578 | .624 |
| SciFact / BM25 | .726 | .791 | .628 | .662 |
| SciFact / MiniLM hybrid | .756 | .846 | .640 | .686 |

Hybrid uses independent cosine and BM25 rankings with RRF constant 60, matching
the implementation's scoring formula. Benchmark IDs break ties deterministically;
actual signed-record IDs can order exact ties differently. **Hybrid is not
uniformly better:** it helps on SciFact and hurts on the paraphrase-heavy memory
fixture. The CLI exposes `--semantic-only` and `--lexical-only`; default text
search retains the system's hybrid policy. Weight changes require broader real
memory evaluation, rather than tuning against these 32 queries.

The benchmark preserves each downloaded artifact's native truncation. Inspection
found that this Qdrant MiniLM tokenizer sets `max_length=128`, despite the
upstream model's commonly documented 256-token setting. The report uses the
effective value, not the initial candidate metadata's 256. SciFact abstracts
are truncated for this standard whole-document benchmark. Runtime memory
ingestion rejects oversized input instead, so these scores do not measure a
future chunk-and-aggregate pipeline.

## Bundling and operation

Model: [upstream MiniLM](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2).
Conversion: [Qdrant snapshot](https://huggingface.co/qdrant/all-MiniLM-L6-v2-onnx/tree/5f1b8cd78bc4fb444dd171e59b18f3a3af89a079).
Revision: `5f1b8cd78bc4fb444dd171e59b18f3a3af89a079`.

The weights are 90,387,630 bytes; all tested model/tokenizer artifacts total
91,334,522 bytes. Licenses and the profile add a small amount. Python and ONNX
runtime dependencies are additional disk/memory costs. The generated wheel
includes the model, tokenizer, notices and license; it does not include the
benchmark dataset or alternative model. Dependency installation still needs
packages or an offline wheelhouse; offline inference alone needs no connection.

The embedding namespace is a SHA-256 profile of model files, revision, pooling,
prefixes, normalization, dimensions and runtime versions. It uses 384 dimensions,
attention-mask mean pooling, L2 normalization, and no query/passage prefix.
FastEmbed 0.8.0, ONNX Runtime 1.29.0, and tokenizers 0.23.2 are pinned and checked
at load. Every listed asset is checksummed before loading. The encoder uses
CPUExecutionProvider, two threads, batch size one, and a specific local model
path. Runtime telemetry events are disabled before model construction.

```bash
.venv/bin/intertexum --data /tmp/notes init
.venv/bin/intertexum --data /tmp/notes write --text 'Restore the database from backups after disk failure.'
# Publish the returned private ID to make it eligible for shared search:
.venv/bin/intertexum --data /tmp/notes publish PRIVATE_ID --audience '*'
.venv/bin/intertexum --data /tmp/notes search --text 'Recover data after losing a drive'
```

The 128-token limit includes special tokens. Overlength input fails with a clear
split/shorten message; `mesh_write_document` provides bounded, atomic chunking. Encoding errors
never cause fallback to another model. Existing custom-vector nodes retain their
configured namespace and require explicit vectors. A future model change requires
a new namespace and re-embedding; equal dimension alone does not mean compatible
vectors. Remote record signatures do not prove that the origin actually used
the claimed embedding model; quarantine approval remains necessary.

## Reproduction and evidence

```bash
uv sync --locked --extra test
.venv/bin/python -m benchmarks.prepare
.venv/bin/python -m benchmarks.run minilm
.venv/bin/python -m benchmarks.run bge-small --memory-only
.venv/bin/python -m benchmarks.work
```

`prepare` downloads the committed revisions and verifies hashes from
`benchmarks/MODEL_SOURCES.json`; it does not select the latest model silently.
The exact SciFact archive SHA-256 is
`536e14446a0ba56ed1398ab1055f39fe852686ecad24a6306c80c490fa8e0165`.
The memory fixture SHA-256 is
`4f40811ad4ab948495804f0c30ebef02121393d35ec222ee3b4a90288a240cbd`.

Raw metrics and per-query rankings are generated under `benchmarks/results/`,
which is excluded from Git and distribution archives. Reproduce them with the
commands above; the measured selection summary remains in this document.

The BGE full run can be repeated with `benchmarks.run bge-small`; the runner does
not automatically stop on the memory threshold. In this session it was explicitly
interrupted once the observed process memory exceeded the budget. It is not
necessary to finish a disqualified configuration to reproduce the decision.

Dataset sources: [BEIR](https://github.com/beir-cellar/beir) and
[SciFact](https://github.com/allenai/scifact). Test on the weakest intended
CPU and on real, consented memory examples before promising a device-level SLO.
