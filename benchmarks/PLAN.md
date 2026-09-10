# CPU embedding selection plan (written before model evaluation)

Compare BAAI/bge-small-en-v1.5 (Qdrant quantized ONNX, MIT) with
sentence-transformers/all-MiniLM-L6-v2 (Qdrant ONNX, Apache-2.0). Both are publicly
downloadable without accepting gated terms, produce 384-dimensional vectors,
and fit the proposed English default. This does not select a multilingual or
code-specialist model.

Use CPUExecutionProvider only, two inference threads, batch size 16, and
separate fresh processes per candidate. Record actual hardware, cold model-load
time (excluding download), warmed single-query p50/p95, document throughput,
process peak RSS, and local artifact size. Peak RSS includes runtime and
benchmark data, not just weights. This machine is not a low-end CPU; two threads
constrain parallelism but do not simulate an ARM board or old laptop.

Quality: the fixed, hand-authored Agent Mesh memory fixture plus the full BEIR
SciFact test split (5,183 abstracts / 300 queries). Store hashes before running.
The memory fixture is a small synthetic regression set, not an independent
production-quality benchmark. SciFact supplies external judged relevance and
scientific terminology but may overlap model training and is not agent memory.
Never change queries, labels, candidate settings, or data after seeing outcomes.

Compare dense-only, BM25-only, and independent-candidate RRF hybrid retrieval.
Report Recall@5/10, MRR@10, and nDCG@10, with per-query ranks saved for inspection.
Use BGE's documented retrieval query prefix; do not add it to passages. MiniLM
has no prefix. Keep each model's native truncation behavior and report it.

Proposed selection: first check a <=150 MiB artifact and <=750 MiB peak-process
RSS budget. Rank eligible models by 0.6*memory hybrid nDCG@10 + 0.4*SciFact hybrid
nDCG@10. If the difference is <=0.02, prefer lower warmed p95 query latency,
using disk size to break a latency tie. These are explicit engineering
preferences for this first build, not statistical significance thresholds.

After selection, ship the exact tested model profile, pin artifact revision and
checksums, retain license files, and validate offline encode/publish/search across
two nodes. Runtime must not silently download, truncate oversized memory, change
models, or mix embedding spaces under the same profile ID.

Artifact inspection correction (during BGE run, before MiniLM run): Qdrant's
MiniLM tokenizer config explicitly sets max_length=128, despite the upstream
model's common 256-token default. The native-behavior rule above means the
benchmark uses 128, and the shipped profile must record that effective limit.
The Qdrant BGE conversion's model card declares Apache-2.0; the upstream BGE
weights declare MIT. Include both notices if selecting that conversion.
