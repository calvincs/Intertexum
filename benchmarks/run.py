"""CPU-only benchmark. One isolated candidate process per run."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import time
from collections import Counter

# Prevent secondary BLAS/tokenizer pools from inflating the two-thread budget.
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["HF_HUB_OFFLINE"] = "1"

import numpy as np
import onnxruntime as ort
from fastembed import TextEmbedding
from agentmesh.records import terms

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "benchmarks" / "assets"


def datasets():
    memory = json.loads((ROOT / "benchmarks/memory.json").read_text())
    source = ASSETS / "scifact"
    docs = [json.loads(line) for line in (source / "corpus.jsonl").read_text().splitlines()]
    queries = {q["_id"]: q for q in map(json.loads, (source / "queries.jsonl").read_text().splitlines())}
    relevant = {}
    with (source / "qrels/test.tsv").open() as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if int(row["score"]) > 0:
                relevant.setdefault(row["query-id"], []).append(row["corpus-id"])
    sci = {"documents": [{"id": d["_id"], "text": d["title"] + "\n" + d["text"]} for d in docs],
           "queries": [{"id": qid, "text": queries[qid]["text"], "relevant": rel} for qid, rel in sorted(relevant.items())]}
    return {"memory": memory, "scifact": sci}


def lexical_matrix(docs, queries):
    bags = [Counter(terms(d["text"])) for d in docs]
    lengths = np.array([sum(b.values()) for b in bags])
    avg = float(np.mean(lengths)) or 1
    matrix = np.zeros((len(queries), len(docs)), dtype=np.float32)
    for i, q in enumerate(queries):
        for term in set(terms(q["text"])):
            tf = np.array([b.get(term, 0) for b in bags])
            df = int(np.count_nonzero(tf))
            idf = math.log(1 + (len(docs) - df + .5) / (df + .5))
            matrix[i] += idf * tf * 2.2 / (tf + 1.2 * (.25 + .75 * lengths / avg))
    return matrix


def evaluate(scores, docs, queries):
    rows = []
    for score, q in zip(scores, queries):
        order = np.argsort(-score, kind="stable")
        found = [docs[int(i)]["id"] for i in order[:10] if score[i] > -np.inf]
        rel = set(q["relevant"])
        rr = next((1/(i+1) for i, rid in enumerate(found) if rid in rel), 0)
        dcg = sum(1/math.log2(i+2) for i, rid in enumerate(found) if rid in rel)
        ideal = sum(1/math.log2(i+2) for i in range(min(len(rel),10)))
        rows.append({"query":q["id"], "top10":found, "recall5":len(rel & set(found[:5]))/len(rel),
                     "recall10":len(rel & set(found))/len(rel), "mrr10":rr, "ndcg10":dcg/ideal})
    return {"metrics": {k: statistics.mean(r[k] for r in rows) for k in ("recall5","recall10","mrr10","ndcg10")},
            "per_query":rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", choices=["bge-small", "minilm"])
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument('--memory-only', action='store_true', help='follow-up diagnostics, not a full benchmark')
    args = parser.parse_args()
    ort.disable_telemetry_events()
    manifest = json.loads((ASSETS / "manifest.json").read_text())
    cfg = manifest["candidates"][args.candidate]
    for filename, meta in cfg["files"].items():
        assert hashlib.sha256((ASSETS/args.candidate/filename).read_bytes()).hexdigest() == meta["sha256"]
    started = time.perf_counter()
    model = TextEmbedding(cfg["model"], threads=args.threads, providers=["CPUExecutionProvider"], cuda=False,
                          specific_model_path=str(ASSETS/args.candidate), local_files_only=True,
                          cache_dir=str(ASSETS/"unused-cache"))
    load_seconds = time.perf_counter()-started
    def query(texts):
        return list(model.embed([cfg["query_prefix"]+q for q in texts], batch_size=16))
    query(["warm up the local query encoder"])
    fixture = datasets()
    if args.memory_only:
        fixture = {'memory': fixture['memory']}
    result = {"candidate":args.candidate, "profile":cfg, "threads":args.threads,
              "hardware":platform.platform(), "python":platform.python_version(), "provider":"CPUExecutionProvider",
              "model_load_seconds":load_seconds, "artifact_bytes":sum(x["bytes"] for x in cfg["files"].values()),
              "effective_tokenizer_truncation":model.model.tokenizer.truncation,
              "memory_fixture_sha256":hashlib.sha256((ROOT/"benchmarks/memory.json").read_bytes()).hexdigest(),
              "dataset_sha256":manifest["dataset"]["sha256"], "datasets":{}}
    cpuinfo=Path('/proc/cpuinfo').read_text()
    result["cpu"]=next(line.split(':',1)[1].strip() for line in cpuinfo.splitlines() if line.startswith('model name'))
    # Query latency first, before corpus allocations; three repetitions of every memory query.
    timings=[]
    for _ in range(3):
        for q in fixture['memory']['queries']:
            t=time.perf_counter(); query([q['text']]); timings.append((time.perf_counter()-t)*1000)
    result['query_latency_ms']={"samples":len(timings),"p50":float(np.percentile(timings,50)),"p95":float(np.percentile(timings,95))}
    for name, data in fixture.items():
        docs=sorted(data['documents'],key=lambda d:d['id']); qs=data['queries']
        print(f"{args.candidate}: encoding {name}: {len(docs)} documents / {len(qs)} queries",flush=True)
        t=time.perf_counter(); blocks=[]
        for start in range(0,len(docs),256):
            blocks.extend(model.passage_embed([d['text'] for d in docs[start:start+256]],batch_size=16))
            if start and start%1024==0:
                print(f"{args.candidate}: {name} {start}/{len(docs)}",flush=True)
        elapsed=time.perf_counter()-t
        emb=np.array(blocks,dtype=np.float32); qemb=np.array(query([q['text'] for q in qs]),dtype=np.float32)
        emb/=np.linalg.norm(emb,axis=1,keepdims=True); qemb/=np.linalg.norm(qemb,axis=1,keepdims=True)
        dense=qemb@emb.T; bm25=lexical_matrix(docs,qs)
        fused=np.zeros_like(dense)
        for i in range(len(qs)):
            for scores, only_positive in ((dense[i],False),(bm25[i],True)):
                order=np.argsort(-scores,kind='stable')
                for position,idx in enumerate(order,1):
                    if only_positive and scores[idx]<=0: break
                    fused[i,idx]+=1/(60+position)
        lexical=np.where(bm25>0,bm25,-np.inf)
        result['datasets'][name]={"documents":len(docs),"queries":len(qs),"embedding_seconds":elapsed,
            "documents_per_second":len(docs)/elapsed,"dense":evaluate(dense,docs,qs),
            "bm25":evaluate(lexical,docs,qs),"hybrid":evaluate(fused,docs,qs)}
        print(name,{method:result['datasets'][name][method]['metrics'] for method in ('dense','bm25','hybrid')},flush=True)
    result['peak_process_rss_mib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
    target=ROOT/'benchmarks/results';target.mkdir(exist_ok=True)
    suffix = '-memory-only' if args.memory_only else ''
    outfile=target/f'{args.candidate}-{args.threads}threads{suffix}.json'
    outfile.write_text(json.dumps(result,indent=2)+'\n')
    print('Saved',outfile,'peak RSS',result['peak_process_rss_mib'],flush=True)


if __name__=='__main__': main()
