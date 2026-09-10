"""Apply the recorded selection rule, then bundle the selected local artifacts."""
import hashlib
import json
from pathlib import Path
import shutil

from agentmesh.crypto import canonical

ROOT=Path(__file__).resolve().parents[1]


def main():
    results=ROOT/'benchmarks/results'
    candidates=[]
    for name in ('bge-small','minilm'):
        disqualification=results/f'{name}-resource-limit.json'
        if disqualification.exists():
            evidence=json.loads(disqualification.read_text())
            assert evidence['observed_peak_rss_mib']>750
            continue
        result=json.loads((results/f'{name}-2threads.json').read_text())
        if result['artifact_bytes']>150*1024**2 or result['peak_process_rss_mib']>750:
            continue
        score=.6*result['datasets']['memory']['hybrid']['metrics']['ndcg10']+.4*result['datasets']['scifact']['hybrid']['metrics']['ndcg10']
        candidates.append((score,result))
    if not candidates:
        raise RuntimeError('no candidate meets the preregistered budget; do not bundle a winner')
    best=max(x[0] for x in candidates)
    _,chosen=min((x for x in candidates if best-x[0]<=.02),
                 key=lambda x:(x[1]['query_latency_ms']['p95'],x[1]['artifact_bytes']))
    name=chosen['candidate'];cfg=chosen['profile']
    assets=ROOT/'agentmesh/assets/embedding'
    if assets.exists():
        raise RuntimeError('bundled profile already exists; review migrations before replacement')
    assets.mkdir(parents=True)
    files={}
    for filename,meta in cfg['files'].items():
        data=(ROOT/'benchmarks/assets'/name/filename).read_bytes()
        assert hashlib.sha256(data).hexdigest()==meta['sha256']
        (assets/filename).write_bytes(data)
        files[filename]=meta['sha256']
    spec={'model':cfg['model'],'repo':cfg['repo'],'revision':cfg['revision'],
          'files':files,'dimensions':384,'max_tokens':chosen['effective_tokenizer_truncation']['max_length'],
          'query_prefix':cfg['query_prefix'],'passage_prefix':'','normalization':'l2',
          'pooling':'cls' if name=='bge-small' else 'attention-mask-mean',
          'fastembed':'0.8.0','onnxruntime':'1.29.0','tokenizers':'0.23.2',
          'long_input':'reject','precision':'Qdrant ONNX artifact as pinned by file hashes'}
    profile={'id':'mesh-embed-v1:'+hashlib.sha256(canonical(spec)).hexdigest(),'spec':spec}
    (assets/'profile.json').write_text(json.dumps(profile,indent=2)+'\n')
    shutil.copyfile(ROOT/'benchmarks/licenses/Apache-2.0.txt',assets/'LICENSE-APACHE-2.0.txt')
    if name=='bge-small':
        shutil.copyfile(ROOT/'benchmarks/licenses/BGE-MIT.txt',assets/'LICENSE-BGE-MIT.txt')
    (assets/'NOTICE.txt').write_text(f"Bundled embedding model: {cfg['model']}\n"
        f"ONNX conversion: {cfg['repo']} at {cfg['revision']}\n"
        'The Qdrant conversion model card declares Apache-2.0.\n'
        'Files are unmodified; original model card and license text accompany them.\n'
        'See docs/EMBEDDINGS.md and benchmarks/results for measured selection evidence.\n')
    (results/'selection.json').write_text(json.dumps({'selected':name,'profile':profile['id'],
        'rule':'benchmarks/PLAN.md','eligible_candidates':[x[1]['candidate'] for x in candidates]},indent=2)+'\n')
    print(json.dumps(profile,indent=2))


if __name__=='__main__': main()
