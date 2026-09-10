"""Download only public benchmark/model assets; pin bytes before evaluation."""
import hashlib
import json
from pathlib import Path
import zipfile

import requests

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "benchmarks" / "assets"
CANDIDATES = {
    "bge-small": {"model": "BAAI/bge-small-en-v1.5", "repo": "qdrant/bge-small-en-v1.5-onnx-q",
                  "onnx": "model_optimized.onnx", "max_tokens": 512, "license": "MIT",
                  "query_prefix": "Represent this sentence for searching relevant passages: "},
    "minilm": {"model": "sentence-transformers/all-MiniLM-L6-v2", "repo": "qdrant/all-MiniLM-L6-v2-onnx",
               "onnx": "model.onnx", "max_tokens": 256, "license": "Apache-2.0", "query_prefix": ""},
}
DATA_URL = "https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip"


def download(url, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        with requests.get(url, stream=True, timeout=90) as response:
            response.raise_for_status()
            part = target.with_suffix(target.suffix + ".part")
            with part.open("wb") as f:
                for block in response.iter_content(1024 * 1024):
                    f.write(block)
            part.replace(target)
    return {"sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "bytes": target.stat().st_size}


def main():
    ASSETS.mkdir(exist_ok=True)
    manifest_path = ASSETS / "manifest.json"
    committed = ROOT/'benchmarks/MODEL_SOURCES.json'
    old_path = committed if committed.exists() else manifest_path
    old = json.loads(old_path.read_text()) if old_path.exists() else {}
    manifest = {"candidates": {}, "dataset": {"url": DATA_URL}}
    for name, config in CANDIDATES.items():
        pinned = old.get('candidates',{}).get(name)
        if pinned:
            for filename, expected in pinned['files'].items():
                actual = download(f"https://huggingface.co/{pinned['repo']}/resolve/{pinned['revision']}/{filename}", ASSETS/name/filename)
                if actual != expected:
                    raise RuntimeError('pinned model artifact mismatch: '+name+'/'+filename)
            manifest['candidates'][name] = pinned
            continue
        api = requests.get(f"https://huggingface.co/api/models/{config['repo']}", timeout=30)
        api.raise_for_status()
        info = api.json()
        revision = old.get("candidates", {}).get(name, {}).get("revision", info["sha"])
        files = {s["rfilename"] for s in info["siblings"]}
        needed = {config["onnx"], "config.json", "tokenizer.json", "tokenizer_config.json",
                  "special_tokens_map.json"}
        needed.update(files & {"vocab.txt", "LICENSE", "LICENSE.txt", "README.md"})
        entry = {**config, "revision": revision, "files": {}}
        for filename in sorted(needed):
            if filename not in files:
                if filename in {config["onnx"], "config.json", "tokenizer.json", "tokenizer_config.json"}:
                    raise RuntimeError(f"missing required file: {filename}")
                continue
            print(f"Downloading {name}/{filename} at {revision}", flush=True)
            target = ASSETS / name / filename
            entry["files"][filename] = download(
                f"https://huggingface.co/{config['repo']}/resolve/{revision}/{filename}", target)
        manifest["candidates"][name] = entry
    print("Downloading BEIR SciFact", flush=True)
    archive = ASSETS / "scifact.zip"
    manifest["dataset"].update(download(DATA_URL, archive))
    if old.get('dataset') and manifest['dataset'] != old['dataset']:
        raise RuntimeError('pinned benchmark dataset mismatch')
    # Extract only named data files, never archive paths or scripts.
    with zipfile.ZipFile(archive) as z:
        for filename in ("corpus.jsonl", "queries.jsonl", "qrels/test.tsv"):
            dest = ASSETS / "scifact" / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read("scifact/" + filename))
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Pinned manifest:", manifest_path, flush=True)


if __name__ == "__main__":
    main()
