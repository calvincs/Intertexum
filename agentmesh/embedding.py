"""Pinned, offline CPU encoder. The profile identifies the entire embedding space."""
from functools import lru_cache
import hashlib
import json
from importlib.metadata import version
from pathlib import Path

from .crypto import Invalid, canonical

ASSETS = Path(__file__).parent/'assets'/'embedding'


def profile():
    obj = json.loads((ASSETS/'profile.json').read_text())
    expected = 'mesh-embed-v1:'+hashlib.sha256(canonical(obj['spec'])).hexdigest()
    if obj['id'] != expected:
        raise Invalid('embedding profile checksum mismatch')
    return obj


class Encoder:
    def __init__(self, *, threads=2):
        if type(threads) is not int or not 1 <= threads <= 32:
            raise Invalid('encoder threads must be 1..32')
        self.profile = profile()
        spec = self.profile['spec']
        for package in ('fastembed','onnxruntime','tokenizers'):
            if version(package) != spec[package]:
                raise Invalid('embedding runtime version mismatch: '+package+'; install the locked dependencies')
        for filename, checksum in spec['files'].items():
            if Path(filename).name != filename:
                raise Invalid('invalid embedding asset filename')
            with (ASSETS/filename).open('rb') as f:
                actual = hashlib.file_digest(f,'sha256').hexdigest()
            if actual != checksum:
                raise Invalid('bundled model checksum mismatch: '+filename)
        import onnxruntime as ort
        ort.disable_telemetry_events()
        from fastembed import TextEmbedding
        from tokenizers import Tokenizer
        # Explicit local path bypasses FastEmbed's download manager entirely.
        self.model = TextEmbedding(spec['model'],threads=threads,cuda=False,
            providers=['CPUExecutionProvider'],specific_model_path=str(ASSETS),
            local_files_only=True)
        if self.model.model.tokenizer.truncation['max_length'] != spec['max_tokens']:
            raise Invalid('runtime tokenizer disagrees with pinned embedding profile')
        self.tokenizer = Tokenizer.from_file(str(ASSETS/'tokenizer.json'))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()

    def _encode(self, text, query):
        if not isinstance(text,str) or not text.strip() or len(text.encode('utf-8'))>32768:
            raise Invalid('embedding text must be nonempty and at most 32 KiB')
        spec = self.profile['spec']
        prepared = (spec['query_prefix'] if query else '')+text
        count = len(self.tokenizer.encode(prepared).ids)
        if count > spec['max_tokens']:
            raise Invalid(f"text requires {count} tokens; this profile accepts {spec['max_tokens']}; split the memory or shorten the query")
        output = next(iter(self.model.embed([prepared],batch_size=1)))
        return [float(x) for x in output]

    def passage(self, text):
        return self._encode(text,False)

    def query(self, text):
        return self._encode(text,True)


@lru_cache(maxsize=1)
def default_encoder():
    return Encoder()


def encode_for(node, text, *, query=False):
    configured = profile()
    if node.model != configured['id'] or node.dimensions != configured['spec']['dimensions']:
        raise Invalid('custom embedding profile requires an explicit vector')
    encoder = default_encoder()
    return encoder.query(text) if query else encoder.passage(text)


def write_document(node,content):
    """Bounded, atomic long-text ingestion; character ranges retain source context."""
    from .crypto import digest
    node.capability('write')
    if not isinstance(content,str) or not content.strip() or len(content.encode())>32768:raise Invalid('document must contain 1..32768 UTF-8 bytes')
    if node.model!=profile()['id']:raise Invalid('document chunking requires the bundled embedding profile')
    encoder=default_encoder();chunks=[];offset=0
    while offset<len(content):
        remaining=content[offset:]
        if not remaining.strip():break
        low,high=1,len(remaining);end=0
        while low<=high:
            mid=(low+high)//2
            if len(encoder.tokenizer.encode(remaining[:mid]).ids)<=128:end=mid;low=mid+1
            else:high=mid-1
        if not end:raise Invalid('cannot encode document character')
        passage=remaining[:end]
        if passage.strip():chunks.append((offset,offset+end,passage,encoder.passage(passage)))
        offset+=end
        if len(chunks)>64:raise Invalid('document exceeds 64 chunks; split the document')
    with node.transaction():
        results=[{'id':node.write_private(p,v),'start':start,'end':end} for start,end,p,v in chunks]
    return {'source_sha256':digest(content.encode()),'chunks':results,'state':'private','offset_unit':'Unicode characters','next_action':'inspect and publish selected chunks with an explicit audience'}
