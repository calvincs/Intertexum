import json
import math

import pytest

from agentmesh import embedding
from agentmesh.crypto import Invalid
from agentmesh.node import Node
from agentmesh.network import Client, Server


def test_offline_encoder_shape_similarity_and_no_truncation(monkeypatch):
    import requests
    import socket
    def forbidden(*args,**kwargs):
        raise AssertionError('encoder attempted network access')
    monkeypatch.setattr(requests.sessions.Session,'request',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden)
    encoder=embedding.default_encoder()
    query=encoder.query('How do we recover the database after losing a disk?')
    good=encoder.passage('Restore the database from the most recent backup when a storage drive fails.')
    bad=encoder.passage('The cafeteria serves sandwiches and soup for lunch.')
    assert len(query)==len(good)==384
    assert all(math.isfinite(x) for x in query)
    assert sum(x*x for x in query)==pytest.approx(1,abs=1e-5)
    assert sum(a*b for a,b in zip(query,good))>sum(a*b for a,b in zip(query,bad))+.15
    with pytest.raises(Invalid,match='split the memory'):
        encoder.passage('database '*200)


def test_default_profile_end_to_end_text_search(tmp_path):
    a,b=(Node.create(tmp_path/name) for name in ('alice','bob'))
    assert a.model==b.model==embedding.profile()['id']
    try:
        with Server(a) as server:
            a.trust(b.card(port=7443),['read','publish','message'])
            b.trust(a.card(port=server.server_address[1]),['read','publish','message'])
            thread=server.start()
            try:
                rid=a.publish(a.write_text('Restore the database from backups when storage drives fail.'),audience=['*'])
                a.publish(a.write_text('The cafeteria serves sandwiches for lunch.'),audience=['*'])
                query='Recover data after a disk failure'
                result=Client(b,a.id).search(query_text=query,query_vector=embedding.encode_for(b,query,query=True))
                assert result['results'][0]['record']['id']==rid
                Client(b,a.id).fetch(rid)
                b.approve(rid)
                assert b.search_text(query)['results'][0]['record']['id']==rid
            finally:
                server.shutdown();thread.join()
    finally:
        a.close();b.close()


def test_asset_corruption_fails_before_loading(tmp_path,monkeypatch):
    (tmp_path/'profile.json').write_bytes((embedding.ASSETS/'profile.json').read_bytes())
    (tmp_path/'README.md').write_text('tampered model asset')
    monkeypatch.setattr(embedding,'ASSETS',tmp_path)
    with pytest.raises(Invalid,match='checksum mismatch'):
        embedding.Encoder()


def test_custom_profile_does_not_silently_use_default(tmp_path):
    node=Node.create(tmp_path/'custom',model='custom-space',dimensions=384)
    try:
        with pytest.raises(Invalid,match='explicit vector'):
            node.write_text('A note for another embedding space')
    finally:
        node.close()
