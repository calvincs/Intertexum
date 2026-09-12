"""Owner-only source selection and documentation-provider policy.

Identities are signing-key IDs, not endpoints. Missing lists are unrestricted;
empty lists deny every foreign identity. Policy is re-read at each boundary.
"""
from .crypto import Denied, Invalid, decode, valid_id

DEFAULTS = {'version': 1, 'mode': 'standard', 'sources': None, 'authors': None, 'senders': None}
PROVIDER_DISABLED = ('search', 'fetch', 'approve', 'send', 'receive', 'threads',
                     'cache', 'reshare', 'reward_relays')


def validate(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise Invalid('unknown source policy field')
    c = {**DEFAULTS, **value}
    if type(c['version']) is not int or c['version'] != 1 or c['mode'] not in ('standard', 'provider'):
        raise Invalid('unsupported source policy version or mode')
    for name in ('sources', 'authors', 'senders'):
        items = c[name]
        if items is not None and (not isinstance(items, list) or len(items) > 256
                or any(not valid_id(p) for p in items) or len(set(items)) != len(items)):
            raise Invalid(name + ' must be null or up to 256 distinct node IDs')
    return c


def config(node):
    path = node.directory / 'source-policy.json'
    return validate(decode(path.read_bytes()) if path.exists() else {})


def configure(node, value):
    from .onboarding import private_write
    c = validate(value)
    private_write(node.directory / 'source-policy.json', c)
    return c


def schema(node):
    node.db.executescript('''
      CREATE TABLE IF NOT EXISTS record_sources(record TEXT,source TEXT,PRIMARY KEY(record,source));
      CREATE TRIGGER IF NOT EXISTS record_sources_delete AFTER DELETE ON records BEGIN
        DELETE FROM record_sources WHERE record=OLD.id;
      END;
    ''')


def allowed(node, kind, peer):
    if peer == node.id:
        return True
    c = config(node)
    return c['mode'] != 'provider' and (c[kind] is None or peer in c[kind])


def require(node, kind, peer):
    if not allowed(node, kind, peer):
        raise Denied('source_policy_denied:' + kind)


def record_allowed(node, obj):
    if not allowed(node, 'authors', obj['body']['origin']):
        return False
    if obj['body']['origin'] == node.id or config(node)['sources'] is None:
        return True
    # Old imports with no recorded supplier fail closed under a source list.
    return any(allowed(node, 'sources', r[0]) for r in node.db.execute(
        'SELECT source FROM record_sources WHERE record=?', (obj['id'],)))


def require_record(node, obj):
    if not record_allowed(node, obj):
        raise Denied('source_policy_denied:record')


def remember_source(node, obj, source):
    require(node, 'sources', source)
    require(node, 'authors', obj['body']['origin'])
    # Bound supplier metadata even when the owner has no source restriction.
    if node._row(obj['id']) is not None:
        node.db.execute('INSERT OR IGNORE INTO record_sources VALUES(?,?)', (obj['id'], source))
        node.db.execute('DELETE FROM record_sources WHERE record=? AND source NOT IN '
                        '(SELECT source FROM record_sources WHERE record=? ORDER BY source LIMIT 256)',
                        (obj['id'], obj['id']))
