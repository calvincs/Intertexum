"""Authenticated capability hints scoped to the requesting peer, never grants."""
import time

from . import __version__
from .crypto import Invalid, canonical
from .onboarding import policy

PROTOCOL = 'agentmesh.peer-capabilities.v1'
FEATURES = ['memory-v1', 'message-v1', 'message-v2', 'threads-v1',
            'peer-view-v1', 'peer-capabilities-v1', 'message-work-v1', 'reply-permit-v1', 'message-v3',
            'peer-paths-v1', 'routed-message-v1', 'route-advertisement-v1']


def describe(node, requester):
    node.capability('network')
    permissions = node.peer(requester)['permissions']
    caps = policy(node)
    from .source_policy import allowed
    caps['receive'] = caps['receive'] and allowed(node, 'senders', requester)
    can_read = bool({'read', 'public'} & set(permissions))
    return {
        'protocol': PROTOCOL,
        'peer': node.id,
        'requester': requester,
        'version': __version__,
        'model': node.model,
        'dimensions': node.dimensions,
        'features': FEATURES[:],
        'permissions': permissions,
        'operations': {
            'search': caps['serve_memory'] and can_read,
            'get': caps['serve_memory'] and can_read,
            'message': caps['receive'] and 'message' in permissions,
            'public_thread_read': caps['threads'] and can_read,
            'public_thread_post': caps['threads'] and caps['receive'] and can_read,
            'private_thread_read': caps['threads'] and 'read' in permissions,
            'private_thread_post': caps['threads'] and caps['receive']
                and {'read', 'message'} <= set(permissions),
        },
        'private_thread_membership_required': True,
        'checked_at_ms': int(time.time() * 1000),
    }


def checked(result, node, peer):
    """Reject malformed hints and preserve the remote/local permission distinction."""
    fields = {'protocol', 'peer', 'requester', 'version', 'model', 'dimensions',
              'features', 'permissions', 'operations',
              'private_thread_membership_required', 'checked_at_ms'}
    operations = {'search', 'get', 'message', 'public_thread_read',
                  'public_thread_post', 'private_thread_read', 'private_thread_post'}
    if (not isinstance(result, dict) or set(result) != fields
            or len(canonical(result)) > 16384
            or result['protocol'] != PROTOCOL or result['peer'] != peer
            or result['requester'] != node.id):
        raise Invalid('invalid peer capability identity or schema')
    if (not isinstance(result['version'], str) or len(result['version']) > 80
            or not isinstance(result['model'], str) or not 1 <= len(result['model']) <= 200
            or type(result['dimensions']) is not int or not 1 <= result['dimensions'] <= 4096
            or type(result['checked_at_ms']) is not int or result['checked_at_ms'] < 0
            or result['private_thread_membership_required'] is not True):
        raise Invalid('invalid peer capability metadata')
    if (not isinstance(result['features'], list) or len(result['features']) > 32
            or any(not isinstance(x, str) or not 1 <= len(x) <= 80 for x in result['features'])
            or not isinstance(result['permissions'], list) or len(result['permissions']) > 4
            or any(x not in ('read', 'publish', 'message', 'public') for x in result['permissions'])
            or not isinstance(result['operations'], dict) or set(result['operations']) != operations
            or any(type(x) is not bool for x in result['operations'].values())):
        raise Invalid('invalid peer capability bounds')
    return {**result, 'supported': True, 'untrusted_data': True,
            'model_compatible': (result['model'], result['dimensions']) == (node.model, node.dimensions),
            'authorization_scope': 'Remote grants to this node at check time. '
                'Record audiences, thread membership, expiry and live policy still apply.'}
