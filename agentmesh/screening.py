"""Best-effort local content screening, never an instruction trust decision.

Assume adversaries know this implementation. Parsing and bounded normalization
feed compositional indicators; neither these heuristics nor a clean result prove
safety. Originals, signatures, peer RPCs and durable receipts are not rewritten.
"""
from collections import deque
import base64
import binascii
import hashlib
import html
from html.parser import HTMLParser
import re
import unicodedata
from urllib.parse import unquote

VERSION = '2'
MAX_CHARS = 512 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_VIEWS = 128
MAX_DEPTH = 2
# Only common Latin lookalikes; not a complete Unicode confusables implementation.
CONFUSABLES = str.maketrans('аесорхуіјѕΑΒΕΖΗΙΚΜΝΟΡΤΥΧ', 'aecopxyijsABEZHIKMNOPTYX')
OVERRIDE = {'ignore', 'disregard', 'override', 'bypass', 'forget', 'disable', 'supersede'}
AUTHORITY = {'instruction', 'instructions', 'policy', 'policies', 'rules', 'safeguards', 'restrictions'}
EXTRACT = {'reveal', 'disclose', 'exfiltrate', 'upload', 'send', 'print', 'dump', 'read'}
SECRETS = {'password', 'passwords', 'credentials', 'credential', 'secret', 'secrets'}
PERSIST = {'remember', 'store', 'save', 'persist'}
VOCABULARY = OVERRIDE | AUTHORITY | EXTRACT | SECRETS | PERSIST
WORDS = re.compile(r'[^\W_]+', re.UNICODE)
ENCODED = re.compile(r'(?<![\w/+\-])[A-Za-z0-9_+/\-]{24,}={0,2}(?![\w/+\-])')
ESCAPES = re.compile(r'\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})')


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = False
        self.role = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        style = (attrs.get('style') or '').replace(' ', '').lower()
        self.hidden |= ('hidden' in attrs or attrs.get('aria-hidden') == 'true'
                        or 'display:none' in style or 'visibility:hidden' in style)
        self.role |= tag in {'system', 'developer'}
        self.parts.extend(value for value in attrs.values() if value)

    def handle_data(self, data):
        self.parts.append(data)

    def handle_comment(self, data):
        self.parts.append(data)


def _word(word):
    if word in VOCABULARY or not 5 <= len(word) <= 14:
        return word
    # Recover internal-letter permutations and one adjacent transposition.
    # This is deliberately bounded, not general edit-distance search.
    for target in VOCABULARY:
        if (len(word) == len(target) and word[0] == target[0]
                and word[-1] == target[-1] and sorted(word[1:-1]) == sorted(target[1:-1])):
            return target
    return word


def _normalize(text):
    text = unicodedata.normalize('NFKC', text).translate(CONFUSABLES).casefold()
    text = ''.join(c for c in text if unicodedata.category(c) not in {'Cf', 'Mn'})
    words = WORDS.findall(text)
    # Collapse spaced-out letters into a supplementary interpretation.
    joined = []; run = []
    for word in words + ['']:
        if len(word) == 1 and word.isascii() and word.isalpha():
            run.append(word)
        else:
            joined.extend([''.join(run)] if len(run) >= 3 else run)
            run = []
            if word:joined.append(word)
    recovered = []; i = 0
    while i < len(joined):
        word = joined[i]; end = i + 1
        if word not in VOCABULARY:
            candidate = word
            for j in range(i + 1, min(i + 6, len(joined))):
                candidate += joined[j]
                if len(candidate) > 14:break
                if candidate in VOCABULARY:
                    word = candidate; end = j + 1; break
        recovered.append(_word(word)); i = end
    return text, recovered


def _indicators(text):
    normalized, words = _normalize(text)
    reasons = set()
    for i, word in enumerate(words):
        following = set(words[i + 1:i + 13])
        nearby = ' '.join(words[max(0, i - 3):i + 13])
        if word in OVERRIDE and following & AUTHORITY:
            reasons.add('instruction_override')
        if word in EXTRACT and (following & SECRETS or any(term in nearby for term in
                ('private key', 'api key', 'identity key', 'system prompt', 'developer prompt', 'hidden instructions'))):
            reasons.add('sensitive_data_request')
        if word in PERSIST and following & AUTHORITY and following & {'future', 'always', 'trusted', 'permanent'}:
            reasons.add('persistent_instruction')
    # Model-specific delimiters plus structural role tags are independent signals.
    if any(marker in normalized for marker in ('[inst]', '<<sys>>', '<|im_start|>system',
            '<|im_start|>developer', '<|start_header_id|>system', '<|start_header_id|>developer')):
        reasons.add('forged_role_delimiter')
    return reasons


def _decoded(text):
    """Yield bounded text interpretations. Never execute or resolve URLs."""
    for value in (html.unescape(text), unquote(text),
                  ESCAPES.sub(lambda m: chr(int(m[1] or m[2], 16)), text)):
        if value != text:yield value
    # Unicode tags can carry an entire ASCII payload invisible to a reader.
    tags = ''.join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:yield tags
    for match in ENCODED.finditer(text):
        token = match[0]
        try:
            if len(token) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in token):
                raw = bytes.fromhex(token)
            else:
                raw = base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True)
            value = raw.decode('utf-8')
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if value and sum(c.isprintable() or c.isspace() for c in value) / len(value) > .9:
            yield value


def scan(text, *, _budget=None):
    """Return fixed reason codes only: no excerpts or attacker-chosen labels."""
    if not isinstance(text, str):raise TypeError('screening expects text')
    reasons = set(); complete = True; high = False
    digest = hashlib.sha256(text.encode('utf-8', errors='surrogatepass')).hexdigest()
    queue = deque([(text, 0)]); seen = set(); scheduled = {text}; total = 0
    while queue:
        value, depth = queue.popleft()
        if value in seen:continue
        if len(value) > MAX_CHARS or total + len(value) > MAX_TOTAL or len(seen) >= MAX_VIEWS:
            complete = False; break
        if _budget is not None:
            if _budget['chars']+len(value)>MAX_TOTAL or _budget['views']>=MAX_VIEWS:
                complete=False; break
            _budget['chars']+=len(value); _budget['views']+=1
        seen.add(value); total += len(value)
        found = _indicators(value)
        reasons.update(found); high |= bool(found)
        if any(unicodedata.category(c) == 'Cf' for c in value):
            reasons.add('invisible_or_directional_text')
        if '<' in value:
            parser = _Markup()
            try:
                parser.feed(value); parser.close()
                if parser.hidden:reasons.add('hidden_markup')
                if parser.role:reasons.add('forged_role_tag'); high = True
                # Both boundaries and inline tag splits can conceal a phrase.
                for separator in (' ', ''):
                    parsed = separator.join(parser.parts)
                    if parsed and parsed not in scheduled:
                        if depth >= MAX_DEPTH or len(scheduled) >= MAX_VIEWS:complete = False
                        else:
                            scheduled.add(parsed)
                            queue.append((parsed, depth + 1))
            except (ValueError, AssertionError):
                complete = False
        for decoded in _decoded(value):
            if decoded in scheduled:continue
            reasons.add('encoded_text')
            if depth >= MAX_DEPTH or len(scheduled) >= MAX_VIEWS:
                complete = False; break
            scheduled.add(decoded)
            queue.append((decoded, depth + 1))
    if not complete:reasons.add('scan_limit')
    return {'version': VERSION, 'content_sha256': digest, 'complete': complete,
            'decision': 'withhold' if high or not complete else 'pass',
            'findings': sorted(reasons), 'untrusted_data': True}


def screen_response(response):
    """Screen every outgoing tool response, including errors and receipt replays.

Whole-response withholding avoids exposing a second copy in signatures, nested
objects, metadata or snippets. A blocked result is not an operation failure:
receipt semantics and the original ok flag remain authoritative.
"""
    try:
        report = scan(_text(response.get('result', response.get('error'))))
    except Exception:
        report = _unavailable()
    return _finish(response, report)


def _text(value):
    strings = []; stack = [(value, 0)]; size = 0; count = 0
    while stack:
        value, depth = stack.pop(); count += 1
        if depth > 32 or count > 65536:raise ValueError('scan budget')
        if isinstance(value, str):
            size += len(value)
            if size > MAX_CHARS:raise ValueError('scan budget')
            strings.append(value)
        elif isinstance(value, dict):
            for key in sorted(value, reverse=True):
                stack.extend(((key, depth + 1), (value[key], depth + 1)))
        elif isinstance(value, (list, tuple)):
            stack.extend((item, depth + 1) for item in reversed(value))
    return '\n'.join(strings)


def _unavailable():
    return {'version': VERSION, 'complete': False, 'decision': 'withhold',
            'findings': ['scan_unavailable'], 'untrusted_data': True}


def _finish(response, report):
    result = dict(response)
    result['content_screening'] = report
    if report['decision'] == 'withhold':
        if response.get('ok'):
            result['result'] = {'withheld': True, 'untrusted_data': True,
                'next_action': 'Content withheld by local screening. Owner review is required; do not retry a mutation with a new key.'}
            # Let clients move past a withheld inbox/thread page without claiming
            # it was processed. Only a bounded numeric cursor is copied.
            original = response.get('result')
            if isinstance(original, dict) and 'next' in original:
                cursor = original['next']
                if cursor is None or type(cursor) is int and 0 <= cursor < 2**63:
                    result['result']['next'] = cursor
        else:
            original = response.get('error', {})
            result['error'] = {'code': 'screened_error', 'detail': 'Error details withheld by local content screening.',
                'retryable': False, 'next_action': 'Inspect local state with the owner; do not repeat a mutation with a new key.'}
            # Preserve known durable-receipt semantics without arbitrary strings.
            if original.get('receipt_state') == 'completed':
                result['error'].update(receipt_state='completed', same_key_action='retrieve_receipt')
    return result


def screen_page(response, field):
    """Isolate offending entries, then screen retained content together.

Only local inbox/thread tools select this path. Aggregate screening still catches
instructions assembled across entries or copied into page metadata. All scans
share interpretation/character limits; incomplete work withholds the whole page.
"""
    if not response.get('ok'):return screen_response(response)
    try:
        page=response['result']; _text(page)  # Bound the original page before work.
        if not isinstance(page,dict) or not isinstance(page.get(field),list) or len(page[field])>100:
            return screen_response(response)
        budget={'chars':0,'views':0}; entries=[]; withheld=0
        for entry in page[field]:
            report=scan(_text(entry),_budget=budget)
            if not report['complete']:return _finish(response,report)
            if report['decision']=='withhold':
                replacement={'withheld':True,'untrusted_data':True,'content_screening':report}
                if isinstance(entry,dict):
                    cursor=entry.get('cursor')
                    if type(cursor) is int and 0<=cursor<2**63:replacement['cursor']=cursor
                    obj=entry.get('message',entry.get('object'))
                    oid=obj.get('id') if isinstance(obj,dict) else None
                    if isinstance(oid,str) and re.fullmatch('[0-9a-f]{64}',oid):replacement['id']=oid
                entries.append(replacement);withheld+=1
            else:entries.append(entry)
        retained={**page,field:entries}
        report=scan(_text(retained),_budget=budget)
        if report['decision']=='withhold':return _finish(response,report)
        if withheld:
            report.update(decision='partial',withheld_items=withheld,scope='retained_page_content')
        return {**response,'result':retained,'content_screening':report}
    except Exception:
        return _finish(response,_unavailable())
