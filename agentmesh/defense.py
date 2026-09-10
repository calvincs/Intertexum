"""Local listener defense: bounded quotas, persistent bans and bounded audit.

Source addresses come only from accepted sockets, never request payloads.
Authenticated abuse is attributed to peer IDs to avoid banning an entire NAT.
"""
from contextlib import contextmanager
import ipaddress
import json
import sqlite3
import sys
import threading
import time

from .crypto import Denied, Invalid, valid_id


class RateLimited(Denied):
    def __init__(self, message, retry_after):
        super().__init__(message)
        self.retry_after=retry_after


class Defense:
    def __init__(self, directory, *, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.buckets = {}
        self.failures = {}
        self.search_slot = threading.BoundedSemaphore(1)
        self.db = sqlite3.connect(directory/'defense.sqlite',check_same_thread=False,isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS blocks(kind TEXT, target TEXT, expires REAL, reason TEXT,
            PRIMARY KEY(kind,target));
          CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at REAL, event TEXT,
            source TEXT, peer TEXT, detail TEXT);
          CREATE TABLE IF NOT EXISTS evidence(kind TEXT, target TEXT, event TEXT,
            first_seen REAL, last_seen REAL, occurrences INTEGER,
            PRIMARY KEY(kind,target,event));
        ''')

    def close(self):
        self.db.close()

    def audit(self, event, *, source='', peer='', detail=''):
        with self.lock:
            now=self.clock()
            self.db.execute('INSERT INTO audit(at,event,source,peer,detail) VALUES(?,?,?,?,?)',
                            (now,event,source,peer,detail[:200]))
            self.db.execute('DELETE FROM audit WHERE at<? OR id <= (SELECT COALESCE(MAX(id),0)-2000 FROM audit)',(now-86400,))

    def events(self):
        with self.lock:
            self.db.execute('DELETE FROM audit WHERE at<?',(self.clock()-86400,))
            return [dict(r) for r in self.db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')]

    def erase_routine(self, peer):
        with self.lock:
            # Abuse evidence is segregated and is never touched by this path.
            self.db.execute('DELETE FROM audit WHERE peer=?',(peer,))

    def evidence(self):
        with self.lock:
            return [dict(r) for r in self.db.execute('SELECT * FROM evidence ORDER BY last_seen DESC')]

    def retention_status(self):
        with self.lock:
            count=self.db.execute('SELECT count(*) FROM evidence').fetchone()[0]
            return {'evidence_rows':count,'capacity':10000,'network_admission_stopped':count>=10000,
                    'automatic_evidence_expiry':False,'operator_retention_review_required':True}

    def remember(self, kind, target, event):
        with self.lock:
            old=self.db.execute('SELECT occurrences FROM evidence WHERE kind=? AND target=? AND event=?',
                                (kind,target,event)).fetchone()
            if old is None and self.db.execute('SELECT count(*) FROM evidence').fetchone()[0]>=10000:
                return # Admission fails closed at this bound; existing evidence is not evicted.
            now=self.clock()
            self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,1) ON CONFLICT(kind,target,event) '
                            'DO UPDATE SET last_seen=excluded.last_seen,occurrences=occurrences+1',
                            (kind,target,event,now,now))

    def clear_evidence(self, kind, target, reason):
        if not isinstance(reason,str) or not reason.strip() or len(reason)>200:
            raise Invalid('documented local retention-review reason required')
        with self.lock:
            self.db.execute('DELETE FROM evidence WHERE kind=? AND target=?',(kind,target))
            self.audit('retention_review',detail=reason)

    def block(self, kind, target, *, seconds=0, reason='operator'):
        if kind == 'peer':
            if not valid_id(target): raise Invalid('invalid peer ID')
        elif kind == 'cidr':
            try: target=str(ipaddress.ip_network(target,strict=False))
            except ValueError as exc: raise Invalid('invalid IP range') from exc
        else:
            raise Invalid('block kind must be peer or cidr')
        if type(seconds) not in (int,float) or not 0 <= seconds <= 31536000:
            raise Invalid('invalid ban duration')
        with self.lock:
            self.db.execute('DELETE FROM blocks WHERE expires>0 AND expires<=?',(self.clock(),))
            if self.db.execute('SELECT count(*) FROM blocks').fetchone()[0]>=1000:
                raise Denied('block table capacity reached')
            self.db.execute('INSERT OR REPLACE INTO blocks VALUES(?,?,?,?)',
                            (kind,target,self.clock()+seconds if seconds else 0,reason[:200]))
            self.audit('block',peer=target if kind=='peer' else '',detail=kind+':'+target)

    def unblock(self, kind, target):
        if kind=='cidr': target=str(ipaddress.ip_network(target,strict=False))
        with self.lock:
            self.db.execute('DELETE FROM blocks WHERE kind=? AND target=?',(kind,target))
            self.audit('unblock',detail=kind+':'+target)

    def rules(self):
        with self.lock:
            self.db.execute('DELETE FROM blocks WHERE expires>0 AND expires<=?',(self.clock(),))
            return [dict(r) for r in self.db.execute('SELECT * FROM blocks ORDER BY kind,target')]

    def blocked(self, *, source='', peer=''):
        addr=ipaddress.ip_address(source) if source else None
        return any((r['kind']=='peer' and r['target']==peer) or
                   (r['kind']=='cidr' and addr is not None and addr in ipaddress.ip_network(r['target']))
                   for r in self.rules())

    def consume(self, keys):
        """Atomic token consumption; failed requests do not consume other scopes."""
        now=self.clock()
        with self.lock:
            self.buckets={k:v for k,v in self.buckets.items() if now-v[1]<120}
            if len(self.buckets)+len(keys)>4096: return False
            updated={}
            for key,rate,burst in keys:
                tokens,last=self.buckets.get(key,(burst,now))
                tokens=min(burst,tokens+max(0,now-last)*rate)
                updated[key]=(tokens,now)
                if tokens<1:
                    self.buckets.update(updated)
                    return False
            self.buckets.update({k:(tokens-1,now) for k,(tokens,_) in updated.items()})
            return True

    def failure(self, source, *, peer='', event='invalid'):
        # Only pass peer after its signature/TLS identity was verified.
        key=('peer',peer) if peer else ('cidr',str(ipaddress.ip_network(source,strict=False)))
        with self.lock:
            self.remember(*key,event)
            now=self.clock()
            self.failures={k:v for k,v in self.failures.items() if now-v[1]<60}
            if key not in self.failures and len(self.failures)>=4096: return
            count,start=self.failures.get(key,(0,now))
            self.failures[key]=(count+1,start)
            if count==0: self.audit(event,source=source,peer=peer)
            if count+1==8:
                previous=self.db.execute("SELECT occurrences FROM evidence WHERE kind=? AND target=? AND event='auto_ban'",key).fetchone()
                duration=min(86400,300*2**min(previous[0] if previous else 0,9))
                self.remember(*key,'auto_ban')
                try: self.block(*key,seconds=duration,reason='automatic repeated '+event)
                except Denied: return
                self.audit('auto_ban',source=source,peer=peer,detail=event)
                if not peer:
                    # Fixed-format line, suitable for journald/Fail2Ban. No user text.
                    print('agentmesh abuse source='+str(ipaddress.ip_address(source)),file=sys.stderr,flush=True)

    def connection(self, source, role):
        if self.blocked(source=source): return False
        with self.lock:
            if self.db.execute('SELECT count(*) FROM evidence').fetchone()[0]>=10000: return False
        # A bootstrap sees many legitimate identities sharing one NAT. Retain
        # bounded admission without turning ordinary congestion into an IP ban.
        rate,burst=(10,16) if role=='bootstrap' else (4,20)
        allowed=self.consume([(role+':ip:'+source,rate,burst)])
        if not allowed and role!='bootstrap': self.failure(source,event='connection_rate')
        return allowed and self.consume([(role+':connections',40 if role=='bootstrap' else 20,40)])

    def operation(self, source, peer, op, role):
        if self.blocked(source=source,peer=peer): raise Denied('locally blocked')
        if role=='data':
            if op=='search':
                keys=[('search:global',4,16),('search:peer:'+peer,2,8),('search:ip:'+source,4,16)]
            else:
                keys=[('rpc:global',20,40),('rpc:peer:'+peer,10,30)]
        elif op=='connectivity':
            keys=[('signaling:global',10,32),('signaling:ip:'+source,8,24)]
        elif op=='deregister':
            keys=[('removal:global',2,8),('removal:ip:'+source,.2,4)]
        elif op in ('challenge','register'):
            keys=[('admission:'+op,1,8),('admission:'+op+':'+source,.1,4)]
        else:
            keys=[('discovery:global',5,20),('discovery:'+source,2,10)]
        if not self.consume(keys[1:]):
            # Unauthenticated registration's claimed peer must never be punished.
            if role=='data':self.failure(source,peer=peer,event='request_rate')
            raise RateLimited('rate limited; back off before retrying',max(1,max(1/rate for _,rate,_ in keys[1:])))
        if not self.consume(keys[:1]):
            raise RateLimited('global capacity limited; retry later',max(1,1/keys[0][1]))

    @contextmanager
    def search(self, source='', peer=''):
        if not self.search_slot.acquire(blocking=False):
            raise Denied('search capacity busy; retry later')
        started=time.thread_time()
        try: yield
        finally:
            # One token includes 50ms of CPU. Expensive admitted searches incur
            # debt, so staying under a request-count limit cannot sustain a flood.
            extra=min(20,max(0,(time.thread_time()-started)/.05-1))
            with self.lock:
                for key in ('search:global','search:peer:'+peer,'search:ip:'+source):
                    if key in self.buckets:
                        tokens,last=self.buckets[key]
                        self.buckets[key]=(tokens-extra,last)
            self.search_slot.release()
