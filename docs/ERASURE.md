# Seed de-registration and retention

Nodes can request removal from each configured seed using their own signing key.
The request binds the node, target seed, network, timestamps and random nonce.
It is domain-separated from registration and remains valid for five minutes.
Another node cannot remove the subject by claiming its identity. The server
accepts key-possession proof even if the subject's transport certificate expired;
this grants no other permissions. Removal requires no registration PoW.

```bash
intertexum --data /path/to/node deregister \
  --seed /path/to/seed1.json --seed /path/to/seed2.json --network agentmesh-demo-v1
```

The result contains signed receipts and a per-seed failure list. Acknowledgement
from one seed never implies acceptance by other seeds. Each receipt is verified
against its pinned seed certificate and the outgoing request. The node can repeat
the command to obtain current status without moving an existing cleanup deadline.
Save the receipt to retain evidence of the seed's commitment. A receipt is not
proof that every disk or independent third-party copy was erased.

## Countdown and scope

Upon acceptance, the seed hides the entry from discovery **immediately** and
schedules removal of registration data and routine peer-linked audit entries
after **60 seconds**. This short delay coordinates persistent cleanup; it is
an engineering target, not a GDPR-prescribed waiting period. The live seed's
existing maintenance pass runs every 60 seconds, so cleanup normally occurs
between 60 and 120 seconds after acceptance. A stopped seed cannot execute jobs;
the persisted queue resumes when it runs again. Discovery remains suppressed
across restarts, even before overdue cleanup runs.

Cleanup removes the stored announcement (including certificate and advertised
endpoint) and routine audit entries linked to that peer. Security evidence and
active block rules are separate and remain. Source-IP events not attributable to
the requesting key cannot safely be assigned to that peer, especially behind NAT;
a broader human data-subject request needs operator review.

A minimal request/peer-ID record remains for 3,630 seconds after acceptance to
stop replay of previously signed, still-valid announcements. It contains no
certificate or endpoint. Registration is refused during this interval; a renewed
registration does not silently cancel the request. Maintenance then removes this
record once cleanup completed. By that point, old announcements and the original
five-minute removal request have expired. An unknown, unlisted identity receives
an immediate scoped receipt without allocating a tombstone, so unauthenticated
identity churn cannot create an unlimited removal queue. The queue caps at 10,000.

Requests have independent quotas (2/sec globally, burst eight; one per five seconds
per source, burst four). Connection blocks, source-IP bans and resource limits
still apply. They must not become the sole means of exercising legal rights:
operators need a reachable support route for blocked or key-lost users.

For a blocked node with its key, `deregister-request --seed CARD` produces signed
requests without connecting. Send the relevant object from its `requests` array
to the operator through the support route. The operator can apply that object
locally with `bootstrap-apply-removal REQUEST.json`. Generate it near processing
time: the five-minute replay window still applies. No external message is sent
by these commands. A formal support/identity-verification workflow remains an
operator responsibility; this key-based API does not cover every legal claimant.

## Security evidence

Useful security evidence is now separate from routine audit: subject kind,
verified peer ID or observed source IP, event category, first/last observation
and count. It excludes memory, query/message text, raw requests and certificates.
These are observations, **not a finding that a person acted maliciously**.

There is **no automatic expiry or eviction of recorded abuse summaries**.
De-registration cannot delete them or reset prior ban incidents. Repeated ban
incidents increase temporary bans from five minutes to ten minutes, twenty minutes,
and so on, capped at one day. Incident history persists across restarts and ban
expiry. Persistent manual blocks retain their existing policy.

At 10,000 evidence rows, new network admission stops rather than evicting existing
history. Operators can inspect `security-status` and export `security-evidence`.
Already-running requests may exhaust capacity; new distinct summaries at capacity
cannot be added. This is an explicit finite-storage limitation, not a promise to
capture every packet forever. Distributed attackers can force operator attention;
production operation needs monitoring and a capacity/retention plan.

A local `security-clear-evidence --kind peer --target ID --reason TEXT` supports
documented correction/retention review. No remote operation can invoke it. It
does not lift an active block. This deliberate escape hatch is necessary for
false positives, reassigned IPs, and lawful erasure/retention decisions; automatic
“abuse” classification cannot make records permanently unreviewable.

Routine audit still uses its 24-hour/2,000-event limit when no request is received.
Expired endpoint announcements still leave the live directory. Useful security
summaries persist; ordinary metadata is not retained merely because it might
prove useful someday. No-request does not mean unlimited retention is lawful.

## Legal and deletion limits

Where GDPR applies, Article 17 requires erasure when its conditions apply,
without undue delay. Article 12 generally requires responding to a rights request
within one month; that is **not** permission to delay every deletion for a month.
Retention exceptions and security interests require an applicable, necessary and
proportionate justification. “Marked as abuse” is not a blanket permanent-retention
exception. Operators must assess and explain retained categories, basis and
review criteria; this implementation does not automatically send a legal refusal
or certify compliance. See [GDPR Articles 5, 12 and 17](https://eur-lex.europa.eu/eli/reg/2016/679/art_17/oj/eng)
and [EDPB rights-request guidance](https://www.edpb.europa.eu/sme/be-compliant/respect-individuals-rights_en).

Indefinite automatic retention is the configured anti-abuse behavior, **not a
claim that it is legally acceptable for every operator or record**. Review this
policy before public US/EU deployment, define retention reviews, and document
any lawful exceptions. The default is not a substitute for those decisions.

Deletion here is logical deletion from the seed's live SQLite tables. SQLite
WAL/free pages, backups, host logs, OS snapshots and copies at other peers are not
forensically erased by this API. Operators need backup expiry/restore handling
and any applicable recipient-notification process. Currently seeds do not gossip
requests to one another; the client contacts each selected seed separately.
Future referral gossip needs signed withdrawal propagation and restore-time
suppression before broader deletion claims can be made.
