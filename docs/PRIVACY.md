# Bootstrap metadata: privacy and legal considerations

Implementation update: signed de-registration with immediate discovery removal,
a cleanup countdown, and separately retained security summaries is documented in
[ERASURE.md](ERASURE.md). The key-based API covers seed registration; broader
rights requests, retention decisions and backup/recipient handling still require
an operator process.

Sharing only discovery metadata reduces content exposure, but does not make the
service anonymous or automatically low-risk legally. Operators and users may be in different jurisdictions. This is a planning
baseline, not a legal conclusion for a particular deployment.

The seed shares a signed node ID, certificate, advertised IP/port, network name
and announcement timestamps. Stable IDs permit correlation; residential IPs can
reveal a household's network and approximate location. Security auditing also
processes observed source IPs. We do not share queries, memory content, vectors,
private keys or ban lists through discovery. Searches do not traverse seeds.

**EU:** IP addresses and other online identifiers may be personal data. A
pseudonymous key hash does not necessarily anonymize an identifiable operator.
The GDPR requires an applicable lawful basis, transparency, purpose limitation,
data minimisation, proportionate retention/security and applicable rights.
Registration is a deliberate product action, but is not by itself proof of valid
GDPR consent. If legitimate interests is the basis, necessity and balancing must
be assessed. A seed operator may have controller responsibilities for the
processing it determines; decentralization does not automatically remove them.
See the [European Commission on GDPR scope and personal data](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en),
[processing grounds](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/legal-grounds-processing-data_en)
and [data-protection principles](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en).

A US operator can fall within GDPR scope when offering services (including free
services) to individuals in the EU or monitoring their behaviour there. Mere
worldwide technical accessibility is not itself the complete targeting test.
EU-established operators may have their own obligations. Assess each operator's
actual role and whether purposes/means are jointly determined; do not assume
every participant controls the entire mesh. Exchanges of covered personal data
from the EEA to US recipients also need a transfer assessment. Sources:
[EU territorial scope](https://commission.europa.eu/law/law-topic/data-protection/data-protection-explained_en),
[EDPB targeting guidance](https://www.edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_3_2018_territorial_scope_after_public_consultation_en_1.pdf),
[international transfers](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/rules-international-data-transfers_en).

**US:** applicable state privacy laws and business/scope thresholds matter. IP
addresses and other identifiers can be personal information; a metadata-only
service is not categorically exempt. An ordinary discovery disclosure is not
automatically a statutory sale or advertising-related “sharing”; the actual
arrangement and definitions matter. Privacy disclosures and promises must match
actual practice. See [California's CCPA overview](https://oag.ca.gov/privacy/ccpa)
and [privacy-policy guidance](https://oag.ca.gov/privacy/facts/online-privacy/privacy-policy).
This is not a complete survey of state, telecom, transfer or intermediary rules.

Before public operation, identify the operator, hosting/user locations and data
recipients; document the lawful purpose/basis; provide a clear notice before
advertising; and establish contact, access/removal and incident processes. Get
deployment-specific legal review once those facts are known. Collecting less
data helps but cannot establish that a deployment complies with all applicable
law or qualifies for a particular intermediary protection.

Current engineering measures: managed runtimes advertise after onboarding with
a network profile and owner network authorization; manual enrollment also supports
an explicit `join` action. IPv4 mDNS advertising and browsing default to enabled
for managed listeners on local interfaces, with identity, address, network and
short-lived signed membership metadata visible to nearby devices. Owner policy
`mdns:false`, network suspension and relay-only mode suppress mDNS. LAN
announcements expire after 120 seconds and renew while the runtime is active.
Seed announcements expire after 15 minutes by default. Active seed maintenance deletes expired directory entries
at least once per minute. Operators can forget entries and block re-registration
under the same ID. Audit is limited to 2,000 events/24 hours, excludes content and
queries, and remains local. Manual blocks persist until removed or their chosen
expiry; that separate retention purpose must be disclosed and reviewed.

Limits: signed seed deregistration and its cleanup countdown are implemented,
but there is no general automated subject-rights workflow or published deployment
operator privacy notice. Local deletion does not erase third-party copies, WAL or backups.
Running a private demonstration with controlled participants reduces exposure;
opening a publicly enumerable directory to residential machines changes the
assessment. Relays or otherwise limiting residential address exposure should be
considered before that deployment, without pretending they remove all metadata.

Public search/fetch results may be temporarily re-served by other nodes under
their cache policies. Relay-contribution observations (record ID, provider ID,
expiry) remain local for up to 24 hours and affect only local peer selection.
See [CACHING.md](CACHING.md); these records are separate from security evidence.

## Opt-in mesh routing

Forwarders store end-recipient-encrypted envelopes, not message plaintext. Routing
neighbors can learn admitted identities, adjacency, work prices and receipt
metadata. Each paid hop sees origin, recipient, message/envelope IDs, expiry, size
and hop history. This does not provide anonymity. The recipient encryption secret
is derived from its long-term identity; compromise can expose recorded ciphertext.
Origin and recipient message storage retain existing plaintext semantics. Custody
records, advertisements and receipts are local state and belong in private backups,
not published source. See [routing policy and limits](ROUTING.md).
