# Security

Intertexum 0.2.x is alpha software. Use isolated pilot deployments with explicit owner
policy. There is no completed independent security audit or production SLA.

## Reporting

If this repository has GitHub private vulnerability reporting enabled, use
**Security → Report a vulnerability**. Otherwise open an issue requesting a private
reporting channel without exploit details, private data, credentials, or affected
endpoint addresses. A maintainer should arrange private communication before
receiving sensitive material. No maintainer email or response-time promise is
implied by this document.

Include affected version, minimal reproduction, expected/observed authorization,
and the impact. Use synthetic data and disposable identities. Do not probe other
operators' nodes without authorization.

## Deployment boundary

Keep node directories and backups private; they contain plaintext signing keys and
content. TLS/DTLS protects transport, not an authorized recipient's computer.
Separate identities/directories for separate harness principals. Protect the local
MCP socket and filesystem; a process with owner filesystem access can change policy.

Use independently hosted seeds, authenticated relays, host/firewall protections,
and monitored storage/egress budgets. Configure operator retention and erasure
policies before enrolling real users. Consult docs/DEFENSE.md, docs/PRIVACY.md and
docs/CONNECTIVITY.md for specific controls and limits.
