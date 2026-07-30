# Security Policy

CertBaton is security-sensitive software. It is intended to handle certificate
private keys, ACME account credentials, remote-host trust, and deployment
operations. The project is also pre-alpha: no version is approved for production
use.

## Supported versions

| Version | Security support |
| --- | --- |
| Unreleased `main` branch | Best-effort development fixes; not production supported |
| Packaged releases | None published |

This table will be revised before the first supported release.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability and do not attach
credentials, private keys, host inventories, logs containing customer data, or
reproduction bundles with secrets.

Use GitHub's private vulnerability reporting feature on the repository's
**Security** tab when it is available. If that feature is not available, contact
the repository owner privately through a method published on the owner's GitHub
profile and ask for a secure reporting channel. Share sensitive evidence only
after that channel is established.

Include, when safe:

- the affected commit or version;
- the security boundary involved;
- steps to reproduce with synthetic data;
- expected and observed behavior;
- likely impact and prerequisites; and
- whether the issue may already be exploited.

The maintainers will attempt to acknowledge a complete report within five
business days, but the pre-alpha project does not offer a response-time or fix
SLA. Please coordinate disclosure timing with the maintainers.

## Security boundaries

Changes receive additional scrutiny when they affect:

- secret creation, storage, retrieval, redaction, or deletion;
- Windows service identity, privileges, installer ACLs, or elevation;
- named-pipe authentication, authorization, framing, or deserialization;
- ACME account keys, certificate private keys, or challenge tokens;
- SSH host-key validation or remote-path handling;
- upload, activation, rollback, or post-deployment verification;
- update signing, dependency provenance, or release packaging; and
- diagnostics, exports, backups, or crash reporting.

## Development rules

- Use only synthetic credentials and ACME staging accounts in development.
- Never persist a real secret until the secret-protection architecture gate is
  accepted.
- Treat connection strings, host inventories, certificate bundles, recovery
  archives, and test-site identifiers as sensitive even when they contain no
  password.
- Do not weaken TLS validation, SSH host-key checks, IPC authorization, or
  filesystem ACLs to make a test pass.
- Use parameterized connector operations and canonical remote paths. Do not
  concatenate untrusted text into a remote shell command.
- Redact logs at the point of creation, not only when exporting them.
- Add negative tests for malformed, oversized, unauthorized, replayed, and
  interrupted operations.

## Dependency and release policy

Dependencies must have a clear owner, license, update path, and security history.
Release artifacts will not be considered supported until automated build
provenance, malware scanning, secret scanning, dependency review, and Windows
code signing are in place and documented.
