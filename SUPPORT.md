# Support

CertBaton is pre-alpha development software. There are no supported releases,
production guarantees, paid support plans, or emergency certificate-recovery
services.

## Where to ask

After the repository is published:

- use GitHub Discussions, when enabled, for design questions, hosting patterns,
  and contributor help;
- use a GitHub issue for a reproducible defect or a scoped feature proposal;
  and
- use the private process in [SECURITY.md](SECURITY.md) for anything that could
  expose a security weakness.

Before filing an issue, remove credentials, account identifiers, domain names
that should not be public, internal paths, IP addresses, user names, certificate
private keys, and host-key inventories. Prefer a small synthetic example.

## Useful issue details

- CertBaton commit or version
- Windows edition, version, and architecture
- remote server and web-server family, without private addressing
- expected and observed behavior
- minimal reproduction using synthetic data
- sanitized event IDs and error codes
- whether the operation changed remote state
- recovery steps already attempted

## Not a certificate emergency service

If a production certificate is expiring or a site is unavailable, use the
hosting provider's documented certificate or recovery process and a qualified
operator who has authorization and a verified rollback plan. Do not install a
pre-alpha CertBaton build as an emergency workaround.

The project cannot recover passwords, bypass hosting-provider controls, install
certificates on a platform that provides no supported access, or guarantee that
a third-party host permits Let's Encrypt issuance.
