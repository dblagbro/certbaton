# ADR 0003: Secret protection requires a service-identity spike

- Status: Proposed — blocking security spike
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

The installed service may need unattended access to ACME account keys,
certificate private keys, and remote credentials. The interactive user must be
able to configure a target without making secrets readable to every local user
or relying on an exportable application master password.

Windows data-protection choices behave differently across service identities,
upgrades, backup/restore, machine rejoining, and administrator access. Selecting
a convenience API without testing the complete lifecycle could make secrets
either overexposed or unrecoverable.

## Decision under evaluation

No production secret-persistence mechanism is accepted yet.

The primary spike evaluates DPAPI-NG protection descriptors through
`NCryptProtectSecret` and `NCryptUnprotectSecret`, bound to the final restricted
Windows Service identity or service SID. A fallback spike may evaluate a
dedicated virtual service account with user-scoped Windows data protection.

The following are prohibited as production fallbacks:

- plaintext secrets;
- reversible obfuscation;
- machine-scope DPAPI available to unrelated processes on the machine;
- a hard-coded or repository-stored application encryption key;
- secret values sent through ordinary logs, crash dumps, IPC status payloads,
  support bundles, or address-book imports; and
- silently decrypting and copying passwords stored by another application.

Imported address books may provide non-secret connection metadata only until a
separate, reviewed credential-transfer design exists.

## Spike acceptance criteria

The spike must use the intended installer-created service identity and prove:

1. an authorized setup flow can create or hand off a secret;
2. the service can decrypt it unattended after logoff and reboot;
3. an ordinary different local user cannot decrypt it;
4. an unprivileged process cannot change ACLs or replace the encrypted record;
5. service repair and in-place upgrade preserve access;
6. uninstall removes protected material according to an explicit user choice;
7. identity or machine changes fail clearly and provide a recovery path;
8. backup and restore behavior is documented and tested;
9. memory and diagnostic handling minimize secret duplication; and
10. the design supports deliberate credential rotation and revocation.

Tests must also document the limits of protection from a local administrator.
No Windows-local design should claim to defeat an administrator who controls the
machine.

## Consequences

- Real credentials may not be persisted while this ADR remains proposed.
- The installer identity and ACL design cannot be finalized independently from
  the vault design.
- A failed spike requires a new ADR, not an automatic downgrade to machine-wide
  or plaintext storage.
- Export, migration, recovery, and support workflows must be designed as part of
  the secret lifecycle rather than added after release.
