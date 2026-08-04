# ADR 0003: Protect Service secrets with DPAPI-NG `LOCAL=user`

- Status: Accepted for pre-alpha implementation; production lifecycle gate open
- Date: 2026-07-29
- Updated: 2026-07-31
- Decision owners: CertBaton maintainers

## Context

The installed Service needs unattended access to ACME account keys,
certificate private keys, and remote credentials. An authorized interactive
administrator must be able to hand a credential to the Service without making
it readable to every local user or relying on an exportable application master
password.

Windows data-protection choices behave differently across service identities,
workgroup and domain machines, upgrades, backup/restore, machine rejoining, and
administrator access. A convenience API selected without the complete
lifecycle can make secrets either overexposed or unrecoverable.

The initial experiment attempted to bind a DPAPI-NG protection descriptor to a
SID. That descriptor failed on the workgroup development machine with Windows
error `0x80090034`. Falling back to machine-scope DPAPI would make encrypted
records available to unrelated machine processes and is prohibited.

## Decision

For the pre-alpha standalone Windows client, protect each secret with DPAPI-NG
using the `LOCAL=user` protection descriptor while the process runs as the
dedicated `NT SERVICE\CertBaton` virtual Service account. Store only the
protected record in the Service-owned `%ProgramData%\CertBaton\Secrets`
directory. The installer grants access to SYSTEM, administrators, and the exact
Service SID; ordinary users receive no access.

SQLite and IPC status projections contain opaque GUID references, never the
stored value. The current authorized handoff is intentionally narrow:

1. an elevated administrator runs `certbatonctl credential import-ssh-key`;
2. the CLI reads a bounded OpenSSH or PKCS #8 private-key file;
3. the authenticated named-pipe request carries the key bytes in its dedicated
   credential-import payload;
4. the Service validates the key envelope, protects it, writes the protected
   record through a write-through temporary file and atomic replacement, and
   returns a new opaque reference; and
5. both ends zero the bounded request byte arrays after use where the managed
   runtime makes that possible.

The import does not delete, rewrite, or protect the operator's source file.
Interactive passphrase handling and password import are not implemented.
General target, status, log, diagnostic, and database contracts cannot carry a
reusable secret.

The Service exposes an authorized `vault probe` operation. It writes, reads,
compares, and removes a temporary record as the actual Service identity. The
developer-package audit requires this round trip and verifies that no probe
record remains.

The following remain prohibited:

- plaintext records;
- reversible obfuscation;
- machine-scope DPAPI available to unrelated processes on the machine;
- a hard-coded or repository-stored application encryption key;
- secret values in ordinary logs, crash output, status payloads, support
  bundles, target-enrollment JSON, process arguments, or address-book imports;
  and
- silently decrypting and copying passwords stored by another application.

## Scope of acceptance

This decision accepts the implementation direction for pre-alpha development.
It does not approve production secret custody. Focused tests cover a
current-identity DPAPI-NG round trip, invalid protected-blob rejection,
non-plaintext records, explicit replacement/deletion, and CLI request-buffer
zeroing. The vault code rejects reparse points, and the developer-package audit
is designed to exercise a vault round trip as the installed Service. Cross-user
denial and hostile filesystem behavior remain part of the open gate below.

Before any production or public-beta claim, the exact packaged identity must
also prove:

1. unattended decrypt after user logoff and machine reboot;
2. denial to a different ordinary local user;
3. resistance to unprivileged record, directory-ACL, and reparse-point
   substitution;
4. access preservation across Service repair and every supported upgrade;
5. explicit retain/delete behavior during uninstall;
6. clear failure and documented recovery after identity or machine changes;
7. protected backup and restore behavior;
8. deliberate credential rotation and independent revocation;
9. canary-secret absence from logs, errors, IPC status, diagnostics, dumps, and
   installer output; and
10. documented limits of managed-memory zeroing and local-administrator access.

No Windows-local design claims to defeat an administrator who controls the
machine. DPAPI-NG availability and behavior must be qualified for every
supported Windows edition and Service configuration.

## Consequences

- A failed installed lifecycle test blocks release; it does not authorize a
  downgrade to machine-wide DPAPI or plaintext storage.
- The Service identity, profile, filesystem ACLs, repair, upgrade, backup,
  recovery, and uninstall design are part of one security boundary.
- Removing `%ProgramData%\CertBaton` is logical deletion, not a guarantee that
  storage media or backups have been securely erased.
- Address-book import remains limited to reviewed non-secret metadata. A
  future credential-transfer mechanism requires its own design review.
- Credential export is not part of the pre-alpha design. Losing the Service
  identity or machine may make protected records unrecoverable unless the
  separately designed backup mechanism succeeds.
