# ADR 0009: Use SSH.NET with exact pins and a fixed Nginx helper

- Status: Accepted for pre-alpha fixture; one staging qualification run passed
- Date: 2026-07-31
- Decision owners: CertBaton maintainers

## Context

The Windows Service needs SFTP for HTTP-01 and certificate upload, plus a very
small privileged operation surface for certificate validation, Nginx
activation, reload, verification, commit, and rollback. SFTP alone cannot
safely activate a certificate. Giving the remote account a general shell,
unrestricted passwordless sudo, root login, or container-engine membership
would turn a certificate tool into arbitrary remote administration.

SSH host identity is also a distinct trust decision. A fingerprint copied from
the connection being authenticated is vulnerable to first-use interception,
and a fingerprint alone can be mishandled across host aliases or algorithms.

## Decision

Use SSH.NET 2025.1.0 behind CertBaton-owned remote-session interfaces for the
pre-alpha implementation. Pin the dependency centrally and lock the restore
graph. Every unattended connection requires all of the following to match:

- normalized host;
- port;
- permitted host-key algorithm;
- canonical SHA-256 fingerprint; and
- exact raw SSH host-key blob.

The enrollment contract checks that the raw blob hashes to the supplied
fingerprint. The SSH.NET `HostKeyReceived` handler sets trust explicitly and
fails closed on any mismatch; CertBaton does not rely on the library event's
default trust value. There is no trust-on-first-use or automatic pin update.
Initial trust and rotation require an operator to compare key material obtained
through a separately trusted channel.

Use SFTP only for bounded files in typed, canonical POSIX locations. For
privileged Nginx work, invoke exactly:

```text
sudo -n -- /usr/local/libexec/certbaton/certbaton-helper-v1 <fixed-verb> <canonical-uuid>
```

Both trailing fields come from closed application types. No hostname, remote
path, DNS name, certificate value, or operator-authored text is concatenated
into the command. The helper executable and its configuration are installed
out of band by a remote administrator, owned by root, and not writable by the
SSH account. The sudo policy permits that exact executable only.

The helper configuration, not an IPC request, selects the permitted DNS name,
incoming and immutable release roots, bootstrap state, and bounded Nginx
test/reload operations. Directory ancestry must be root-owned, non-writable by
group or other, and free of symlink components. The incoming and release roots
cannot overlap. A dedicated non-root SSH account receives SFTP access only to
the prepared transaction directory and the configured challenge location.

The helper uses fixed verbs for `prepare`, `validate`, `activate`, `verify`,
`commit`, `rollback`, `abort`, and `status`. It freezes uploaded input before
copying it into an immutable generation, checks file type, ownership, size,
certificate/key pairing, DNS name, and validity, tests Nginx, atomically changes
the stable `current` symlink, and records write-ahead activation and rollback
states. Retrying the same transaction after an uncertain SSH response is
idempotent. Transitional state reports `recoveryRequired`; the client must
reconcile or roll back instead of assuming success.

Independent public TLS verification remains in the Windows client. A helper
success response is never sufficient to mark the renewal successful.

## Evidence present

- Remote-adapter tests cover algorithm policy, exact raw-key and fingerprint
  matching, wrong-key fail-closed behavior, bounded SFTP operations, fixed
  helper command construction, output parsing, and timeouts.
- Opt-in read-only tests have connected to an authorized fixture with the
  expected pin and rejected a wrong pin. These are development evidence, not a
  public support claim.
- The isolated Linux helper suite covers the happy path, idempotent retries,
  mismatch and unexpected-file rejection, interrupted activation and rollback,
  failed activation restoration, commit, abort, status, root overlap, and
  recovery reporting.
- On 2026-08-04, the installed Windows Service completed one manually
  authorized Let's Encrypt staging order through exact-pinned SSH/SFTP and the
  root-owned fixed helper on an isolated real Nginx Docker target. Public
  HTTP-01, activation, independent public TLS verification, cleanup, commit,
  durable evidence after Service restart, and restoration of the prior trusted
  runtime all passed.

The helper shim tests do not exercise hostile SFTP races. The single staging
qualification exercised a public ACME order, a real Nginx process, Docker bind
mounts, an actual sudoers rule, and public TLS, but it did not inject failures
or establish a supported matrix.

## Consequences and open gates

- CertBaton does not support arbitrary remote commands, user scripts, SCP,
  root login, general passwordless sudo, or direct Docker API access.
- SSH private-key authentication is the only implemented live credential kind;
  interactive passphrase prompting and password authentication are absent.
- Each supported OS, OpenSSH/SFTP implementation, filesystem, Nginx package,
  init system, and Docker layout needs its own qualification evidence.
- The helper does not yet fsync every directory transition, garbage-collect old
  committed generations, validate the public trust chain, or replace the
  client's public check.
- Real failure injection must cover connection loss before and after every
  helper verb, process termination, Nginx test/reload timeout, symlink and
  rename races, full disk, and rollback failure.
- Any future remote recipe or helper version requires a new closed operation
  contract and security review; it does not inherit Nginx support automatically.
