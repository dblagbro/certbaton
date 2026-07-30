# ADR 0007: Increment 1 simulation control is narrowly authorized

- Status: Accepted for Increment 1 only
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

The authenticated named pipe proves which local process owns the server and
captures the connecting Windows identity. Its installed-service DACL currently
permits ordinary local users to perform the health exchange. That is not, by
itself, authorization to change configuration, handle credentials, or start a
real certificate operation.

Increment 1 adds a synthetic renewal simulator. It has no network adapter,
credential access, certificate key, ACME account, remote target, deployment
command, or production side effect. Even so, allowing every local process to
enqueue work would establish an unsafe precedent and permit resource abuse.

## Decision

Classify the Increment 1 IPC methods as follows:

| Method | Effect | Increment 1 authorization |
| --- | --- | --- |
| `health` | Read-only service metadata | Any identity admitted by the pipe DACL |
| `simulation.latest` | Read-only synthetic run/evidence | Any identity admitted by the pipe DACL |
| `simulation.start` | Enqueues bounded synthetic work | Current user on the current-user development pipe, or an elevated local administrator when hosted as the installed service |

The service makes this decision from the client token captured by the pipe
server. A caller-provided role, process name, executable path, or UI state is
never accepted as authorization.

Only one simulated job may be active, its stage count and evidence sizes are
bounded, and the idempotency key prevents retry duplication. Disconnecting or
closing the UI after an accepted request does not cancel service-owned work.
The same key and simulation plan returns the existing durable job, including
while that job is active. Replaying an older terminal key does not replace the
global latest-job view.

Cancellation and claim use a single atomic command boundary. Cancellation that
wins before claim creates no job. Once the service claims the command, it
finishes durable job creation even if the request deadline subsequently
expires. The Desktop retains the key after an ambiguous transport/deadline
failure and reuses it on retry.

An authorization failure returns a stable, sanitized error and performs no
database mutation.

## Production boundary

This decision authorizes **synthetic simulation only**. It does not authorize:

- target or connection configuration;
- secret enrollment or retrieval;
- ACME account or order creation;
- SSH/SFTP access;
- certificate upload, activation, reload, or rollback;
- schedule changes; or
- production renewal.

Those operations remain blocked until a later authorization ADR defines and
tests a durable CertBaton operator role, elevation/consent behavior, installer
group or SID lifecycle, revocation, audit evidence, and least-privilege method
matrix.

The likely direction is an installer-managed local operator group distinct
from ordinary Users and Administrators, but Increment 1 does not create or rely
on that group.

## Consequences

- A normal non-elevated user of an installed developer preview can read the
  synthetic timeline but cannot start a new run.
- An installed-service demonstration that needs to start a simulation requires
  an elevated Desktop or CLI process.
- The current-user console development profile remains test-only. Production
  clients continue authenticating the SCM-owned service rather than trusting
  an arbitrary console process.
- UI controls must display an authorization error honestly; they must not
  imply that real renewal authorization exists.
- A UI polling the global latest-job view must retain the accepted run ID and
  refuse to attribute a different caller's later run to it.
- Tests must prove denial happens before enqueue and that read-only requests
  remain available.
