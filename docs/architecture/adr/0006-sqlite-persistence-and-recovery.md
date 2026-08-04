# ADR 0006: Service-owned SQLite persistence and deterministic recovery

- Status: Accepted for pre-alpha local persistence; production recovery gate open
- Date: 2026-07-29
- Updated: 2026-07-31
- Decision owners: CertBaton maintainers

## Context

The Windows Service must own schedules, run state, and evidence after the
Desktop application closes. A process or machine interruption must never turn
an uncertain operation into a reported success. The store is local operational
state, not a secret vault and not an administrator-resistant audit ledger.

Increment 1 needed a small, testable persistence layer for simulated renewal
jobs. The live pre-alpha slice now also needs targets, connection pins,
deployment plans, renewal policy, ACME account metadata, operations,
write-ahead remote intents, certificate metadata, and sanitized evidence.
Secret values remain prohibited from this database; records refer to secrets
in the ADR 0003 vault by opaque identifier.

## Decision

Use direct, parameterized ADO.NET through `Microsoft.Data.Sqlite.Core`. Do not
add an ORM in Increment 1.

Pin the managed provider, SQLitePCLRaw provider, and native SQLite library
centrally and lock the complete restore graph. The application must initialize
the selected native provider explicitly and verify `sqlite_version()` at
startup and in tests. The accepted native SQLite floor is 3.51.3; the initial
pin is 3.53.3.

Use the following database settings:

- `journal_mode=DELETE`;
- `synchronous=EXTRA`;
- `foreign_keys=ON`;
- `trusted_schema=OFF`;
- a finite busy timeout; and
- a database on local NTFS storage only.

SQLite's ADO.NET asynchronous methods still perform synchronous I/O. Database
mutations therefore run through one service-owned serialized worker, use short
transactions, and never execute on the Desktop UI thread. Desktop and CLI
processes receive projections over authenticated IPC and never open the
database.

WAL mode is intentionally rejected for Increment 1. CertBaton has one writer,
so its extra reader/writer concurrency is not currently valuable. Avoiding WAL
also avoids checkpoint, `-wal`, `-shm`, backup-coordination, and recovery
complexity. SQLite documents a WAL-reset corruption race affecting versions
through 3.51.2; although the selected native library is patched, WAL may be
adopted only under a later ADR after measured contention and dedicated
concurrent checkpoint/crash tests.

Sources:

- [Microsoft.Data.Sqlite async limitations](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/async)
- [Microsoft.Data.Sqlite transactions](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/transactions)
- [Microsoft.Data.Sqlite database errors](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/database-errors)
- [SQLite synchronous modes](https://sqlite.org/pragma.html#pragma_synchronous)
- [SQLite WAL and the WAL-reset bug](https://sqlite.org/wal.html#the_wal_reset_bug)

## Storage boundary

The MSI must create `%ProgramData%\CertBaton\State` and a separate backup
directory with protected inheritance. The intended access boundary is:

- owner: `SYSTEM`;
- `SYSTEM`: Full Control;
- `BUILTIN\Administrators`: Full Control;
- exact `NT SERVICE\CertBaton` SID: Modify without `WRITE_DAC` or
  `WRITE_OWNER`; and
- no access rule for ordinary Users or Authenticated Users.

The installed service must verify this boundary at startup and fail closed on
material ACL drift. It must not silently repair permissions; MSI repair is the
administrative recovery path. Increment 1 currently checks only that the
installed state directory already exists and that its final path is not a
reparse point. Owner/DACL and ancestor reparse-point validation remain
unimplemented release gates. Development mode uses an explicitly separate,
current-user directory and never falls back to the production location.

The installed-service ACL remains a release gate until it passes clean-machine
tests under the real virtual service identity. Windows service SID background:
[SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).

## Schema and migration rules

Use forward-only embedded SQL migrations with:

- a fixed SQLite `application_id`;
- `STRICT` tables;
- UUIDv7 job identifiers serialized in canonical text form;
- UTC timestamps stored as Unix milliseconds;
- explicit `CHECK` and foreign-key constraints;
- monotonically increasing schema versions;
- migration names and SHA-256 checksums; and
- parameterized values only.

Schema version 1 contains the synthetic job and evidence foundation. Version 2
adds the production domain foundation, and version 3 adds live orchestration,
including target issuance metadata, raw exact SSH host-key pins, enrollments,
ACME account records, write-ahead intents, and certificate artifacts. The
migrations are forward-only and checksum-validated. Future migrations may add
alerts, richer checkpoints, and retention metadata. A failed migration never
causes the database to be silently recreated.

Before a future production schema migration, the service must verify the store
identity and supported schema range, make a secured backup through SQLite's
backup API, validate that backup, and apply the migration and its history row
in one immediate transaction. Unknown future schemas and downgrades fail
closed. See [Microsoft.Data.Sqlite online backup](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/backup).

## Job and recovery semantics

Persist each state transition, its sanitized evidence, and the new checkpoint
in the same transaction.

- Job creation is idempotent through a unique request key.
- Increment 1 permits only one active simulation globally. Live operations use
  a target-scoped active-operation constraint and a stable request key so a
  retry observes the existing durable operation.
- A durable insertion sequence, not the wall clock, defines job recency.
- A service execution epoch identifies the process that owns an attempt and is
  required on every stage-evidence and completion write.
- Work owned by an older epoch is reconciled during startup recovery. A run
  that stopped before activation is closed as interrupted; a run with a
  planned, applied, or uncertain activation intent becomes
  `rollback-required` and is not replayed automatically.
- Simulated and other proven-idempotent work may be retried from a durable
  boundary.
- A remote mutating step with an uncertain outcome is never blindly replayed.
  The worker must reconcile observed state first or stop as blocked or
  rollback-required.
- Increment 1 request cancellation can withdraw an unclaimed start command. If
  service processing claims the command first, durable job creation completes
  and the caller reconciles by retrying the same idempotency key.
- Future cancellation of an accepted production job is a durable request
  honored only at safe stage boundaries.
- `succeeded` is legal only after final verification and cleanup evidence are
  durably committed.

This is at-least-once execution with operation-level idempotency and
reconciliation. CertBaton does not claim exactly-once remote effects.

For the Increment 1 simulator, an incomplete running job found at startup is
marked `interrupted` with recovery evidence. For the live slice, queued work
can be claimed by the new Service epoch, but incomplete remote-mutating work is
classified from durable intents as described above. Local fake-workflow and
persistence tests cover these state rules; process-kill testing through every
real SSH/ACME boundary is still required.

The pre-alpha scheduler scans due targets once per minute. A newly enrolled
target with automatic renewal enabled is due immediately. On success it uses
the certificate expiry and configured renewal window; on failure it uses the
configured check interval. Production-grade jitter, exponential backoff,
rate-limit-aware retry, global workload policy, and unattended alerts remain
open work.

## Retention direction

Until the complete retention migration exists:

- active, blocked, degraded, interrupted, and rollback-required work is never
  automatically deleted;
- terminal summaries and verification/failure evidence target 400 days and at
  least the latest ten jobs per target;
- routine detailed stage evidence targets 90 days;
- the latest three verified migration backups are retained, with a 30-day
  minimum for older backups; and
- no automatic `VACUUM` or secure-erasure claim is made.

Retention is not implemented by Increment 1 and must not be presented as an
available setting.

## Alternatives considered

### EF Core SQLite

Rejected for Increment 1. It adds change tracking and migration machinery that
the small recovery-focused schema does not need. SQLite provider limitations
also include table rebuild cases and migration-lock recovery concerns:
[EF Core SQLite limitations](https://learn.microsoft.com/en-us/ef/core/providers/sqlite/limitations).

### Dapper

Deferred. It provides object mapping but does not decide migrations, state
transitions, recovery, or evidence integrity. A thin repository layer is
smaller at the present schema size.

### System.Data.SQLite

A viable fallback, but less aligned with the project's Microsoft .NET support
cadence and still requires an explicit native-library servicing decision.

### Direct sqlite3 interop

Rejected. It would make CertBaton own native loading and interop details that
the Microsoft provider already covers.

## Consequences and gates

- The persistence package and native SQLite versions become supply-chain
  dependencies covered by locked restore, NuGet audit, SBOM, license notices,
  and runtime-version tests.
- SQLite errors and synchronous stalls must be bounded and surfaced as
  sanitized health failures.
- File backup must keep the database and any active journal together or use
  SQLite's backup API; copying an open database file is not an accepted backup.
- Local administrators can inspect or tamper with local operational state.
  CertBaton does not claim local non-repudiation against an administrator.
- Production use remains blocked on real MSI-created directory ACL, migration,
  corruption, disk-full, locked-store, backup/restore, and process-kill tests,
  including interruption before and after each remote intent.
