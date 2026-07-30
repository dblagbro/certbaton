# ADR 0006: Service-owned SQLite persistence and deterministic recovery

- Status: Accepted for Increment 1
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

The Windows Service must own schedules, run state, and evidence after the
Desktop application closes. A process or machine interruption must never turn
an uncertain operation into a reported success. The store is local operational
state, not a secret vault and not an administrator-resistant audit ledger.

Increment 1 needs a small, testable persistence layer for simulated renewal
jobs. Later increments will add targets, schedules, deployments, alerts, and
opaque references to secrets protected by the vault selected under ADR 0003.
Secret values are prohibited from this database.

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

Increment 1 implements the minimum durable job and evidence schema. Later
migrations may add targets, schedules, job attempts, operation intents, typed
step checkpoints, alerts, and retention metadata. A failed migration never
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
- Increment 1 permits only one active simulation globally; the production
  schema must enforce one applicable active job per target.
- A durable insertion sequence, not the wall clock, defines job recency.
- A service execution epoch identifies the process that owns an attempt and is
  required on every stage-evidence and completion write.
- Work owned by an older epoch is interrupted during startup recovery.
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
marked `interrupted` with recovery evidence. It is not promoted to success and
is not automatically replayed. A later increment may resume idempotent stages
after the durable step/intent model is implemented and tested.

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
  corruption, disk-full, locked-store, backup/restore, and process-kill tests.
