# Contributing to CertBaton

Thank you for helping make certificate operations safer for small web developers
and service providers. CertBaton is pre-alpha, so small, reviewable contributions
that strengthen a documented boundary are especially valuable.

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before starting

1. Read the [README](README.md), [roadmap](docs/roadmap.md),
   [P0 backlog](docs/backlog/p0.md), and
   [support matrix](docs/supported-matrix.md).
2. Search existing issues and pull requests.
3. For a new connector, protocol change, secret-handling change, or major user
   workflow, open a design issue before writing substantial code.
4. For a security concern, stop and use the private process in
   [SECURITY.md](SECURITY.md).

The repository does not accept production credentials, real private keys,
customer configuration, private host details, or unredacted diagnostic bundles
as test data.

## Development setup

The P0 development target is Windows 11 x64 with the .NET 10 SDK.

```powershell
git clone https://github.com/dblagbro/certbaton.git
Set-Location .\certbaton
dotnet restore .\CertBaton.slnx --locked-mode
dotnet build .\CertBaton.slnx --configuration Debug --no-restore
dotnet test .\CertBaton.slnx --configuration Debug --no-build --no-restore
```

## Contribution workflow

1. Create a focused branch from the current default branch.
2. Add or update tests for behavior changes.
3. Update documentation and an ADR when a durable architectural decision
   changes.
4. Run the build and test commands above.
5. Inspect the entire diff for secrets, generated files, machine-specific paths,
   and unrelated changes.
6. Open a pull request explaining the user problem, chosen boundary, validation,
   and recovery behavior.

Keep pull requests small enough to review threat boundaries. A refactor and a
security-sensitive behavior change should normally be separate changes.

## Code expectations

- Nullable reference types stay enabled.
- Prefer explicit domain types over loosely structured dictionaries.
- Pass `CancellationToken` through I/O and long-running work.
- Inject time and external I/O so failure and recovery can be tested.
- Bound input sizes and durations.
- Use structured events with centrally redacted fields.
- Do not log challenge contents, credentials, private-key material, or full
  command output that may contain them.
- Never accept an SSH host key automatically because a host name matches.
- Do not add arbitrary remote-command or in-process plug-in execution as a
  shortcut around a typed connector.
- Preserve an idempotent retry and rollback story for every remote mutation.

## Tests

Tests must be deterministic and default to local fixtures or synthetic data.
Network-dependent tests must be clearly separated, opt-in, bounded by timeouts,
and safe when interrupted.

ACME integration tests use a staging directory. Live-site tests require the
maintenance and recovery controls in
[ADR 0004](docs/architecture/adr/0004-live-test-restoration-boundary.md).
Pull requests should not require reviewers to provide real infrastructure.

## Architecture decisions

An ADR is expected when a change:

- establishes or changes a security boundary;
- selects a durable platform or dependency;
- changes on-disk state or IPC compatibility;
- changes how remote mutations or rollback work; or
- expands the supported-host promise.

Copy the structure of an existing file under `docs/architecture/adr/`. Record
context, decision, consequences, and status. Do not rewrite accepted history;
supersede it with a new ADR.

## Licensing

Unless explicitly stated otherwise, a contribution intentionally submitted to
this repository is provided under the
[Apache License, Version 2.0](LICENSE), consistent with section 5 of that
license. Confirm that you have the right to submit the work and retain required
third-party notices.
