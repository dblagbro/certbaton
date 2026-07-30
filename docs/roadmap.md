# CertBaton roadmap

This roadmap communicates sequence and exit criteria, not dates or a promise of
specific releases. Security and recovery gates may deliberately hold a feature
back.

## Phase 0: trustworthy foundation

Goal: prove the Windows process boundary and make the repository safe to
collaborate in.

- Establish the .NET 10 solution, deterministic build, tests, and Windows CI.
- Implement the bounded v1 named-pipe health exchange.
- Run the service in console development mode and as an installer-owned Windows
  Service fixture.
- Show service compatibility and health in the WPF shell and diagnostic CLI.
- Complete the service-identity and secret-protection spike.
- Define durable job states, local storage migration rules, and redacted event
  contracts.
- Add dependency, license, secret, and static-analysis controls.
- Establish reproducible development fixtures.

Exit criteria:

- IPC negative tests cover framing and unauthorized callers;
- install/service identity assumptions are demonstrated on Windows 11 x64;
- the accepted secret design supersedes the proposed spike ADR; and
- no real credential is required to build or test the repository.

## Phase 1: first safe certificate handoff

Goal: complete one narrowly qualified end-to-end renewal in an isolated fixture.

- Create and validate a target profile without saving a raw password.
- Review and pin the SSH host key.
- Complete ACME account, order, authorization, challenge, and finalize flows
  against a staging directory.
- Place and remove HTTP-01 challenge files through a typed SFTP connector.
- Stage certificate artifacts to a qualified Nginx layout.
- Validate remote preconditions, activate with a bounded operation, and verify
  the public TLS endpoint independently.
- Record durable phase state and perform a targeted rollback after simulated
  failures.
- Prove safe retry after process, network, and machine interruption.

Exit criteria:

- the fixture passes success, denial, host-key change, disk-full, timeout,
  activation-failure, verification-failure, and rollback scenarios;
- challenge cleanup is reliable and independently checked;
- logs and support output pass secret/redaction tests; and
- restoration returns the test service to its known-good baseline.

## Phase 2: useful small-developer preview

Goal: make the narrow flow understandable and maintainable for invited testers.

- Add a guided desktop setup and preflight report.
- Add opt-in import of reviewed, non-secret WinSCP connection metadata.
- Add durable renewal scheduling and renewal-window policy.
- Add actionable desktop status, Windows events, and local alerts when access or
  verification fails.
- Provide target export that excludes secrets by construction.
- Build a conventional installer with least-privilege ACLs, upgrade, repair,
  rollback, and complete-uninstall tests.
- Sign preview artifacts and publish checksums, provenance, release notes, and a
  known-limitations list.
- Write operator and recovery documentation for the exact qualified matrix.

Exit criteria:

- invited testers complete setup and recovery without maintainer intervention;
- unattended restart and renewal simulations pass;
- update and uninstall do not orphan privileged services or secret material;
- telemetry is absent by default unless a separate opt-in design is approved;
  and
- every preview build is clearly labeled non-production until support criteria
  are met.

## Phase 3: community hardening and stable client

Goal: earn a production-support claim for a deliberately small matrix.

- Resolve preview security findings and usability failures.
- Establish a runtime and dependency patch SLA.
- Add reproducible connector conformance suites.
- Publish versioning, deprecation, backup, disaster-recovery, and support
  policies.
- Add a second connector only after the first has clear ownership and stable
  rollback semantics.
- Complete an external security review of the service, IPC, secret vault,
  update, ACME, and SSH boundaries.

Exit criteria:

- the supported matrix names exact qualified combinations;
- signed releases have a tested update and rollback path;
- maintainers can respond to vulnerability and compatibility reports; and
- production documentation states residual risk without promising universal
  hosting compatibility.

## Later exploration: optional hosted coordination

A future containerized backend or web portal may help teams monitor multiple
installations. It is not part of P0 and must not cause the client to depend on a
hosted service for basic renewal.

Before any hosted prototype, a separate product and threat model must address:

- tenant isolation and authorization;
- whether certificate or SSH private keys ever leave the client;
- enrollment, device identity, revocation, and recovery;
- abuse prevention and ACME rate limits;
- billing, privacy, retention, export, and deletion;
- regional availability and incident response; and
- an open protocol boundary that avoids locking the free client to one service.

The preferred seam is coordination of opaque job/status data while the
customer-controlled client retains private keys and performs remote deployment.
That direction remains exploratory until documented in a new ADR.

## How roadmap changes are made

Open an issue describing the affected user, security boundary, supported-matrix
change, recovery story, and measurable exit criterion. Major changes require an
ADR. Popularity alone does not override the least-privilege or rollback model.
