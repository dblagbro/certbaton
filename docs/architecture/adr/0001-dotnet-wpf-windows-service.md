# ADR 0001: .NET, WPF, and a Windows Service for the P0 client

- Status: Accepted
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

CertBaton needs a Windows-native setup experience and a reliable process that
continues renewal work when no interactive UI is open. The initial audience is
small web developers and managed service providers already administering sites
from Windows.

The client must support installer-managed identities and ACLs, local IPC,
Windows secret-protection APIs, background scheduling, and code signing without
requiring a browser-hosted local control plane.

## Decision

The P0 client targets:

- .NET 10 LTS;
- C# with nullable reference types enabled;
- WPF for the Windows desktop UI;
- the .NET Generic Host and `BackgroundService` for the worker process;
- Windows Service hosting for installed background operation; and
- Windows 11 x64 as the initial qualified operating system.

The UI is an unprivileged client. It requests operations through a versioned
local IPC contract and does not own renewal schedules or long-lived secrets.
The service owns durable job execution and performs only operations authorized
for its caller and configured identity.

Development builds may run the worker as a console process for diagnostics.
That mode does not relax the installed service's authorization requirements.

## Consequences

### Positive

- The product can use current Windows identity, ACL, service-control, and
  cryptographic APIs directly.
- UI lifetime is separated from renewal reliability.
- A single language and runtime cover the UI, service, command-line diagnostics,
  contracts, and most tests.
- .NET 10 provides an LTS servicing window appropriate for the first product
  cycle.

### Costs and constraints

- P0 is Windows-specific and must be tested on real Windows installations.
- UI/service compatibility requires a stable IPC contract.
- Self-contained distribution still requires an explicit runtime patch and
  release cadence.
- Service installation, upgrade, rollback, and removal become security-critical
  product features.
- Windows 10, Windows Server, ARM64, Linux, and macOS are not implied by the
  shared .NET code.

## Validation

Before a preview release, CI and release testing must prove:

- clean install, upgrade, repair, and uninstall on the qualified OS;
- worker recovery after restart and interrupted jobs;
- UI behavior when the service is absent, incompatible, or unavailable;
- least-privilege service and filesystem ACLs; and
- runtime and dependency patchability.
