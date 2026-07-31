# Windows developer preview

The current CertBaton package is a developer-only, machine-wide Windows
installation for exercising the desktop, Windows Service, local IPC, durable
simulation state, and recovery behavior.

> **Do not use this build to manage a website or certificate.** It performs no
> ACME request, HTTP-01 challenge placement, SSH/SFTP connection, certificate
> or private-key operation, remote-host change, Nginx reload, renewal schedule,
> or alert delivery. Every renewal stage shown by the UI or CLI is simulated.

This package is an unsigned PowerShell/ZIP development artifact, not the
planned release MSI. It is suitable only for a disposable or explicitly
approved developer test machine.

## What the package installs

- Self-contained Windows x64 Service, WPF desktop application, and CLI under
  `%ProgramFiles%\CertBaton`.
- A delayed-auto-start Windows Service named `CertBaton`, running as the
  dedicated `NT SERVICE\CertBaton` virtual account.
- Durable simulation state in
  `%ProgramData%\CertBaton\State\certbaton.db` and a protected
  `%ProgramData%\CertBaton\Backups` directory.
- An all-users Start Menu shortcut, Application Event Log source, and
  developer-preview uninstall registration.

The package adds no inbound listener, firewall rule, `PATH` entry, updater, or
cloud dependency.

## Prerequisites

Building the package requires Windows 11 x64, the .NET 10 SDK, Git, and Windows
PowerShell. Installing it requires an x64 Windows test machine, a local fixed
NTFS volume, and a local administrator account.

Start at the repository root. Restore, build, and test the source before
packaging it:

```powershell
dotnet restore .\CertBaton.slnx --locked-mode
dotnet build .\CertBaton.slnx --configuration Release --no-restore
dotnet test .\CertBaton.slnx --configuration Release --no-build --no-restore
dotnet format .\CertBaton.slnx --verify-no-changes --no-restore
```

Build the self-contained developer package:

```powershell
.\eng\build-developer-package.ps1 -Configuration Release
```

The builder refuses a dirty Git worktree so the manifest's source commit
identifies the exact source used for every payload. Commit the reviewed source
before packaging; ignored build artifacts do not affect this check.

For version `0.1.0-dev`, this creates:

```text
artifacts\developer\CertBaton-0.1.0-dev-win-x64\
artifacts\developer\CertBaton-0.1.0-dev-win-x64.zip
```

The build prints the exact package path, archive path, and SHA-256 hash. Record
that output with the test evidence. The package carries the CertBaton license
and notices plus the bundled .NET runtime license and notices. The installer
verifies the manifest's exact file list, sizes, and SHA-256 hashes before making
system changes. The archive and scripts are not signed, so the manifest detects
corruption but is not a cryptographic authenticity boundary.

## Install or repair

Open **Windows PowerShell as Administrator**, return to the repository root,
and run:

```powershell
$packageRoot = (Resolve-Path `
    '.\artifacts\developer\CertBaton-0.1.0-dev-win-x64').Path

powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$packageRoot\install-developer-package.ps1" `
    -PackageRoot $packageRoot

if ($LASTEXITCODE -ne 0) {
    throw "CertBaton developer installation failed with exit code $LASTEXITCODE."
}
```

The same command repairs an existing developer-preview installation. The
execution-policy override applies only to the child PowerShell process; it does
not make an unsigned package trustworthy. Inspect the source and build the
package yourself. Close the CertBaton desktop before a repair; the installer
fails before changing system state if the installed desktop process is running.

The installer requires elevation because it writes to Program Files and
ProgramData, registers and configures a service, creates an Event Log source,
and writes machine-wide Start Menu and uninstall entries. It refuses UNC,
non-fixed, non-NTFS, reparse-point, and unexpected installation paths. This
preview permits only the exact `%ProgramFiles%\CertBaton` installation root and
`%ProgramData%\CertBaton` operational-data root.

## Audit the installed state

From an elevated Windows PowerShell session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:ProgramFiles\CertBaton\Tools\test-installed-developer-package.ps1"

if ($LASTEXITCODE -ne 0) {
    throw "The installed CertBaton audit failed with exit code $LASTEXITCODE."
}
```

The audit checks the required files, quoted service image path, service account
and SID configuration, delayed automatic start, restart actions, protected
filesystem ACLs, Event Log source, Start Menu and uninstall entries, absence of
CertBaton firewall rules, and a live CLI health response. Keep the emitted JSON
as test evidence.

Read-only CLI commands do not require elevation:

```powershell
& "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe" health --json
& "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe" `
    simulation latest --json
```

The installed security profile permits only an administrator to start a
simulation. In an elevated shell:

```powershell
& "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe" `
    simulation start --json

& "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe" `
    simulation start --fail-stage verification --json
```

For a retry after a timeout or disconnect, reuse a caller-recorded key so the
Service can return the original durable request instead of creating a second
one:

```powershell
$requestKey = [Guid]::NewGuid()
& "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe" `
    simulation start --idempotency-key $requestKey --json
```

Valid failure stages are the versioned protocol's contract stage names; the
installed exercise currently uses `verification`. Starting a simulation from a
non-elevated installed client is expected to return
`simulation_start_forbidden`.

## Exercise restart and recovery

The destructive resilience exercise deliberately terminates the CertBaton
Service process while a synthetic job is running. Run it only when no other
CertBaton test is active, from an elevated shell at the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\eng\exercise-installed-developer.ps1

if ($LASTEXITCODE -ne 0) {
    throw "The installed CertBaton exercise failed with exit code $LASTEXITCODE."
}
```

It proves four synthetic outcomes: an ordinary success, an injected
verification failure, an interrupted run recorded after Service recovery, and
a post-recovery success. It does not access a network or certificate.

## Security boundaries

The developer installer establishes these intended local boundaries:

- `%ProgramFiles%\CertBaton` is owned and fully controlled by SYSTEM and local
  administrators; ordinary users and the exact Service SID receive
  read/execute access.
- `%ProgramData%\CertBaton\State` and `Backups` use protected inheritance.
  SYSTEM and administrators receive full control, and the exact Service SID
  receives modify access. Ordinary users receive no filesystem access.
- The Service object grants ordinary users query access, not control access.
- Desktop and CLI communication uses the bounded, versioned named-pipe
  protocol. Clients validate that the server process is the Service Control
  Manager-registered CertBaton process before sending request data.
- The current database contains only synthetic job state and non-secret
  evidence. Real credential and private-key storage is not implemented or
  approved.

These controls reduce local attack surface; they do not make the unsigned
preview production-safe.

## Uninstall and data retention

Open Windows PowerShell as Administrator. The default uninstall removes the
Service, installed binaries, shortcut, Event Log source, and uninstall entry,
but retains `%ProgramData%\CertBaton` so simulation history survives a later
install:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:ProgramFiles\CertBaton\Tools\uninstall-developer-package.ps1"
```

Close the CertBaton desktop before running either uninstall command. The
uninstaller validates the developer-preview ownership marker, expected Service
path, recursive-removal targets, and absence of reparse points before removing
any component.

To remove the operational data as well:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:ProgramFiles\CertBaton\Tools\uninstall-developer-package.ps1" `
    -RemoveData
```

`-RemoveData` permanently deletes the complete
`%ProgramData%\CertBaton` tree. Back up any developer evidence that must be
retained before using it.

## Qualification status and release gates

The current functional evidence comes from a reused developer workstation
running Windows 11 23H2, build 22631. Windows 11 23H2 Home and Pro are already
outside their servicing period, and a reused workstation is not a clean
qualification environment regardless of edition. This evidence therefore
does not establish supported-platform compatibility.

Before any public beta or production claim, CertBaton still requires:

- fresh install, repair, upgrade, failure rollback, and uninstall testing on
  clean VMs running supported Windows 11 x64 releases;
- verification of the exact Service identity, Service-object permissions,
  filesystem ACLs, UI/CLI behavior, reboot recovery, and data preservation on
  those VMs;
- a finalized, license-approved MSI toolchain and a conventional machine-wide
  MSI;
- signed executables and installer, published checksums, SBOM, dependency and
  license reports, and reproducible provenance;
- negative tests for tampering, wrong architecture, unsupported downgrade, and
  failed upgrade; and
- completion and review of the ACME, secret-vault, SSH/SFTP, deployment,
  rollback, public-verification, scheduling, and alerting gates.

Passing the developer package tests proves only the local simulation skeleton.
It does not authorize use on a production website.
