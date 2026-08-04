# Windows developer preview

A developer package rebuilt from the current CertBaton source is a
developer-only, machine-wide Windows installation for exercising the desktop,
Windows Service, local IPC, protected secret storage, durable state, the
synthetic simulator, and the first live HTTP-01 vertical slice. An older
installed package may still expose only the simulator; build this revision and
run the repair flow before looking for the live UI or CLI methods.

> **Do not use this build on a production website.** The source contains code
> that can contact Let's Encrypt, write challenge and certificate files, invoke
> the fixed remote Nginx helper, reload Nginx, and change the certificate served
> by a public endpoint. The complete path has local fake-workflow coverage and
> one successful, manually authorized public staging run. This is not broad
> qualification or a production-safety claim. Use only a disposable or
> explicitly authorized target with a tested rollback package.

This package is an unsigned PowerShell/ZIP development artifact, not the
planned release MSI. It is suitable only for a disposable or explicitly
approved developer test machine.

## What the package installs

- Self-contained Windows x64 Service, WPF desktop application, and CLI under
  `%ProgramFiles%\CertBaton`.
- A delayed-auto-start Windows Service named `CertBaton`, running as the
  dedicated `NT SERVICE\CertBaton` virtual account.
- Durable simulation and live orchestration state in
  `%ProgramData%\CertBaton\State\certbaton.db`, protected secret records in
  `%ProgramData%\CertBaton\Secrets`, and a protected
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
.\eng\test-developer-package-scripts.ps1
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

The same command repairs an installation from the same source commit. A repair
or upgrade to a different developer build is intentionally gated. After
reviewing the new package provenance and the rollback boundary, add the exact
source-change switch:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$packageRoot\install-developer-package.ps1" `
    -PackageRoot $packageRoot `
    -AllowDeveloperSourceChange
```

An older package version additionally requires `-AllowDeveloperDowngrade`, and
the downgrade is still refused unless the incoming manifest declares the
installed SQLite schema readable. These switches acknowledge an intentional
developer transition; they do not bypass package hashes, schema bounds, the
offline database integrity check, or rollback verification.

Before replacing a developer build, the installer stops and disables the
Service, refuses any queued or active live-renewal operation, and writes a
maintenance marker that the new Service treats as a hard pause for live
renewal, recovery, and scheduling work. It then makes a protected, hashed,
exact snapshot of both `State` and `Secrets`. The new Service may migrate and
validate the installation only after that snapshot exists. Each transaction
snapshot removes Service access and remains available only to SYSTEM and local
administrators. The installer runs
the complete installed audit and Service-identity vault probe while live work
remains paused, removes the marker, restarts and health-checks the Service, and
only then removes the binary and data rollback snapshots. Any earlier failure
stops the new Service and restores both binaries and protected operational data
before restoring the prior Service state. A crash leaves the Service disabled
or live work paused rather than allowing unattended migration and renewal to
overlap. A later installer run refuses to erase a leftover maintenance marker;
inspect the retained binary and protected data snapshots and finish the prior
rollback before starting another transaction.

The execution-policy override applies only to the child PowerShell process; it
does not make an unsigned package trustworthy. Inspect the source and build the
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

The audit checks the required files and package/schema metadata, quoted service
image path, service account and SID configuration, delayed automatic start,
restart actions, protected filesystem ACLs, Event Log source, Start Menu and
uninstall entries, absence of CertBaton firewall rules, and live CLI health and
vault round trips. The vault probe inventories and hashes every existing
protected record, writes, decrypts, and removes a temporary record as the
running Service identity, and then requires the exact pre-probe inventory to
remain. Legitimate SSH, ACME-account, and certificate-key records are preserved;
temporary files, malformed names, nested content, and probe residue fail the
audit. Keep the emitted JSON as test evidence.

Health and simulation-history commands do not require elevation:

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

## Exercise the live staging path

The live path is intentionally operator-driven in this preview. There is no
enrollment wizard, WinSCP importer, remote helper installer, or production-safe
compatibility detector. Every live command currently requires an elevated
administrator in the installed profile. The development console profile admits
only its current user, but it is not a substitute for installed-Service tests.

Before enrolling anything, complete all of the following:

1. Use a disposable or explicitly authorized Nginx target whose public HTTP
   port 80 reaches the configured webroot.
2. Make and independently verify a rollback package for the currently active
   Nginx and certificate state.
3. Install and qualify the root-owned
   [version 1 Nginx helper](../../fixtures/remote-nginx-helper/README.md). Its
   sudo rule must allow only the exact helper executable, not a shell, arbitrary
   command, or container-engine access.
4. Give the dedicated, non-root SSH account only the SFTP rights needed for the
   configured challenge and incoming roots.
5. Obtain the SSH host-key algorithm, raw public-key blob, and SHA-256
   fingerprint through a separately trusted console or provider channel. Do
   not establish trust from an unauthenticated `ssh-keyscan` result alone.
6. Keep the target's existing certificate automation paused only for the
   declared maintenance window, and define the operator and stop condition that
   will restore it.

The helper is a separate remote trust boundary. CertBaton does not install it
over SSH. Its root-owned configuration determines the Nginx validation/reload
commands, transaction and release roots, stable certificate paths, and the one
permitted DNS name. The JSON enrollment paths must describe that reviewed
layout. The helper accepts only fixed verbs plus a canonical transaction UUID;
it does not accept user-authored shell text.

From an elevated Windows PowerShell session, first prove that the Service can
use its protected store:

```powershell
$ctl = "$env:ProgramFiles\CertBaton\Cli\certbatonctl.exe"
& $ctl vault probe --json
if ($LASTEXITCODE -ne 0) {
    throw 'The CertBaton vault probe failed.'
}
```

Import a dedicated SSH private key. The CLI accepts a bounded OpenSSH or
PKCS #8 private-key file, sends its bytes over the authenticated local pipe, and
zeros its request buffers after handoff. The Service stores the key under a new
opaque credential reference using DPAPI-NG `LOCAL=user` as the virtual Service
account. Interactive passphrase prompting is not implemented. Import does not
delete or protect the original key file, so secure that file separately.

```powershell
$credential = & $ctl credential import-ssh-key `
    --file 'C:\Path\Outside-The-Repository\certbaton-test-key' `
    --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'SSH credential import failed.'
}
$credential.credentialReference
```

Copy the
[synthetic staging enrollment](../examples/target-enrollment.staging.example.json)
to a private location outside the repository and replace every example value.
The example host key and names are intentionally unusable. Set
`credentialReference` to the returned identifier, use a new `enrollmentId`,
and keep `certificateAuthority` equal to `lets-encrypt-staging`. The parser is
case-sensitive, rejects unknown fields, validates absolute POSIX paths and
non-wildcard DNS names, and requires the raw host-key blob to match the exact
unpadded SHA-256 fingerprint.

Review the certificate authority's current terms before leaving
`termsOfServiceAgreed` true. The preview records the administrator's assertion
and timestamp, but not a terms URI or version.

Keep `autoRenew` false for the first reviewed exercise. Enabling it queues the
new target immediately and lets the Service rescan due work every minute; the
preview does not yet have production-grade jitter, bounded exponential
backoff, or an unattended alert channel.

```powershell
& $ctl target enroll `
    --config 'C:\Path\Outside-The-Repository\target.staging.json' `
    --json
if ($LASTEXITCODE -ne 0) {
    throw 'Target enrollment failed.'
}

& $ctl target list --json
```

Enrollment is atomic and retryable for the same immutable identity. Reusing an
`enrollmentId` with a different host, pin, DNS name, deployment path,
credential reference, or ACME directory is rejected as a conflict. Credential
rotation and staging-to-production promotion do not yet have a guided UI.

Start one manual staging renewal with a caller-retained idempotency key. A
successful start means only that the durable Service operation was accepted;
it is not issuance or deployment success.

Let's Encrypt staging certificates chain to an untrusted test root. If the
fixture exposes the activated staging certificate on public port 443, browsers
and ordinary clients will reject it during the test window. Use an isolated
hostname, keep the window short, and restore the previously trusted deployment
after collecting evidence unless the endpoint is intentionally staging-only.

```powershell
$requestKey = [Guid]::NewGuid()
$targetId = '<replace-with-target-id-from-target-list>'
$operation = & $ctl renewal start `
    --target-id $targetId `
    --idempotency-key $requestKey `
    --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'The staging renewal was not accepted.'
}

& $ctl renewal get `
    --operation-id $operation.operationId `
    --json
```

Reuse the same idempotency key if the start response is lost. Poll
`renewal get` or refresh the desktop live view until the operation reaches a
terminal or `rollback-required` state. Success is legal only after public TLS
and challenge-cleanup evidence are persisted. Treat `rollback-required` as an
operator incident and use the helper's reviewed status/rollback procedure; do
not start another renewal over uncertain remote state.

The source accepts only the exact symbolic Let's Encrypt staging and production
choices, but **production is not qualified or supported by this preview**.
Passing a local fake workflow, helper fixture, or staging order does not grant a
production go-ahead.

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
- `%ProgramData%\CertBaton\Secrets` uses the same protected boundary. Each
  record is additionally protected with DPAPI-NG `LOCAL=user` while the Service
  runs as `NT SERVICE\CertBaton`.
- The Service object grants ordinary users query access, not control access.
- Desktop and CLI communication uses the bounded, versioned named-pipe
  protocol. Clients validate that the server process is the Service Control
  Manager-registered CertBaton process before sending request data.
- SQLite stores live target metadata, exact host-key pins, opaque secret
  references, schedules, operation intents, certificate fingerprints, and
  sanitized evidence. It must never contain private-key bytes or reusable
  credentials.
- The vault selection has passed focused local round-trip tests, but its
  unattended logoff/reboot, repair, upgrade, backup/restore, rotation,
  revocation, and uninstall lifecycle remains a release gate.

These controls reduce local attack surface; they do not make the unsigned
preview production-safe.

## Uninstall and data retention

Open Windows PowerShell as Administrator. The default uninstall removes the
Service, installed binaries, shortcut, Event Log source, and uninstall entry,
but retains `%ProgramData%\CertBaton` so operational state survives a later
install. In a live-path experiment this retained tree also contains target
metadata and protected secret records:

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
`%ProgramData%\CertBaton` tree, including protected SSH, ACME-account, and
certificate-key records. This is logical deletion, not a secure-erasure claim.
Back up any developer evidence that must be retained before using it.

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

The 2026-08-04 qualification run adds evidence that one exact developer build
can complete public staging ACME, exact-pinned SSH/SFTP, fixed-helper Nginx
activation, independent public TLS verification, cleanup, and durable reload
after a Service restart. The installer repair path also restored the prior
running Service after multiple pre-commit failures during that exercise.

This remains a single manually authorized target and staging order. It does
not prove clean-machine compatibility, least-privilege behavior across hosting
layouts, rollback under injected real-target failures, unattended scheduling,
alerting, production ACME safety, or support for any matrix entry. See the
[qualification record](../qualification/live-staging-2026-08-04.md).
