# CertBaton

**Trust at Every Handoff**

CertBaton is an open-source Windows application for small web developers and
managed service providers who maintain TLS certificates on websites they can
reach through SSH or SFTP.

The project is in **pre-alpha development**. There are no supported releases,
and the current code must not be used on a production website.

The source tree now contains the first real, service-owned HTTP-01 vertical
slice. An administrator can import an SSH private key into protected storage,
strictly enroll a target, list targets, and start or inspect a renewal through
typed CLI/IPC contracts. The Service can coordinate an embedded ACME client,
exact-pinned SSH/SFTP, a fixed Nginx activation helper, public HTTP
pre-validation, public TLS verification, durable operation evidence, and a
basic automatic schedule. The WPF application's main view shows live targets
and renewal evidence; the synthetic simulator remains available as a secondary
developer tool.

That is implementation progress, not field qualification. The complete live
workflow currently has local fake-workflow tests and the Nginx helper has an
isolated Linux fixture. It has **not** completed an end-to-end order against a
public Let's Encrypt staging endpoint, an installed-Service vault lifecycle,
or a real remote Nginx qualification. Production issuance, production
deployment, WinSCP import, an enrollment wizard, outbound alerts, a signed MSI,
and a supported release all remain unavailable.

The named-pipe foundation validates the connected server process against the
SCM registration, identifies callers with an Identification-level Windows
token, bounds messages, and rejects a pipe-name squatter before sending request
data. A repeatable developer-only package installs the Service, desktop, CLI,
and protected state directories. It must be rebuilt, installed or repaired,
and audited for the exact source revision being tested. It is not a signed
release MSI, and clean supported-machine qualification remains a release gate.

## Why CertBaton

Free ACME certificates solve certificate issuance, but many small hosting
environments still leave a difficult last mile:

1. Prove control of the website.
2. retrieve the issued certificate safely;
3. deploy it to the correct remote paths;
4. activate it without breaking the site;
5. verify the certificate from the public internet; and
6. repeat the process reliably before expiry.

CertBaton is intended to make that handoff observable and repeatable from a
Windows workstation. It is not intended to be a remote Certbot wrapper. The
long-running Windows service owns renewal work, while the desktop application
provides setup, review, status, and recovery guidance.

## Intended P0 scope

P0 is the first testable Windows-client milestone. Some foundations below now
exist in pre-alpha form, but every support claim still depends on the evidence
in the [support matrix](docs/supported-matrix.md).

- Windows 11 x64 desktop application and background service.
- Opt-in import of non-secret connection metadata from supported local address
  books, beginning with an evaluated WinSCP path.
- Explicit SSH host-key review and pinning.
- ACME v2 account and order handling, with staging-directory validation before
  any production issuance.
- HTTP-01 challenge placement over SFTP for compatible hosting accounts.
- Typed deployment profiles for a small, documented set of remote layouts.
- Staged certificate upload, activation, rollback, and independent public TLS
  verification.
- Durable renewal scheduling, actionable local failure status, and audit events
  that do not expose secrets.
- A conventional Windows installer and clean removal path.

## P0 non-goals

- Claiming compatibility with every web host, control panel, or site builder.
- Managing platforms that do not expose certificate installation or a supported
  file/API integration, such as many fully managed site-builder plans.
- Executing arbitrary user-provided remote shell scripts or loading untrusted
  connector assemblies in the service.
- DNS-01 automation, wildcard certificates, or domain registrar integrations.
- A hosted control plane, reseller portal, billing system, or multi-tenant SaaS.
- Linux or macOS desktop clients.
- Replacing a host's existing managed-certificate feature when that feature is
  available and reliable.

See the evolving [support matrix](docs/supported-matrix.md) for finer detail.
The ordered implementation work and release evidence are in the
[P0 development backlog](docs/backlog/p0.md).

## Architecture direction

```text
┌──────────────────────┐       versioned local IPC       ┌──────────────────────┐
│ CertBaton Desktop UI │ ───────────────────────────────▶ │ CertBaton Service    │
│ setup and operations │ ◀─────────────────────────────── │ jobs and policy      │
└──────────────────────┘                                  └──────────┬───────────┘
                                                                      │
                                    ┌─────────────────────────────────┼────────────┐
                                    │                                 │            │
                              ACME client                       SSH/SFTP       public TLS
                              challenge/order                   connectors     verification
```

The client foundation uses .NET 10, WPF, and a Windows Service host.
UI-to-service communication uses a bounded, versioned named-pipe protocol with
Windows-token caller identification and SCM-backed server-process validation.
SQLite now holds target configuration, opaque secret references, schedules,
operations, write-ahead intents, certificate metadata, and sanitized evidence.
Secret values are kept outside SQLite in Service-owned files protected with
DPAPI-NG `LOCAL=user` under the dedicated virtual Service account. This choice
is accepted only for the current pre-alpha implementation; the installed
logoff, reboot, repair, upgrade, backup, restore, and uninstall lifecycle is
still a production gate under
[ADR 0003](docs/architecture/adr/0003-secret-protection-spike.md).

The embedded ACME candidate is Anvil behind a CertBaton-owned boundary. The
remote adapter uses SSH.NET with an exact algorithm, SHA-256 fingerprint, and
raw-host-key pin. Privileged Nginx changes go through a separately installed,
root-owned helper with fixed verbs and transaction identifiers; CertBaton does
not send arbitrary user commands. See
[ADR 0005](docs/architecture/adr/0005-embedded-acme-engine-gate.md) and
[ADR 0009](docs/architecture/adr/0009-sshnet-and-fixed-nginx-helper.md).

Key decisions are recorded in
[architecture decision records](docs/architecture/adr/).

## Security posture

Certificate private keys, ACME account credentials, SSH private keys, passwords,
and recovery archives are sensitive. They must never be committed, attached to
an issue, or written to ordinary application logs.

The design follows these principles:

- pin remote host identity explicitly;
- grant the service and remote account only the access they need;
- authenticate both endpoints of the local named-pipe exchange;
- represent stored credentials by opaque references across IPC boundaries;
- bound and validate every local protocol message;
- prefer typed, reviewable connector operations over arbitrary commands;
- stage remote changes and preserve a verified rollback path;
- verify the final certificate independently from the deployment channel; and
- fail visibly when renewal, activation, or verification cannot be proved.

The pre-alpha vault is not a claim that secrets are safe from a local
administrator or that recovery is complete. Do not put an actual private key,
target inventory, host-key pin, or site path in this public repository. Read
[SECURITY.md](SECURITY.md) before reporting a vulnerability or sharing
diagnostics.

## Development

### Prerequisites

- Windows 11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Git
- PowerShell for the commands below

From the repository root:

```powershell
dotnet restore .\CertBaton.slnx --locked-mode
dotnet build .\CertBaton.slnx --configuration Debug --no-restore
dotnet test .\CertBaton.slnx --configuration Debug --no-build --no-restore
```

These commands only build and test the development tree. They do not install a
Windows Service or authorize production use.

To build, install, audit, exercise, or remove the unsigned standalone package,
follow the [Windows developer preview guide](docs/installation/developer-preview.md).

### Pre-alpha live exercise

The [Windows developer preview guide](docs/installation/developer-preview.md)
documents the current `vault probe`, `credential import-ssh-key`,
`target enroll`, `target list`, `renewal start`, and `renewal get` commands.
Begin with the synthetic
[staging enrollment example](docs/examples/target-enrollment.staging.example.json).
Its names, identifiers, paths, and host key are intentionally unusable and must
be replaced outside the repository.

The default live UI does not yet include an enrollment wizard. All live IPC
methods currently require the current user in the development profile or an
elevated administrator in the installed profile. Automatic scheduling exists,
but retry policy is preliminary and no toast, email, webhook, or other
unattended alert channel exists. Keep `autoRenew` disabled until a disposable
target has passed a reviewed manual staging exercise.

### Test fixtures

The [disposable local target](docs/fixtures/local-target.md), the isolated
[Nginx helper fixture](fixtures/remote-nginx-helper/README.md), and the Let's
Encrypt staging environment are the intended integration sequence. Local fake
workflow and helper tests do not replace a real public staging exercise. Any
test involving a publicly reachable website requires:

- explicit owner authorization;
- a declared maintenance window;
- a current, independently verified backup or rollback package;
- an isolated test configuration wherever possible;
- a written stop condition and named recovery operator; and
- post-test HTTP and public TLS verification.

Do not stop, replace, or reconfigure an existing edge service merely to make a
test convenient. [ADR 0004](docs/architecture/adr/0004-live-test-restoration-boundary.md)
defines the boundary.

## Participate

- Start with [CONTRIBUTING.md](CONTRIBUTING.md).
- Review the [roadmap](docs/roadmap.md), [P0 backlog](docs/backlog/p0.md), and
  [supported matrix](docs/supported-matrix.md).
- Use [SUPPORT.md](SUPPORT.md) to decide where a question belongs.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report security issues privately as described in [SECURITY.md](SECURITY.md).

CertBaton is licensed under the [Apache License 2.0](LICENSE).
