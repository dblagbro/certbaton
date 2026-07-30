# CertBaton

**Trust at Every Handoff**

CertBaton is an open-source Windows application for small web developers and
managed service providers who maintain TLS certificates on websites they can
reach through SSH or SFTP.

The project is in **pre-alpha development**. It cannot yet issue, deploy, renew,
or recover a production certificate. There are no supported releases, and the
current code must not be used on a production website.

What works today is deliberately synthetic: the service owns and durably
records an eight-stage simulated renewal, continues accepted work after the
desktop closes, recovers an interrupted run without reporting false success,
and exposes typed start/latest snapshots over the versioned named-pipe
protocol. The desktop labels this as a developer-only simulation, supports one
injected failure stage, and displays the persisted evidence timeline. No ACME,
SSH/SFTP, certificate, private-key, credential, remote-host, or production
deployment operation is performed.

The named-pipe foundation validates the connected server process against the
SCM registration, identifies callers with an Identification-level Windows
token, bounds messages, and rejects a pipe-name squatter before sending request
data. Automated tests use a current-user development profile. There is no
installer yet, so real SCM registration, service/storage ACLs, the installed
desktop/CLI path, restart behavior, and clean-machine qualification remain
release gates. Production desktop and CLI clients deliberately do not trust an
ordinary console process.

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

P0 is the first testable Windows-client milestone. The items below describe the
target, not functionality that exists today.

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
Increment 1 persists only synthetic job state and non-secret evidence in local
SQLite. Durable certificate state remains planned, and secret storage is gated
on the Windows identity and DPAPI-NG spike described in
[ADR 0003](docs/architecture/adr/0003-secret-protection-spike.md).

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

The production secret-protection design is not yet accepted. Until its security
spike passes, CertBaton must not persist real credentials. Read
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

### Test fixtures

The [disposable local target](docs/fixtures/local-target.md) and the Let's
Encrypt staging environment are the default integration targets. The local
target scaffold is present, but its container runtime smoke test remains
pending a local Docker engine. Any test involving a publicly reachable website
requires:

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
