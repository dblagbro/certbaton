# CertBaton Windows Client Threat Model

Status: **pre-alpha working threat model**

This document describes the security boundaries of the open-source CertBaton
Windows client. It is an engineering review artifact, not a claim that the
certificate workflow is safe or qualified for production.

CertBaton now implements a pre-alpha live vertical slice in addition to its
synthetic simulator: administrator-authorized credential import and strict
target enrollment, DPAPI-NG protected records, durable live SQLite state,
exact-pinned SSH.NET/SFTP, an Anvil ACME adapter, HTTP-01 pre-validation, a
fixed remote Nginx helper contract, public TLS verification, basic scheduling,
and a live-default WPF evidence view. Local fake-workflow and isolated helper
tests exist. A real public Let's Encrypt staging order, real Nginx deployment,
and the installed-Service lifecycle have not yet passed as one qualified
workflow. WinSCP import, outbound alerts, a signed MSI, and production support
also remain absent.

The live code can change remote certificate state. “Pre-alpha” is a release
warning, not a simulation guarantee. It may be exercised only against a
disposable or explicitly authorized test target after the ADR 0004 backup and
restoration boundary is satisfied.

## Status notation

Controls in this document use these labels:

- **Implemented:** present in the current source tree. This does not imply an
  audit or production qualification.
- **Partial:** some code or tests exist, but the boundary is incomplete.
- **Planned:** required for P0 but not implemented.
- **Gated:** dependent work and release claims are blocked until a design
  decision and its evidence are accepted.
- **Out of scope:** not covered by this threat model.

When a row contains more than one label, the text identifies which portion has
each status.

## Scope

### In scope

- The Windows desktop application and diagnostic CLI.
- The long-running Windows Service.
- Local UI-to-service named-pipe communication.
- The Service identity, pre-alpha protected secret vault, local database, logs,
  and planned diagnostic exports.
- Opt-in import of non-secret connection metadata from WinSCP.
- Pre-alpha outbound SSH/SFTP connections and typed remote operations.
- Pre-alpha ACME v2 and HTTP-01 issuance workflow.
- Pre-alpha certificate staging, activation, rollback, scheduling, and public
  TLS verification, plus planned alerting.
- The Windows installer, manual upgrade path, build, dependency, signing, and
  release chain.

### Explicitly out of scope

- A hosted control plane, central web UI, multi-tenant service, billing system,
  hosted scheduler, remote agent fleet, or hosted custody of customer
  credentials.
- DNS-01, wildcard certificates, registrar integrations, browser automation,
  control-panel scraping, plain FTP, and arbitrary user-supplied remote scripts.
- Protecting data from a Windows administrator, kernel-level compromise, or an
  attacker with equivalent control of the client machine.
- Protecting a certificate private key from an administrator on the remote host
  where that key must be installed.
- Repairing a domain, DNS zone, hosting account, or certificate-authority
  account that is already under an attacker's control.

A hosted CertBaton service would introduce tenant isolation, internet-facing
authentication, authorization, abuse prevention, hosted secret custody,
service-to-agent authentication, SSRF, webhook, billing, privacy, availability,
and regulatory boundaries. None of those risks is analyzed here. A hosted
product requires a separate threat model before design or implementation.

## Security objectives

CertBaton is intended to preserve:

1. **Confidentiality:** certificate and ACME private keys, SSH credentials,
   passwords, vault material, and sensitive inventory must not leak through
   IPC, logs, process arguments, diagnostics, imports, or release artifacts.
2. **Integrity:** target identity, pinned host keys, typed plans, certificate
   material, deployment state, schedules, binaries, and evidence must not be
   changed by an unauthorized actor.
3. **Availability:** automation must not unnecessarily interrupt a working
   website or consume renewal opportunities through uncontrolled retries.
4. **Authenticity:** the service, remote host, ACME endpoint, requested domain,
   and final public TLS endpoint must each be authenticated at the appropriate
   boundary.
5. **Accountability:** security-sensitive requests and stage outcomes must be
   attributable to a local Windows identity and recorded without secrets.
6. **No false success:** file transfer, reload, or local file inspection alone
   must never be reported as a successful deployment.

## Assets

| Asset | Security need | Consequence of compromise |
| --- | --- | --- |
| Certificate private keys | Confidentiality and integrity | Website impersonation or inability to activate TLS |
| ACME account keys and account state | Confidentiality, integrity, and availability | Unauthorized orders, account loss, or rate-limit exhaustion |
| SSH private keys and passwords | Confidentiality and revocability | Remote account takeover and website modification |
| Secret-protection keys and descriptors | Confidentiality, integrity, and recoverability | Broad secret disclosure or permanent loss |
| Pinned SSH host keys | Integrity and authenticity | Credential delivery or deployment to an attacker |
| Target inventory and remote metadata | Confidentiality and integrity | Infrastructure disclosure or misdirected operations |
| Typed deployment plan and connector policy | Integrity and authorization | Arbitrary remote changes or privilege escalation |
| Local database, schedules, locks, and checkpoints | Integrity and availability | Duplicate orders, missed renewals, unsafe replay, or false state |
| Current remote certificate and rollback material | Integrity, confidentiality, and availability | Outage, key disclosure, or failed recovery |
| Run evidence, audit events, logs, and alerts | Integrity and controlled disclosure | Hidden attacks, false confidence, or sensitive-data leakage |
| Application, service, installer, and dependencies | Integrity and provenance | Local and remote compromise through trusted software |
| Domain-control authorization | Integrity and accountability | Operations against a site the operator is not authorized to manage |

Public certificates and HTTP-01 tokens are not confidential, but their
integrity, scope, lifetime, and association with an order remain
security-sensitive.

## Assumptions

- P0 runs on a supported Windows client that still receives operating-system
  security updates.
- The operator is authorized to manage every enrolled hostname and remote
  account.
- The Windows machine, remote account, DNS zone, and hosting account are not
  already fully compromised.
- The remote environment exposes a qualified SSH/SFTP and activation contract.
  File access alone does not imply that safe activation is possible.
- The service can make outbound connections to the selected ACME service,
  remote host, public challenge URL, public TLS endpoint, and selected alert
  channel.
- System time is sufficiently accurate for certificate and protocol checks.
- Windows cryptography, trusted roots, process isolation, access controls, and
  code-signing validation behave as documented.
- Backups are protected at least as strongly as the live secret material.

Violating an assumption must lead to a clear unsupported or blocked state, not
an automatic weakening of a security control.

## Threat actors

- A malicious or compromised unprivileged process on the Windows machine.
- A different local user attempting to inspect data or invoke privileged
  service operations.
- A local administrator or malware with administrator-equivalent control.
- A network attacker attempting interception, redirection, downgrade, replay,
  or denial of service.
- A malicious or compromised remote SSH server or remote account.
- A malicious remote filesystem entry, including a symlink or race intended to
  redirect a write.
- Corrupt or attacker-controlled WinSCP metadata.
- An attacker controlling DNS, the public HTTP route, or a TLS-terminating
  intermediary.
- A compromised dependency, build runner, maintainer account, signing process,
  installer, or update source.
- An authorized operator making a dangerous configuration error.
- A local user abusing the service as an outbound scanner, renewal-rate-limit
  consumer, or remote-operation proxy.

## Architecture and data flows

```text
  WinSCP metadata                 Desktop UI / diagnostic CLI
  (untrusted input)                         |
          |                       local named-pipe boundary
          v                                  |
  import preview ----------------------------v
                                      Windows Service
                                     /       |       \
                           protected vault  database  redacted events
                                  |           |             |
                                  +-----------+-------------+
                                              |
                           +------------------+------------------+
                           |                  |                  |
                        SSH/SFTP          ACME HTTPS       public HTTP/TLS
                           |                  |                  |
                      remote host      certificate CA     public endpoint
                           |
                   typed activation and rollback
```

### Flow 0: local health and synthetic simulation exchange

**Implemented.** A local client sends one bounded, versioned JSON request. The
client first obtains the connected pipe server's process ID and requires it to
match the running process registered with Windows Service Control Manager for
the `CertBaton` service. Only then does it send the request. The service obtains
the caller's Windows SID under the client's Identification-level token,
validates the request, and returns a bounded response. Read-only health/latest
requests are available to admitted callers. Synthetic start is limited to the
current-user development profile or an elevated administrator under the
installed-service profile. It enqueues no network, credential, certificate, or
remote-host operation.

**Implemented/partial for live IPC.** Dedicated methods probe the vault, import
an SSH private key, enroll/list a target, and start/get a live renewal. The
installed profile applies the current temporary elevated-administrator policy
to every live method, including reads. Credential bytes appear only in the
bounded import payload and are zeroed after handoff; other live contracts use
opaque secret references. A successful start response means durable acceptance,
not certificate success. The Service owns the operation after IPC disconnect.

The installed-service DACL profile denies network and anonymous SIDs, grants
client rights to local Users and Administrators, and reserves full-control
server rights and ownership for the exact `NT SERVICE\CertBaton` service SID.
An Owner Rights ACE suppresses implicit owner DACL-write authority and grants
only permission inspection, so a shared service account does not regain
pipe-instance creation merely by becoming the default owner. The
console/development profile instead grants access and ownership only to the
current Windows user, while retaining the network and anonymous denies.
Integration tests use an internal, test-only expected-process-ID pin because
there is no installed service in the test process. Production Desktop and CLI
clients do not trust the console process.

The authentication code and negative pipe-squatting test exist, but the real
SCM registration, service SID configuration, DACL, and process-lifecycle path
have not been qualified through an installer on a clean machine. That remains
a release gate.

### Flow 1: connection enrollment and metadata import

**Partial.** An elevated administrator can explicitly import a bounded SSH
private key into the DPAPI-NG Service vault and enroll a strict non-secret JSON
target. Enrollment requires a distinct opaque credential reference, exact host,
port, algorithm, raw host-key blob and matching SHA-256 fingerprint, DNS names,
typed paths, exact Let's Encrypt environment, contact, terms acknowledgement,
and schedule policy. SQLite commits the aggregate atomically and rejects an
immutable-identity conflict.

The UI enrollment wizard, WinSCP discovery, field-by-field metadata preview,
password handling, connection diagnosis, credential rotation/revocation, and
guided host-key rotation are **planned**. Importing another application's saved
password remains prohibited.

### Flow 2: scheduled issuance

**Implemented/partial and gated.** The Service can scan due targets, enforce one
active durable operation per target, load opaque vault references, create or
reuse an Anvil-backed ACME account, create an order, write an HTTP-01 token
through exact-pinned SFTP, compare exact content over the public HTTP route,
answer and poll the challenge, finalize the order, persist certificate metadata
and a vault key reference, and remove the exact token. Write-ahead intents and
sanitized evidence surround remote effects.

The orchestration has local fake-workflow tests, not public staging evidence.
Scheduling uses a one-minute scan and configured retry interval; complete
jitter, bounded exponential backoff, `Retry-After`, ACME Renewal Information,
restart-at-every-boundary, and rate-limit behavior are still gated.

### Flow 3: deployment, activation, and verification

**Implemented/partial and gated.** The Service uploads the issued chain and key
to a prepared transaction, calls only fixed helper verbs, validates the pair and
Nginx configuration, activates an immutable generation through the stable
`current` symlink, reloads, and probes the public TLS endpoint independently of
SSH. Failure initiates the typed rollback path. Success requires persisted
public TLS and challenge-cleanup evidence.

The root-owned helper and hostile-input checks have an isolated Linux shim
suite. Real Nginx, Docker bind mounts, sudoers, SFTP filesystem races, public
TLS, process kill, and rollback-failure qualification remain open. A
transitional or uncertain activation is persisted as `rollback-required`, not
automatically replayed or reported successful.

### Flow 4: installation and manual upgrade

**Partial and gated.** An unsigned developer PowerShell/ZIP package creates the
virtual Service identity, service registration, access-controlled state,
secret, and backup locations, Event Log source, desktop shortcut, and uninstall
entry. Its audit checks Service configuration, ACLs, health, and a protected
vault round trip. It is not the planned signed MSI. P0 upgrades are manually
initiated; P0 has no automatic privileged updater. Clean supported-VM
qualification, toolchain, signing, provenance, upgrade rollback, and complete
uninstall/retention behavior remain release gates.

## Trust boundaries

| Boundary | Trusted side | Untrusted or less-trusted side | Required decision |
| --- | --- | --- | --- |
| UI/CLI to Service | SCM-registered Service process and method authorization policy | Any local process that can discover or squat the pipe name | Endpoint authentication and a coarse current-user/elevated-administrator policy cover current methods; qualify the installed profile and replace the temporary role model |
| Service process to Windows | Restricted service identity and OS controls | Other users, processes, and mutable machine state | Finalize identity, privileges, ACLs, and service hardening |
| Service to vault/database/logs | Validated service code | Filesystem contents, backups, imported or migrated data | Protect, validate, migrate transactionally, and redact |
| WinSCP to importer | Explicitly confirmed fields | Registry or file data controlled outside CertBaton | Parse as untrusted data; never silently import secrets |
| Service to SSH server | Pinned host identity and qualified connector | Network and remote host output/filesystem | Pin, bound, canonicalize, and avoid arbitrary commands |
| Service to ACME endpoint | Selected HTTPS directory and ACME account | Network, redirects, protocol responses, and CA state | Validate TLS and protocol; bound retries and state transitions |
| Service to challenge route | Exact expected token and enrolled hostname | Public HTTP path, caches, proxies, and redirects | External pre-validation and exact content comparison |
| Service to public TLS endpoint | Expected hostname and issued certificate evidence | DNS, network route, proxy, CDN, and server | Independent handshake and strict evidence comparison |
| Source to released installer | Reviewed source and protected release identity | Dependencies, CI runners, artifacts, mirrors, and downloads | Reproducible provenance, signing, verification, and review |

## Security invariants

These rules apply even if a connector, import format, or workflow would be
easier without them:

- **Implemented now:** live IPC has distinct bounded contracts for vault probe,
  SSH-key import, target enroll/list, and renewal start/get. Only the dedicated
  import payload can carry SSH private-key bytes; target and status contracts
  carry opaque references and sanitized metadata. Certificate and ACME private
  keys do not cross UI/CLI IPC.
- **Implemented now:** IPC frames are length-bounded and parsed into explicit
  types with case-sensitive fields; unknown and duplicate properties are
  rejected.
- **Implemented now:** before sending a request, a client compares the
  connected named-pipe server process ID with the running process registered by
  Windows Service Control Manager for the exact `CertBaton` service.
- **Implemented now:** the installed-service pipe profile denies network and
  anonymous SIDs, gives local Users and Administrators client rights, and gives
  the exact `NT SERVICE\CertBaton` SID full-control server rights. The
  console/development profile is restricted to its current Windows user.
- **Implemented now:** clients request only Identification-level token access.
  The server reads the caller SID and role membership but cannot use that token
  to act as the caller.
- **Implemented/partial:** the Service owns durable simulation and live run
  state after the UI closes. It owns vault references, target-scoped active
  operations, schedules, write-ahead remote intents, evidence, and recovery
  classification. Real interruption tests at every remote boundary remain
  gated.
- **Implemented/partial:** endpoint authentication exists for all current IPC.
  Live methods use the temporary current-user/elevated-administrator policy,
  bounded requests, durable idempotency, and target-scoped active-operation
  enforcement. Fine-grained Operator roles and durable actor attribution remain
  planned.
- **Implemented:** every live SSH connection requires an operator-supplied exact
  host, port, algorithm, raw host-key blob, and matching SHA-256 fingerprint. A
  changed key hard-stops; there is no automatic trust or pin replacement.
- **Implemented/partial:** remote paths use validated absolute POSIX forms, and
  the privileged command contains only a fixed helper path, typed verb, and
  canonical UUID. The helper applies root-owned ancestry, link, ownership,
  overlap, and file checks. Hostile real-filesystem race qualification remains
  gated.
- **Implemented/partial:** only exact symbolic Let's Encrypt staging or
  production choices are accepted. Production is explicit, but a stronger
  guided promotion and release-policy gate remains required before supported
  use.
- **Implemented/partial:** activation is preceded by certificate/key and Nginx
  checks; success requires public TLS and cleanup evidence. Uncertain activation
  becomes `rollback-required`. Real failure-injection evidence remains gated.
- **Implemented/partial:** secrets are persisted only through DPAPI-NG
  `LOCAL=user` protected records under the virtual Service identity. The
  installed lifecycle and adversarial qualification remain release gates.
- **Gated:** no public release may claim a supported remote recipe until its
  positive, negative, interrupted-operation, and rollback evidence passes.

## STRIDE analysis and controls

### Windows UI, CLI, service, and named pipe

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A client puts a privileged username or SID in JSON. | **Implemented:** the client requests an Identification-level token; the server briefly reads the connected Windows token's SID and role membership; JSON identity is not accepted. Anonymous and network SIDs are denied by both pipe security profiles. | Add explicit unauthorized-local and remote-attempt tests. Review behavior under filtered UAC tokens. |
| Spoofing | A local process creates a look-alike pipe before the genuine service and returns a false response or captures future requests. | **Implemented/partial:** before writing any request bytes, the client obtains the connected pipe server PID and requires an exact match with the running `CertBaton` process reported by Windows Service Control Manager. A negative integration test proves a mismatched pipe squatter is rejected before receiving request data. Tests use a separate internal expected-PID pin, not a production bypass. | Qualify the real registered service, exact service SID, installed DACL, stop/restart behavior, and relevant PID/process races through the installer on a clean machine. |
| Tampering | A client sends malformed, ambiguous, deeply nested, oversized, truncated, or version-confused JSON. | **Implemented/partial:** fixed-length framing, size and depth limits, strict explicit DTOs, duplicate and unknown property rejection, exact version checks, and sanitized protocol errors exist. | Complete malformed UTF-8, partial read, exact-boundary, missing-field, fuzz, and disconnect tests. |
| Repudiation | A user denies requesting a certificate or changing a target. | **Partial:** request key, target, timestamps, stages, and outcome are persisted for live work, but the caller SID supplied to the coordinator is not yet durable evidence. **Planned for production:** record caller SID, request identifier, action, approval basis, and outcome without secrets. | Define audit schema, retention, clock handling, export, and administrator-tampering limitations. |
| Information disclosure | Health or error responses reveal paths, stack traces, credentials, target inventory, or internal state. | **Implemented/partial:** typed results expose only method-specific metadata; Service exceptions map to fixed client errors and live logs use identifiers rather than secrets. Authorized target-list/evidence responses intentionally reveal inventory. | Review every response and log field, version disclosure, shared-administrator visibility, and canary-secret coverage. |
| Denial of service | A local process opens connections, stalls reads/writes, or sends expensive frames until the service cannot schedule renewals. | **Implemented/partial:** bounded frames, a finite client limit, per-client timeout, cancellation, stalled-client coverage, and rejection of late success from a non-cooperative handler exist. A late handler is observed but cannot retain the pipe slot. | Load-test saturation, slow readers/writers, repeated reconnects, shutdown, memory use, and fairness. Mutating work must be a durable job outside the IPC handler so ignored cancellation cannot continue an unsafe detached mutation. Reserve certificate work from IPC starvation. |
| Elevation of privilege | Any member of the local Users group invokes a mutation through the read-oriented pipe ACL. | **Partial:** simulation start and every current live method are allowed only for the current user in development or an elevated administrator under the installed profile; ordinary installed callers are denied before secret or state access. This coarse temporary rule does not authorize production work. **Planned:** explicit Operator and Administrator roles plus per-operation read/mutate policy. | Negative tests for every method and role, including filtered tokens, disabled users, Service repair, and ACL drift. |
| Elevation of privilege | Replay or duplicate submission starts more than one order or activation. | **Implemented/partial:** caller-retained durable idempotency keys, one active live operation per target, execution epochs, write-ahead intents, and constrained state transitions exist. Remote effects are at-least-once with reconciliation, not exactly-once. | Concurrent triggers and crash/restart tests before and after every real ACME, SFTP, helper, and verification boundary. |

The service must treat a pipe disconnect as loss of the requester, not proof
that already-started remote work was cancelled or rolled back.

### Service identity and protected secret vault

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing / EoP | The Service runs with unnecessary privilege or another process impersonates its storage identity. | **Partial/gated:** the developer installer registers `NT SERVICE\CertBaton`, enables the Service SID, protects executable/state/secret paths, restricts Service control, and gives only the exact Service SID full server-pipe rights. Scripted installed-state audit exists; clean supported-VM lifecycle qualification does not. | Verify token privileges, SID/profile behavior, pipe and executable ACLs, service-control ACL, and repair/upgrade behavior on each supported Windows release. |
| Information disclosure | Another local user reads encrypted records, keys, memory, swap, crash dumps, or backups. | **Implemented/partial:** each Service-owned record is protected with DPAPI-NG `LOCAL=user` under the virtual Service account and stored below a protected ACL. The broad machine-scope fallback is prohibited. Managed plaintext exists briefly during import/use. | Prove cross-user denial, unattended reboot access, memory and dump policy, backup behavior, and the documented local-administrator limitation on clean machines. |
| Tampering | An unprivileged process replaces an encrypted secret record or protection descriptor. | **Implemented/partial:** DPAPI-NG authenticates the protected blob; the vault rejects reparse points, bounds records, uses write-through temporary files and atomic replacement, and relies on installer ACLs. Secret reference/type/owner binding and hostile record-swap lifecycle evidence remain incomplete. | Replace, rollback, cross-reference swap, truncation, directory race, ACL-change, repair, and restore tests. |
| Denial of service | Upgrade, account change, machine rejoin, or uninstall makes secrets permanently unreadable. | **Gated:** recovery, rotation, revocation, backup, deletion, repair, and upgrade are part of the vault decision. | Full lifecycle tests with the actual installer-created identity. Fail clearly without silently creating new credentials. |
| Repudiation | A secret is replaced or deleted without attribution. | **Planned:** audit the secret identifier, type, actor, reason, and result; never record the value. | Verify audit coverage and recovery events. |

A Windows-local vault cannot promise protection against an administrator who
controls the machine. The objective is least privilege, isolation between
ordinary users and unrelated processes, and clear recovery behavior.

### Local database, logs, diagnostics, and alerts

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Tampering | Database edits alter host pins, schedules, approvals, checkpoints, or success evidence. | **Implemented/partial:** STRICT forward-only schemas, migration checksums, foreign keys, atomic enrollments, one active operation per target, owned transitions, write-ahead intents, ordered evidence, certificate metadata, and a success invariant exist. The database is not cryptographically authenticated against an administrator. | Mutation, downgrade, crash injection, backup/restore, clean-machine ACL, impossible-state, and intent-recovery tests. |
| Information disclosure | Database, logs, Event Log entries, support bundles, or alerts expose secrets or a detailed customer inventory. | **Implemented/partial:** SQLite now contains target names, remote metadata, raw public host keys, paths, schedules, fingerprints, opaque secret references, and sanitized evidence, but no reusable secret values. Service live logs use identifiers and fixed messages. Diagnostic export and canary-secret coverage are not complete. | Treat the database as sensitive inventory; seed canary secrets into every boundary and prove absence from logs, errors, exports, notifications, crash output, and process arguments. |
| Repudiation | A local administrator changes or deletes local evidence. | **Residual:** local records can support operations but are not tamper-proof against an administrator. **Planned:** structured event IDs and continuity checks make accidental or unprivileged alteration visible. | Document evidence limits; do not market local audit data as non-repudiation. |
| Denial of service | Corruption, unbounded history, log flooding, disk exhaustion, or concurrent writers stop renewals. | **Partial:** Service-owned synchronous SQLite operations use finite transactions and DELETE journal mode. Startup classifies abandoned live work as interrupted or rollback-required from intents. Retention, online backup, disk-space checks, and degraded-but-visible behavior are not implemented. | Fault injection for full disk, locked/corrupt database, interrupted migration, retention, backup restore, scheduler starvation, and alert storms. |
| Spoofing | A forged alert claims success or asks an operator to disclose a credential. | **Planned:** outbound-only adapter, minimal content, stable event identity, deduplication, recovery events, and clear provenance in the UI. | Choose and threat-model the first unattended channel; test credential prompts are never generated. |

Backups and diagnostics inherit the highest sensitivity of any included field.
Changing a file extension or compressing an archive is not protection.

### WinSCP metadata import

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | Imported metadata substitutes a hostname, username, protocol, or host key that looks like a trusted connection. | **Planned:** imports are opt-in, parsed as untrusted input, shown in a field-by-field preview, and require explicit confirmation. Host-key enrollment is a separate trust action. | Test confusing Unicode, duplicate names, unsupported formats, stale entries, and changed data between preview and commit. |
| Information disclosure | CertBaton decrypts, copies, displays, or logs a password saved by WinSCP. | **Planned invariant:** import supported non-secret metadata only. Never silently decrypt or copy a stored password. | Verify all supported storage modes and error paths with canary secrets. |
| Tampering / EoP | A malicious key-file reference, remote path, proxy setting, tunnel, raw option, or command becomes executable behavior. | **Planned:** use an explicit field allowlist; treat imported paths only as displayable candidates; ignore executable hooks and unsupported raw settings; validate values when separately enrolling a connection. | Corpus tests against registry/file variants and malicious values. Existing CertBaton state must remain unchanged on failure. |
| Denial of service | A corrupt or enormous address book consumes resources or partially overwrites configuration. | **Planned:** bounded input, finite entry count and field lengths, parse in isolation, and commit only after a complete preview transaction. | Fuzzing, size limits, cancellation, and atomicity tests. |

Import proves neither control of a remote host nor authorization to manage its
certificates. It is a convenience for drafting a connection record.

### SSH/SFTP, remote output, paths, and host-key trust

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A network attacker or rebuilt server presents a different SSH host key. | **Implemented/partial:** enrollment stores exact host, port, permitted algorithm, canonical fingerprint, and raw key blob; SSH.NET trust is set explicitly and mismatch fails closed. No TOFU or automatic replacement exists. | Complete rotation ceremony, alias, multi-algorithm, concurrent enrollment, and real unattended mismatch tests. |
| Tampering | User-controlled text is interpolated into a remote shell command. | **Implemented/partial:** SFTP handles files; privileged work invokes one root-owned helper path with a closed verb and canonical UUID. No user text enters the command. | Expand injection corpus and qualify the actual SSH server/sudo command parsing on supported targets. |
| Tampering | A remote path escapes the approved root through traversal, separators, encoding, case behavior, or a symlink. | **Implemented/partial:** local contracts require canonical absolute POSIX paths; the helper requires root-owned non-writable non-symlink ancestry, separated roots, frozen uploads, expected entries, and regular-file ownership. | Hostile SFTP must exercise symlink swaps, hard links, rename races, mount changes, Unicode/filesystem behavior, and time-of-check/time-of-use windows. |
| Tampering | A hostile server changes bytes after upload or lies through command output. | **Implemented/partial:** transfers and helper JSON are bounded; only fixed response shapes affect state; the helper re-reads frozen files and validates the certificate/key; public TLS is checked independently. | Malformed, truncated, delayed, reordered, control-character, post-validation mutation, and false-success tests against a hostile real server. |
| Information disclosure | Credentials, private keys, remote output, filenames, or environment data leak into command lines, logs, UI, diagnostics, or temporary files. | **Implemented/partial:** vault-backed key access, in-memory handoff, fixed commands, bounded sanitized evidence, restricted remote modes, and cleanup logic exist. Certificate private-key bytes necessarily traverse SFTP and remote staging. | Canary-secret tests across authentication failures, exceptions, cancellation, dumps, remote leftovers, and exports. |
| EoP | A broad sudo rule, shell, container-engine membership, or privileged remote account turns CertBaton into arbitrary root execution. | **Accepted design/gated evidence:** the remote account is dedicated and non-root; sudo permits only the root-owned versioned helper. General sudo, root login, arbitrary scripts, and container-engine access are excluded. | Audit actual sudoers, account groups, executable/config ancestry, rejected verbs/arguments/environments, and Docker bind mounts. |
| Denial of service | A hostile or slow server holds connections, returns unbounded data, or interrupts an atomic change. | **Implemented/partial:** connection and operation deadlines, output/file bounds, cancellation boundaries, serialized helper lock, bounded Nginx operations, durable intents, and one Service live worker exist. Retry/rate policy is preliminary. | Slow-server, partial-transfer, response-loss, reboot, saturation, lock timeout, and repeated scheduler tests. |
| Repudiation | Remote changes cannot be tied to a connector operation. | **Partial:** typed action, target/operation, fingerprint, certificate metadata, timestamps, and sanitized results are durable; caller attribution and complete remote hash evidence are incomplete. | Compare local evidence with fixture evidence; document that an administrator can alter local or remote logs. |

Path and symlink checks reduce mistakes and attacks by a constrained remote
account. They cannot make a hostile remote administrator trustworthy: that
actor can change the filesystem or web server after any check.

### ACME and HTTP-01

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A configured or redirected ACME directory impersonates the intended certificate authority. | **Implemented/partial:** only exact symbolic Let's Encrypt staging/production directories are accepted; Anvil uses normal HTTPS validation. No arbitrary endpoint or silent downgrade is exposed. | Public protocol, redirect, bad-certificate, alternate-chain, dependency, and endpoint-change tests. |
| Spoofing | Public HTTP pre-validation reaches a proxy, stale cache, wrong virtual host, or attacker-controlled route. | **Implemented/partial:** exact enrolled hostname/token/content comparison, bounded redirects limited to HTTP/HTTPS ports 80/443, fail-closed public-address checks, per-hop DNS snapshots pinned into the socket connection, disabled application proxies and automatic redirects, and TLS chain policy that prohibits auxiliary certificate and revocation downloads. | Test CDN caching, wrong virtual hosts, redirects, split DNS, address-policy changes, and platform-specific TLS behavior. |
| Tampering | A token name or webroot escapes the HTTP-01 challenge directory or overwrites site content. | **Implemented/partial:** token/path types reject separators and traversal, placement is under one enrolled webroot, exact content is verified, and cleanup removes the owned path. | Expand malicious token/path corpus and real cleanup tests across success, error, cancellation, response loss, and restart. |
| Information disclosure | ACME account or certificate private keys appear in protocol logs, challenge files, exports, or IPC. | **Implemented/partial:** account and certificate keys use vault references; IPC/status carry metadata; the challenge contains only public key authorization. | Canary-secret tests for every ACME problem, exception, network failure, log, dump, and future export. |
| Denial of service | Duplicate triggers or aggressive retry exhaust CA rate limits or leave tokens behind. | **Partial:** one active operation per target, durable request keys, finite coordinator polling, cleanup, and explicit staging selection exist. Server `Retry-After`, complete bad-nonce handling, jitter, bounded exponential backoff, and abandoned-order reconciliation are incomplete. | Concurrency, restart, bad nonce, rate-limit, timeout, repeated automatic failure, and abandoned-order tests. |
| EoP / abuse | A local user asks the privileged Service to probe internal systems or request certificates for unauthorized names. | **Partial:** installed live methods require elevation, operate only on a strict enrolled target, reject wildcard DNS names, and public HTTP/TLS probes reject non-public destinations. Enrollment records an ownership assertion only implicitly through administrator action. | Add explicit ownership acknowledgement/audit, fine-grained roles, target-change review, and tests that ordinary users cannot list, enroll, or run targets. |
| Repudiation | Terms acceptance, account creation, production selection, or issuance cannot be attributed. | **Partial:** target, exact directory, contact, acceptance flag/time, opaque account reference, operation, and certificate fingerprint are stored. Actor, terms URI/version, and complete order reference are not durable audit evidence. | Review privacy and retention; test explicit staging-to-production approval and actor attribution. |

An ACME challenge demonstrates control under the CA's policy at that moment. It
does not establish business ownership or repair compromised DNS and hosting.

### Typed activation, rollback, and public TLS verification

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Tampering | A certificate is paired with the wrong key, uploaded with unsafe permissions, or placed in the wrong target. | **Implemented/partial:** local inspection and the helper compare certificate/public key and names, reject encrypted/malformed input, apply fixed ownership/modes, and bind persisted artifact metadata to target/run. | Real mismatch, cross-target swap, permission, stale-file, corrupted-upload, and post-validation mutation tests. |
| EoP | Activation parameters escape the typed recipe or invoke arbitrary commands. | **Implemented/partial:** one fixed Nginx helper version accepts closed verbs and canonical UUIDs; paths and commands come from root-owned configuration. No user scripts are accepted. | Schema/input corpus, actual sudoers, executable replacement, environment, and unsupported-operation tests. |
| Denial of service | Validation, replacement, reload, or rollback fails and takes down a working site. | **Implemented/partial:** immutable generations preserve the prior target, Nginx test precedes activation, the `current` symlink changes atomically, helper state is write-ahead and idempotent, calls are bounded, and rollback-required is explicit. | Failure injection before/after every real boundary, fsync/power-loss analysis, reload/rollback failure, full disk, and competing automation tests. |
| Spoofing | The remote command reports success while the public endpoint still serves the old or an attacker's certificate. | **Implemented/partial:** a separate public TLS connection validates SNI/hostname, expected leaf SHA-256, validity, and trust according to staging/production mode. SSH/helper success is insufficient. | Real stale reload, wrong virtual host, reverse proxy/CDN, multiple addresses, staging trust, and chain-error tests. |
| Tampering | Local DNS or network interception makes the “independent” public probe observe the wrong endpoint. | **Partial assurance:** the implemented probe is independent of SSH deployment, not of the client resolver, route, trust store, or local malware. | Persist sufficient address/handshake evidence and decide whether supported releases require multiple network vantage points. |
| Repudiation | The UI shows healthy without evidence of which certificate was live. | **Implemented/partial:** the operation snapshot and UI show status, leaf fingerprint, public-TLS result, cleanup result, timestamps, failure code, and ordered evidence. Full resolved-address, chain, plan-version, and actor evidence is incomplete. | Evidence-schema review, UI traceability, clock-skew, and no-false-success tests on a real endpoint. |
| Information disclosure | Rollback archives or staged private keys remain readable or accumulate indefinitely. | **Partial:** remote helper uses restrictive ownership/modes, transaction-scoped names, immutable generations, and bounded input; abort/rollback cleanup is explicit. Version 1 has no garbage collection for old committed generations. | Remote permission, orphan reconciliation, backup expiry/GC, deletion, and rollback-key exposure tests. |

Independent verification means independent of the deployment channel. A probe
from the same Windows machine remains exposed to its resolver, route, trust
store, and local malware.

### Installer, manual update, and software supply chain

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A user installs a counterfeit or tampered package. | **Partial/gated:** the unsigned developer ZIP has a file manifest and printed SHA-256, but neither authenticates a publisher. No supported installer exists. Signed artifacts, authoritative releases, and clear publisher identity are required. | Verify valid, unsigned, modified, expired/revoked-signature, wrong-architecture, and wrong-publisher packages. |
| Tampering | A dependency, build action, runner, artifact handoff, or maintainer account injects code. | **Partial:** central pins, locked restores, reviewed third-party notices, build checks, and source-commit package metadata exist. SBOM, signing, protected release environments, and reproducible provenance are incomplete. | Threat-model CI credentials; audit all dependencies; test artifact/source linkage; require review for security-boundary and dependency changes. |
| EoP | Installer ACLs, an unquoted service path, writable executable directory, custom action, or DLL search path gives local privilege escalation. | **Implemented/partial for developer package:** fixed Program Files/ProgramData paths, manifest validation, quoted Service path, protected executable/data ACLs, restricted Service control, path/reparse checks, and installed audit exist. The conventional MSI and clean-VM hostile tests do not. | Clean-VM privilege/ACL/search-path tests after install, repair, upgrade, rollback, and uninstall. |
| Information disclosure | Installer logs, repair data, crash dumps, or uninstall leave credentials behind. | **Partial/gated:** secrets are not installer properties or command-line values. Default developer uninstall retains state and protected secrets; explicit `-RemoveData` logically deletes the tree. Neither path claims secure erasure. | Canary-secret install/repair/upgrade/uninstall tests, dump policy, backup handling, and documented deletion limits. |
| Denial of service | Upgrade corrupts the database, changes Service identity, loses vault access, or cannot roll back. | **Partial/gated:** forward-only transactional migrations and identity-preserving developer repair exist. Vault-preserving upgrade, downgrade policy, preflight backup, and MSI rollback are not qualified. | Upgrade from every supported version with Service interruption, vault use, migration failure, and rollback injection. |
| Repudiation | A release cannot be traced to reviewed source and its dependency set. | **Partial:** the developer builder refuses a dirty tree and records its source commit, exact payload manifest, and hash. Signed tags/artifacts, SBOM, provenance, and retained release evidence remain planned. | Independent verification from a clean environment. |
| EoP | An automatic updater becomes a persistent privileged code-execution channel. | **P0 exclusion:** P0 has only operator-initiated MSI upgrades. | Any future automatic updater requires a new design review and threat-model section. |

Open-source publication improves reviewability but does not itself establish
provenance, trustworthiness, or secure update delivery.

## Abuse cases

| Abuse case | Expected safe result | Status |
| --- | --- | --- |
| A standard local user sends a forged administrator field in JSON. | The field has no authority; the Service uses the Windows token and denies current installed live methods to a non-elevated caller. | **Implemented; role model still temporary** |
| A local process starts a counterfeit service pipe before the real service. | Before sending a frame, UI/CLI compares the connected server PID with the running SCM-registered `CertBaton` service process and rejects a mismatch. | **Implemented with negative test; installed-service qualification gated** |
| A local user floods the pipe with stalled connections. | Slots expire; renewal work and service shutdown remain responsive. | **Partial** |
| A malicious WinSCP entry contains a password, command hook, traversal path, or misleading host key. | Only allowlisted non-secret fields appear in preview; no state changes until explicit confirmation; executable fields are ignored. | **Planned** |
| A host presents a new SSH key during an unattended renewal. | Exact-pin verification stops before authenticated work; the operation fails visibly. There is no unattended alert channel yet. | **Implemented locally; real mismatch qualification pending** |
| A hostname or path contains shell metacharacters or an option-like prefix. | Strict types reject it; the only privileged command fields come from a closed verb and canonical UUID. | **Implemented with local tests** |
| A remote symlink is swapped between path inspection and certificate replacement. | The helper rejects links and freezes input; unsupported residual races must keep a platform unqualified. | **Partial with residual risk** |
| A remote server emits enormous output, terminal control codes, or a false success message. | Output is bounded and parsed as fixed data; only typed results and independent evidence affect state. | **Implemented locally; hostile real-server tests pending** |
| Multiple triggers start orders for one target. | One durable active operation owns the target; a matching idempotent retry observes its operation and a conflicting active request does not create a second. | **Implemented locally; crash/concurrency integration pending** |
| A challenge token is crafted as a path traversal. | It is rejected before remote I/O; cleanup addresses only the owned path. | **Implemented with local tests** |
| Configuration validation succeeds but reload serves the old certificate. | Public verification fails; success is forbidden and the typed rollback path runs. | **Implemented with fakes; real endpoint pending** |
| Activation and rollback both fail. | A critical rollback-required state and evidence are persisted without claiming success. No outbound alert exists yet. | **Implemented with fakes; real failure injection pending** |
| A forged or downgraded installer is offered to the user. | Signature, publisher, architecture, and version policy reject it. | **Planned/gated** |
| A diagnostic bundle contains a seeded credential. | Export fails closed and identifies the offending field without exposing its value. | **Planned** |
| An operator enrolls a system they do not own. | The product requires local authorization and ownership acknowledgement, records the actor, and still relies on protocol validation; it does not claim to adjudicate legal ownership. | **Planned with operator residual risk** |

## Verification checklist

### Evidence present in the pre-alpha source tree

- [x] Health/simulation and dedicated vault, credential-import, target, and live
  renewal methods use explicit bounded contracts and method validation.
- [x] Only the SSH-key import payload can carry reusable credential bytes;
  target/status contracts use opaque references and certificate metadata.
- [x] Before sending a request, clients compare the connected pipe server PID
  with the running SCM-registered `CertBaton` service process.
- [x] A negative test proves a mismatched pipe squatter receives no request
  bytes.
- [x] The pipe server reads the actual client SID from an
  Identification-level token.
- [x] Both pipe DACL profiles explicitly deny network and anonymous SIDs.
- [x] The installed-service profile grants client rights to local Users and
  Administrators and full-control server rights and ownership only to the exact
  `NT SERVICE\CertBaton` SID. Its Owner Rights ACE suppresses implicit DACL
  modification by a shared-account default owner.
- [x] The console/development profile is restricted to the current user.
- [x] Frames have a fixed length prefix and finite maximum size.
- [x] JSON uses explicit contracts and rejects unknown and duplicate members.
- [x] Protocol version and request deadline are validated.
- [x] Client concurrency and request time are bounded.
- [x] Tests cover health round-trip, observed caller SID, oversized frames,
  unknown and duplicate members, unsupported versions, unreasonable deadlines,
  Identification-level access, cooperative handler deadline cancellation,
  rejection of late success from a non-cooperative handler without retaining
  its client slot, a stalled client releasing its slot, and rejection of a
  mismatched pipe server before request transmission.
- [x] Live mutations require the temporary current-user development policy or
  an elevated administrator under the installed profile.
- [x] DPAPI-NG protected-file vault, exact host-key pin, SSH.NET adapter, Anvil
  adapter, HTTP/TLS verifiers, fixed Nginx helper, durable operations/intents,
  scheduler, and live UI have focused local tests.
- [x] The isolated helper suite covers happy path, rejection, idempotent retry,
  interrupted activation/rollback, commit, abort, status, and recovery reports.
- [x] Documentation and UI identify the path as pre-alpha and do not present
  local fake tests as public staging or production evidence.

### Required before production acceptance of sensitive or mutating IPC

- [ ] Qualify server-PID validation against a genuinely installed and running
  service, including stop, restart, unavailable-SCM, and process-race cases.
- [ ] Qualify the exact service SID and installed-service DACL through the real
  installer on a clean supported Windows machine.
- [ ] Create installer-owned Operator and Administrator groups or an equivalent
  explicit authorization model.
- [ ] Authorize every method against the caller token; test standard,
  elevated, filtered, disabled, anonymous, and remote identities.
- [x] Add durable idempotency and service-owned recovery for the synthetic job.
- [x] Add durable live idempotency, per-target active-operation enforcement,
  write-ahead intents, and safe start reconnect behavior.
- [ ] Define production actor audit, complete cancellation semantics, and
  recovery for every uncertain remote boundary.
- [ ] Complete IPC fuzzing, malformed UTF-8, partial frame, saturation, shutdown,
  and redaction tests.

### Required before production custody of real secrets

- [x] Select DPAPI-NG `LOCAL=user` under the virtual Service identity for
  pre-alpha implementation and record ADR 0003.
- [ ] Prove unattended decrypt after logoff and reboot and denial to a different
  ordinary user.
- [ ] Test record substitution, ACL tampering, repair, upgrade, backup, restore,
  rotation, revocation, and uninstall.
- [ ] Document memory, dump, administrator, machine-change, and unrecoverable
  secret risks.
- [ ] Pass canary-secret tests across IPC, logs, alerts, diagnostics, errors,
  arguments, and installer output.

### Required before a qualified mutating SSH/SFTP target

- [x] Pass focused exact host-key enrollment and mismatch tests; rotation and
  real unattended evidence remain open.
- [x] Record the fixed-helper remote privilege contract in ADR 0009.
- [x] Prove fixed command construction and local injection resistance; actual
  SSH/sudo parsing qualification remains open.
- [ ] Prove remote-root confinement and exercise traversal, symlink, rename,
  hard-link, and time-of-check/time-of-use attacks in a hostile fixture.
- [ ] Bound authentication, transfer, output, retries, concurrency, and cleanup.
- [ ] Verify independently enrolled credentials can be revoked independently.

### Required before ACME staging or production

- [x] Select Anvil 3.3.3 behind the adapter and record its initial dependency
  decision in ADR 0005.
- [ ] Complete protocol, TLS, redirect, bad nonce, retry, rate-limit,
  concurrency, restart, and problem-response tests.
- [x] Prove exact HTTP-01 placement, external pre-validation, and cleanup in
  local fake workflows; public staging and restart/error integration remain.
- [ ] Require an explicit, audited transition from staging to production.
- [x] Route account and certificate keys through the vault interfaces in local
  implementation tests; installed lifecycle qualification remains.

### Required before a supported deployment recipe

- [x] Validate certificate/key pairing, names, fixed modes/ownership, Nginx
  configuration, and typed activation in local/helper fixtures; real chain and
  remote layout qualification remains.
- [ ] Inject failure at every stage and prove the previous working deployment is
  preserved or restored.
- [x] Prove with fakes that a stale or wrong public certificate prevents
  success after upload/reload; repeat on a real public endpoint.
- [ ] Record expected and observed public TLS evidence and document single-vantage
  limitations.
- [ ] Pass reboot, sleep, logout, network-loss, duplicate-trigger, full-disk,
  corrupt-state, and rollback-failure exercises.

### Required before a public beta installer

- [ ] Complete installer/toolchain and signing decisions.
- [ ] Audit service identity, privileges, executable/data ACLs, service-control
  ACL, search paths, repair, upgrade, rollback, and uninstall on a clean
  supported VM.
- [ ] Produce and verify signatures, hashes, SBOM, dependency/license reports,
  provenance, and source-to-artifact traceability.
- [ ] Reject unsigned, modified, wrong-publisher, wrong-architecture, unsupported
  downgrade, and known-vulnerable release candidates.
- [ ] Close every critical or high security finding or explicitly stop the
  release.

## Residual risks

Even after P0 controls pass:

- A Windows administrator or kernel-level attacker can read process memory,
  alter binaries and trust stores, impersonate users, and access protected
  secrets.
- A remote administrator can read an installed private key, change files after
  verification, forge remote evidence, or bypass the web-server configuration.
- Some remote filesystems and SFTP servers cannot offer portable,
  race-resistant atomic replacement and no-follow semantics. Such combinations
  must remain unsupported rather than receive a weaker silent fallback.
- A public probe from one client machine can be deceived by its DNS resolver,
  network route, local trust store, proxy, or malware. Multiple vantage points
  may be necessary for stronger assurance.
- DNS, CDN, reverse-proxy, and hosting diversity can make the apparent SSH host
  different from the actual TLS termination point.
- A certificate authority, domain account, DNS zone, or hosting account
  compromise is outside the client's ability to repair.
- The Windows machine may be asleep, offline, broken, or decommissioned during
  the renewal window. Alerts reduce but do not eliminate this availability
  risk.
- Operator mistakes, overbroad remote permissions, weak account recovery, and
  failure to revoke old credentials remain material operational risks.
- Signed software can still contain malicious or vulnerable code; signatures
  establish publisher identity and integrity, not correctness.

Support claims must reflect these residual risks and the exact tested connector
contract. Unknown platforms fail closed at diagnosis.

## Review triggers

Maintainers must update and review this document when:

- any non-health or mutating IPC method is proposed;
- the pipe authentication, DACL, authorization roles, or protocol changes;
- a secret type, vault implementation, credential handoff, export, backup, or
  recovery flow changes;
- the Windows service identity, privileges, installer, update mechanism, or
  filesystem ACLs change;
- an importer or supported WinSCP storage format is added or changed;
- an SSH, ACME, database, cryptography, installer, or signing dependency is
  selected or materially upgraded;
- a connector adds a path, remote operation, privilege, web-server recipe, or
  hosting-platform claim;
- another ACME challenge type, certificate authority, key algorithm policy, or
  production-directory flow is added;
- public verification, DNS resolution, proxy behavior, alerting, telemetry,
  crash reporting, or diagnostics change;
- a new Windows version or architecture is supported;
- an automatic updater, plugin system, community-loaded connector, hosted
  service, central web UI, or remote agent is proposed;
- a security incident, penetration test, external report, or dependency
  advisory changes an assumption; and
- each release candidate crosses from developer preview to private alpha,
  public beta, or stable support.

Security-boundary changes require explicit review and negative tests. Passing a
happy-path certificate renewal is not sufficient evidence.
