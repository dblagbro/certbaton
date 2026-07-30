# CertBaton Windows Client Threat Model

Status: **pre-alpha working threat model**

This document describes the security boundaries of the open-source CertBaton
Windows client. It is an engineering review artifact, not a claim that the
planned certificate workflow is implemented or safe for production.

CertBaton currently implements only a Windows desktop shell, a service host, a
diagnostic CLI, and a read-only health exchange over a local named pipe. It does
not yet persist configuration or secrets, import address books, connect to
remote hosts, communicate with an ACME service, issue certificates, deploy
files, activate a web server, verify a public endpoint, install a Windows
service, or update itself.

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
- The intended service identity, protected secret vault, local database, logs,
  and diagnostic exports.
- Opt-in import of non-secret connection metadata from WinSCP.
- Intended outbound SSH/SFTP connections and typed remote operations.
- Intended ACME v2 and HTTP-01 issuance workflow.
- Intended certificate staging, activation, rollback, scheduling, alerting, and
  public TLS verification.
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

### Flow 0: local health exchange

**Implemented.** A local client sends one bounded, versioned JSON request. The
client first obtains the connected pipe server's process ID and requires it to
match the running process registered with Windows Service Control Manager for
the `CertBaton` service. Only then does it send the request. The service obtains
the caller's Windows SID under the client's Identification-level token,
validates the request, and returns a bounded health response. No secret or
mutating method exists.

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

**Planned.** An operator selects a WinSCP source, previews supported non-secret
fields, confirms each imported connection, separately establishes trust in the
remote host key, and enrolls credentials through an approved protected handoff.
The protected handoff is **gated** on the vault design.

### Flow 2: scheduled issuance

**Planned and gated.** The service loads a target and opaque secret references,
acquires a durable per-target lock, performs read-only preflight checks, creates
or resumes an ACME order, writes a narrowly scoped HTTP-01 token through SFTP,
checks that token over the public HTTP route, asks the ACME service to validate,
finalizes the order, and cleans up the token. The embedded ACME engine and
secret vault are separate blocking gates.

### Flow 3: deployment, activation, and verification

**Planned.** The service verifies certificate/key pairing, backs up the current
state, uploads to temporary locations, validates paths and file attributes,
runs only connector-defined activation operations, validates the web-server
configuration, replaces files atomically where the qualified platform permits,
reloads, and probes the public TLS endpoint independently of SSH. Failure
initiates a typed rollback. Success is recorded only after endpoint evidence
matches the order.

### Flow 4: installation and manual upgrade

**Planned and gated.** A machine-wide signed installer creates the service
identity, service registration, access-controlled data locations, and event
source. P0 upgrades are manually initiated; P0 has no automatic privileged
updater. Toolchain, signing, provenance, repair, rollback, and uninstall
behavior must pass release gates.

## Trust boundaries

| Boundary | Trusted side | Untrusted or less-trusted side | Required decision |
| --- | --- | --- | --- |
| UI/CLI to service | SCM-registered service process and service authorization policy | Any local process that can discover or squat the pipe name | Endpoint authentication exists for health; qualify the installed-service profile and authorize every future operation |
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

- **Implemented now:** the only IPC method is read-only health; the current IPC
  DTOs cannot carry a certificate key, SSH credential, password, or arbitrary
  log.
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
- **Planned:** future IPC uses opaque secret references, never reusable secret
  values in general request, response, status, or diagnostic messages.
- **Planned:** the service owns schedules, locks, secrets, remote operations,
  and durable run state. Closing the UI cannot transfer or cancel ownership
  implicitly.
- **Implemented/planned:** endpoint authentication exists for the health
  exchange. Every future mutating operation must additionally authorize the
  caller for that operation, use a deadline, and have a durable idempotency
  rule.
- **Planned:** a first-seen SSH host key requires explicit operator review. A
  changed pinned key is a hard stop during unattended work.
- **Planned:** remote paths remain inside connector-declared roots after
  normalization and filesystem inspection. User text is never concatenated
  into a shell command.
- **Planned:** production ACME use requires an explicit transition from staging
  and cannot be selected accidentally by importing metadata.
- **Planned:** access loss cannot delete or replace the currently active
  certificate.
- **Planned:** activation is preceded by certificate/key pairing and
  web-server configuration checks.
- **Planned:** deployment success requires a public TLS handshake that matches
  the enrolled hostname and expected issuance evidence.
- **Planned:** failure to prove activation or rollback is a visible critical
  state, never a successful or merely warning state.
- **Gated:** no real credential may be persisted until the service-compatible
  secret-vault design passes its lifecycle and adversarial tests.
- **Gated:** no public release may claim a supported remote recipe until its
  positive, negative, interrupted-operation, and rollback evidence passes.

## STRIDE analysis and controls

### Windows UI, CLI, service, and named pipe

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A client puts a privileged username or SID in JSON. | **Implemented:** the client requests an Identification-level token; the server briefly reads the connected Windows token's SID and role membership; JSON identity is not accepted. Anonymous and network SIDs are denied by both pipe security profiles. | Add explicit unauthorized-local and remote-attempt tests. Review behavior under filtered UAC tokens. |
| Spoofing | A local process creates a look-alike pipe before the genuine service and returns a false response or captures future requests. | **Implemented/partial:** before writing any request bytes, the client obtains the connected pipe server PID and requires an exact match with the running `CertBaton` process reported by Windows Service Control Manager. A negative integration test proves a mismatched pipe squatter is rejected before receiving request data. Tests use a separate internal expected-PID pin, not a production bypass. | Qualify the real registered service, exact service SID, installed DACL, stop/restart behavior, and relevant PID/process races through the installer on a clean machine. |
| Tampering | A client sends malformed, ambiguous, deeply nested, oversized, truncated, or version-confused JSON. | **Implemented/partial:** fixed-length framing, size and depth limits, strict explicit DTOs, duplicate and unknown property rejection, exact version checks, and sanitized protocol errors exist. | Complete malformed UTF-8, partial read, exact-boundary, missing-field, fuzz, and disconnect tests. |
| Repudiation | A user denies requesting a certificate or changing a target. | **Not applicable to current health method. Planned:** record caller SID, request identifier, action, target identifier, approval basis, timestamps, and outcome without secrets. | Define audit schema, retention, clock handling, export, and administrator-tampering limitations. |
| Information disclosure | Health or error responses reveal paths, stack traces, credentials, target inventory, or internal state. | **Implemented/partial:** current health contract contains only status, version, and timestamps; internal exceptions map to a fixed error. | Review version disclosure policy. Add response-field and log-redaction tests before adding target operations. |
| Denial of service | A local process opens connections, stalls reads/writes, or sends expensive frames until the service cannot schedule renewals. | **Implemented/partial:** bounded frames, a finite client limit, per-client timeout, cancellation, stalled-client coverage, and rejection of late success from a non-cooperative handler exist. A late handler is observed but cannot retain the pipe slot. | Load-test saturation, slow readers/writers, repeated reconnects, shutdown, memory use, and fairness. Mutating work must be a durable job outside the IPC handler so ignored cancellation cannot continue an unsafe detached mutation. Reserve certificate work from IPC starvation. |
| Elevation of privilege | Any member of the local Users group invokes a future mutating method through the health-only ACL. | **Current safe limitation:** no mutating method exists. **Planned:** installer-created Operator and Administrator roles plus operation-level authorization. The current broad health ACL is not sufficient. | Negative tests for every method and role, including filtered tokens, disabled users, service repair, and ACL drift. |
| Elevation of privilege | Replay or duplicate submission starts more than one order or activation. | **Planned:** durable idempotency key, per-target lock, one active order, request deadlines, and state-machine checks. A request ID alone is not authorization or idempotency. | Crash/restart and concurrent-trigger tests at every stage. |

The service must treat a pipe disconnect as loss of the requester, not proof
that already-started remote work was cancelled or rolled back.

### Service identity and protected secret vault

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing / EoP | The service runs with unnecessary privilege or another process impersonates its storage identity. | **Partial/gated:** the installed pipe profile names only the exact `NT SERVICE\CertBaton` SID for full-control server rights. The installer-created identity, service SID type, privileges, executable ACL, and data access are not implemented or qualified. | Verify the registered service, token, privileges, SID type, pipe and executable ACLs, service-control ACL, and behavior after repair and upgrade. |
| Information disclosure | Another local user reads encrypted records, keys, memory, swap, crash dumps, or backups. | **Gated:** evaluate service-bound DPAPI-NG; a dedicated service account with user-scoped protection may be evaluated as fallback. Plaintext, reversible obfuscation, hard-coded keys, and broad machine-scope protection are prohibited. | Prove cross-user denial, unattended reboot access, memory minimization, dump policy, backup behavior, and the documented local-administrator limitation. |
| Tampering | An unprivileged process replaces an encrypted secret record or protection descriptor. | **Gated/planned:** authenticated protected records, restrictive ACLs, immutable identifiers, and integrity checks. | Replace, rollback, swap, truncation, and ACL-change tests. Bind secret references to type and owning connection. |
| Denial of service | Upgrade, account change, machine rejoin, or uninstall makes secrets permanently unreadable. | **Gated:** recovery, rotation, revocation, backup, deletion, repair, and upgrade are part of the vault decision. | Full lifecycle tests with the actual installer-created identity. Fail clearly without silently creating new credentials. |
| Repudiation | A secret is replaced or deleted without attribution. | **Planned:** audit the secret identifier, type, actor, reason, and result; never record the value. | Verify audit coverage and recovery events. |

A Windows-local vault cannot promise protection against an administrator who
controls the machine. The objective is least privilege, isolation between
ordinary users and unrelated processes, and clear recovery behavior.

### Local database, logs, diagnostics, and alerts

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Tampering | Database edits alter host pins, schedules, approvals, checkpoints, or success evidence. | **Planned:** service-only write access, transactional migrations, constrained records, monotonic state transitions, and consistency checks. | Mutation tests, downgrade tests, crash injection, backup restore, and detection of impossible state transitions. |
| Information disclosure | Database, logs, Event Log entries, support bundles, or alerts expose secrets or a detailed customer inventory. | **Current limitation:** no target database or target logging exists. Current service log messages are fixed. **Planned:** classification and redaction at event creation, opaque IDs, allowlisted export fields, and explicit export preview. | Seed canary secrets into every field and prove they do not appear in logs, errors, exports, notifications, crash output, or process arguments. |
| Repudiation | A local administrator changes or deletes local evidence. | **Residual:** local records can support operations but are not tamper-proof against an administrator. **Planned:** structured event IDs and continuity checks make accidental or unprivileged alteration visible. | Document evidence limits; do not market local audit data as non-repudiation. |
| Denial of service | Corruption, unbounded history, log flooding, disk exhaustion, or concurrent writers stop renewals. | **Planned:** bounded retention, one database writer, disk-space checks, WAL/checkpoint policy, rate-limited events, and degraded-but-visible behavior. | Fault injection for full disk, locked/corrupt database, interrupted migration, and alert storms. |
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
| Spoofing | A network attacker or rebuilt server presents a different SSH host key. | **Planned:** explicit first-use review, exact pin storage, modern algorithm policy, and a hard stop on mismatch during unattended runs. No automatic pin replacement. | Tests for changed keys, multiple host-key algorithms, rotation ceremony, aliases, and concurrent enrollment. |
| Tampering | User-controlled text is interpolated into a remote shell command. | **Planned invariant:** prefer SFTP operations; expose a small typed operation vocabulary; never concatenate untrusted values into shell syntax. If elevation is required, use an independently reviewed fixed remote helper or equally narrow contract. | Injection corpus for names, paths, whitespace, control characters, quoting, encodings, and option-like arguments. |
| Tampering | A remote path escapes the approved root through traversal, separators, encoding, case behavior, or a symlink. | **Planned:** connector-owned roots, canonical relative components, reject traversal and ambiguous names, inspect each path component, reject links where a regular file/directory is required, use unpredictable staging names, and re-check attributes before commit. | A hostile SFTP fixture must exercise symlink swaps, hard links where relevant, rename races, mount changes, and time-of-check/time-of-use behavior. |
| Tampering | A hostile server changes bytes after upload or lies through command output. | **Planned:** bound all output, parse only operation-specific formats, treat output as data, upload to temporary names, verify size and cryptographic digest, then perform typed replacement. | Malformed, truncated, delayed, reordered, control-character, and false-success output tests. |
| Information disclosure | Credentials, private keys, remote output, filenames, or environment data leak into command lines, logs, UI, diagnostics, or temporary files. | **Planned/gated:** vault-backed credentials, in-memory handoff, bounded redacted output, restrictive temporary-file handling, and cleanup evidence. | Canary-secret tests across authentication failures, exceptions, cancellation, dumps, and exports. |
| EoP | A broad sudo rule, shell, container-engine membership, or privileged remote account turns CertBaton into arbitrary root execution. | **Gated:** define the minimum remote privilege contract per typed connector. Direct root-equivalent container-engine access and arbitrary scripts are excluded from P0. | Review the exact remote authorization rule and prove rejected verbs, arguments, paths, callers, and environments. |
| Denial of service | A hostile or slow server holds connections, returns unbounded data, or interrupts an atomic change. | **Planned:** connection and operation deadlines, byte limits, cancellation boundaries, finite retries, checkpointing, and a global concurrency limit. | Slow-server, partial-transfer, disconnect, reboot, and saturation tests. |
| Repudiation | Remote changes cannot be tied to a connector operation. | **Planned:** record typed operation, target ID, pinned key fingerprint, hashes, timestamps, caller approval, and sanitized result. | Compare local evidence with remote fixture evidence; document that a hostile administrator can forge remote-side logs. |

Path and symlink checks reduce mistakes and attacks by a constrained remote
account. They cannot make a hostile remote administrator trustworthy: that
actor can change the filesystem or web server after any check.

### ACME and HTTP-01

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A configured or redirected ACME directory impersonates the intended certificate authority. | **Gated/planned:** select the ACME engine; require HTTPS with normal certificate validation; make the directory and environment explicit; disallow silent downgrade or validation bypass. | Protocol conformance, redirect, bad-certificate, alternate-chain, and endpoint-change tests. |
| Spoofing | Public HTTP pre-validation reaches a proxy, stale cache, wrong virtual host, or attacker-controlled route. | **Planned:** use the exact enrolled hostname and token path, compare exact expected content, constrain redirects, and preserve resolver/address evidence. | Test redirects, IPv4/IPv6 differences, proxies, CDN caching, wrong virtual hosts, and split DNS. |
| Tampering | A token name or webroot escapes the HTTP-01 challenge directory or overwrites site content. | **Planned:** construct the challenge filename from validated ACME protocol data, bind it to one authorization, use a connector-declared webroot, reject separators/traversal, verify after write, and remove only the exact owned artifact. | Malicious token/path corpus and cleanup tests on success, error, cancellation, and restart. |
| Information disclosure | ACME account or certificate private keys appear in protocol logs, challenge files, exports, or IPC. | **Gated/planned:** vault-only key storage, explicit secret types, redacted ACME adapter, and public-token-only challenge content. | Canary-secret tests for every ACME problem and network failure. |
| Denial of service | Duplicate triggers or aggressive retry exhaust CA rate limits or leave tokens behind. | **Planned:** one active order per target, persisted order state, renewal jitter, bounded backoff, server-provided retry handling, cleanup reconciliation, and staging by default. | Concurrency, restart, bad nonce, rate-limit, timeout, and abandoned-order tests. |
| EoP / abuse | A local user asks the privileged service to probe internal systems or request certificates for unauthorized names. | **Planned:** operation-level local authorization, explicit enrolled targets, ownership acknowledgement, constrained outbound destinations, preflight proof, and audit. ACME validation remains necessary but is not the only authorization control. | Tests that health-only users cannot create targets or jobs; document operator accountability. |
| Repudiation | Terms acceptance, account creation, production selection, or issuance cannot be attributed. | **Planned:** record actor, directory identity, account reference, terms URI/version where available, target, order URL reference, certificate fingerprint, and result without key material. | Review privacy and retention; test explicit staging-to-production approval. |

An ACME challenge demonstrates control under the CA's policy at that moment. It
does not establish business ownership or repair compromised DNS and hosting.

### Typed activation, rollback, and public TLS verification

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Tampering | A certificate is paired with the wrong key, uploaded with unsafe permissions, or placed in the wrong target. | **Planned:** compare public keys before activation, verify chain and names, use restrictive permissions, hash uploads, and bind every artifact to a target and run. | Mismatch, cross-target swap, permission, stale-file, and corrupted-upload tests. |
| EoP | Activation parameters escape the typed recipe or invoke arbitrary commands. | **Planned/gated:** connector-defined operations and narrow remote privilege contract; no user-provided shell scripts. | Schema allowlist, parameter injection, unsupported-operation, and privilege-rule tests. |
| Denial of service | Validation, replacement, reload, or rollback fails and takes down a working site. | **Planned:** preflight, bounded backup, configuration validation, atomic replacement where supported, safe reload, checkpointed rollback, and explicit rollback-required state. | Failure injection before and after every boundary, including rollback and reload failure. |
| Spoofing | The remote command reports success while the public endpoint still serves the old or an attacker's certificate. | **Planned:** a separate public TLS connection validates SNI/hostname, expected leaf identity or fingerprint, chain, validity, and presented endpoint evidence. SSH success is never sufficient. | Test stale reload, wrong virtual host, reverse proxy/CDN termination, multiple addresses, and chain errors. |
| Tampering | Local DNS or network interception makes the “independent” public probe observe the wrong endpoint. | **Planned/partial assurance:** the probe is independent of the SSH deployment channel, not necessarily of the client network or resolver. Record resolved addresses and handshake evidence. | Decide whether supported releases need multiple network vantage points. Document this residual risk in the UI and support claims. |
| Repudiation | The UI shows healthy without evidence of which certificate was live. | **Planned:** store the expected and observed fingerprints, names, chain result, validity, addresses, timestamps, connector plan version, and final state. | Evidence-schema review, UI traceability test, and clock-skew test. |
| Information disclosure | Rollback archives or staged private keys remain readable or accumulate indefinitely. | **Planned:** restrictive ownership/mode, bounded retention, run-scoped names, verified cleanup, and explicit handling when cleanup fails. | Remote permission, orphan reconciliation, backup expiry, and deletion evidence tests. |

Independent verification means independent of the deployment channel. A probe
from the same Windows machine remains exposed to its resolver, route, trust
store, and local malware.

### Installer, manual update, and software supply chain

| Category | Threat | Controls and status | Required evidence or remaining work |
| --- | --- | --- | --- |
| Spoofing | A user installs a counterfeit or tampered package. | **Gated/planned:** signed release artifacts, published hashes, an authoritative release source, and clear publisher identity. No supported installer exists today. | Verify valid, unsigned, modified, expired/revoked-signature, wrong-architecture, and wrong-publisher packages. |
| Tampering | A dependency, build action, runner, artifact handoff, or maintainer account injects code. | **Planned:** locked dependencies, review, least-privilege CI, pinned actions, secret scanning, dependency and license review, SBOM, provenance, protected release environments, and reproducible evidence. | Threat-model CI credentials; test artifact/source linkage; require review for security-boundary and dependency changes. |
| EoP | Installer ACLs, an unquoted service path, writable executable directory, custom action, or DLL search path gives local privilege escalation. | **Gated/planned:** conventional machine-wide MSI, immutable installed binaries for ordinary users, restricted service-control ACL, no user-writable search path, and minimal privileged custom actions. | Clean-VM ACL audit and local privilege-escalation tests after install, repair, upgrade, rollback, and uninstall. |
| Information disclosure | Installer logs, repair data, crash dumps, or uninstall leave credentials behind. | **Gated/planned:** secrets are never installer properties or command-line values; MSI logs are treated as untrusted for secrets; uninstall asks whether to retain or securely remove operational data. | Canary-secret install/repair/upgrade/uninstall tests and documented deletion limits. |
| Denial of service | Upgrade corrupts the database, changes service identity, loses vault access, or cannot roll back. | **Gated/planned:** transactional migrations, identity-preserving repair/upgrade, downgrade protection, preflight, and installer rollback. | Upgrade from every supported version with service interruption and rollback injection. |
| Repudiation | A release cannot be traced to reviewed source and its dependency set. | **Planned:** provenance, signed tags/artifacts, SBOM, checksums, and retained release evidence. | Independent verification from a clean environment. |
| EoP | An automatic updater becomes a persistent privileged code-execution channel. | **P0 exclusion:** P0 has only operator-initiated MSI upgrades. | Any future automatic updater requires a new design review and threat-model section. |

Open-source publication improves reviewability but does not itself establish
provenance, trustworthiness, or secure update delivery.

## Abuse cases

| Abuse case | Expected safe result | Status |
| --- | --- | --- |
| A standard local user sends a forged administrator field in JSON. | The field has no authority; the service uses the Windows token. | **Implemented for health** |
| A local process starts a counterfeit service pipe before the real service. | Before sending a frame, UI/CLI compares the connected server PID with the running SCM-registered `CertBaton` service process and rejects a mismatch. | **Implemented with negative test; installed-service qualification gated** |
| A local user floods the pipe with stalled connections. | Slots expire; renewal work and service shutdown remain responsive. | **Partial** |
| A malicious WinSCP entry contains a password, command hook, traversal path, or misleading host key. | Only allowlisted non-secret fields appear in preview; no state changes until explicit confirmation; executable fields are ignored. | **Planned** |
| A host presents a new SSH key during an unattended renewal. | The run stops, preserves the active certificate, and alerts for explicit review. | **Planned** |
| A hostname or path contains shell metacharacters or an option-like prefix. | No shell string is constructed; typed validation rejects unsupported input. | **Planned** |
| A remote symlink is swapped between path inspection and certificate replacement. | The connector detects the change or refuses a platform that cannot provide the required safe primitive; the old deployment remains active or rollback is required. | **Planned with residual risk** |
| A remote server emits enormous output, terminal control codes, or a false success message. | Output is bounded and escaped; only typed results and independent evidence affect state. | **Planned** |
| Multiple triggers start orders for one target. | One durable run owns the target; duplicates observe or join its state without creating another order. | **Planned** |
| A challenge token is crafted as a path traversal. | It is rejected before remote I/O; cleanup cannot delete an unrelated file. | **Planned** |
| Configuration validation succeeds but reload serves the old certificate. | Public verification fails; the run cannot be marked successful and follows the reviewed recovery policy. | **Planned** |
| Activation and rollback both fail. | A critical rollback-required state is persisted and alerted; evidence is retained without claiming success. | **Planned** |
| A forged or downgraded installer is offered to the user. | Signature, publisher, architecture, and version policy reject it. | **Planned/gated** |
| A diagnostic bundle contains a seeded credential. | Export fails closed and identifies the offending field without exposing its value. | **Planned** |
| An operator enrolls a system they do not own. | The product requires local authorization and ownership acknowledgement, records the actor, and still relies on protocol validation; it does not claim to adjudicate legal ownership. | **Planned with operator residual risk** |

## Verification checklist

### Evidence present in the pre-alpha source tree

- [x] Only the health method is registered; it is read-only.
- [x] Current IPC contracts contain no credential or certificate material.
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
- [x] No production secret persistence, importer, SSH, ACME, deployment, or
  installer code exists to create a false production-readiness claim.

### Required before adding sensitive or mutating IPC

- [ ] Qualify server-PID validation against a genuinely installed and running
  service, including stop, restart, unavailable-SCM, and process-race cases.
- [ ] Qualify the exact service SID and installed-service DACL through the real
  installer on a clean supported Windows machine.
- [ ] Create installer-owned Operator and Administrator groups or an equivalent
  explicit authorization model.
- [ ] Authorize every method against the caller token; test standard,
  elevated, filtered, disabled, anonymous, and remote identities.
- [ ] Add durable job idempotency, request audit, cancellation semantics, and
  safe reconnect behavior.
- [ ] Complete IPC fuzzing, malformed UTF-8, partial frame, saturation, shutdown,
  and redaction tests.

### Required before storing real secrets

- [ ] Accept the vault ADR using the final service identity.
- [ ] Prove unattended decrypt after logoff and reboot and denial to a different
  ordinary user.
- [ ] Test record substitution, ACL tampering, repair, upgrade, backup, restore,
  rotation, revocation, and uninstall.
- [ ] Document memory, dump, administrator, machine-change, and unrecoverable
  secret risks.
- [ ] Pass canary-secret tests across IPC, logs, alerts, diagnostics, errors,
  arguments, and installer output.

### Required before a real SSH/SFTP target

- [ ] Pass explicit host-key enrollment, mismatch, and rotation tests.
- [ ] Accept the narrow remote privilege contract.
- [ ] Prove command-injection resistance with a hostile input corpus.
- [ ] Prove remote-root confinement and exercise traversal, symlink, rename,
  hard-link, and time-of-check/time-of-use attacks in a hostile fixture.
- [ ] Bound authentication, transfer, output, retries, concurrency, and cleanup.
- [ ] Verify independently enrolled credentials can be revoked independently.

### Required before ACME staging or production

- [ ] Select and threat-model the embedded ACME engine and dependency chain.
- [ ] Complete protocol, TLS, redirect, bad nonce, retry, rate-limit,
  concurrency, restart, and problem-response tests.
- [ ] Prove exact HTTP-01 placement, external pre-validation, and cleanup under
  success and every injected failure.
- [ ] Require an explicit, audited transition from staging to production.
- [ ] Prove account and certificate keys exist only through the accepted vault.

### Required before a supported deployment recipe

- [ ] Validate certificate/key pairing, chain, names, remote modes, ownership,
  upload digest, web-server configuration, and typed activation.
- [ ] Inject failure at every stage and prove the previous working deployment is
  preserved or restored.
- [ ] Prove a stale or wrong public certificate is a failure even after
  successful upload and reload.
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
