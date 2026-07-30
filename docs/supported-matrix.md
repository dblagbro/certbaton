# Supported and planned matrix

CertBaton has no supported production release. This matrix separates the P0
engineering target from future evaluation and known exclusions. A planned cell
is not a compatibility claim.

Legend:

- **P0 target** — intended to be implemented and qualified before the first
  public preview.
- **Evaluate later** — useful, but no release commitment.
- **Not P0** — deliberately outside the first client milestone.
- **Not applicable** — the platform does not expose the required integration.

## Local client

| Area | Platform | Status | Notes |
| --- | --- | --- | --- |
| Operating system | Windows 11 x64 | P0 target | Desktop UI, Windows Service, and installer |
| Operating system | Windows 10 | Not P0 | No implied support after Microsoft's general end of support |
| Operating system | Windows Server | Evaluate later | Requires separate service, UI, and installer qualification |
| Architecture | Windows on ARM64 | Evaluate later | No P0 artifact or emulation promise |
| Operating system | Linux or macOS | Not P0 | Shared libraries do not imply a supported client |
| UI | WPF desktop | P0 target | Setup, status, review, and recovery guidance |
| Background execution | Windows Service | P0 target | Owns schedules and durable jobs |
| Address-book import | WinSCP non-secret metadata | P0 target, pending spike | Opt-in; never silently imports/decrypts stored passwords |
| Address-book import | Other applications | Evaluate later | One reviewed importer at a time |

## Certificate validation and issuance

| Area | Method | Status | Notes |
| --- | --- | --- | --- |
| ACME protocol | ACME v2 | P0 target | Staging qualification precedes production use |
| Certificate authority | Let's Encrypt | P0 target | Other ACME CAs require separate qualification |
| Domain validation | HTTP-01 | P0 target | Requires public HTTP reachability and compatible document-root access |
| Domain validation | DNS-01 | Not P0 | No wildcard certificates in P0 |
| Domain validation | TLS-ALPN-01 | Not P0 | Not part of the first connector model |
| Key algorithm | ECDSA or RSA | Pending design validation | Final preview policy will document defaults and compatibility |

## Remote access and activation

| Area | Platform or method | Status | Notes |
| --- | --- | --- | --- |
| Transport | SSH/SFTP to an OpenSSH-compatible Linux host | P0 target | Explicit host-key pinning is required |
| Transport | SCP | Not P0 | SFTP is preferred for typed file operations |
| Transport | FTP/FTPS | Not P0 | Different trust and credential model |
| Transport | Hosting-provider API | Evaluate later | Requires a maintained, provider-specific connector |
| Web server | Nginx filesystem layout | P0 target fixture | Exact qualified layouts will be narrower than all Nginx installs |
| Web server | Apache HTTP Server | Evaluate later | Requires a typed activation and rollback profile |
| Web server | IIS | Evaluate later | Local Windows server management is a separate connector |
| Activation | Arbitrary remote shell script | Not P0 | Typed, bounded connector operations only |
| Verification | Independent public TLS handshake | P0 target | Deployment-channel success alone is insufficient |

## Hosting environment fit

| Environment | Status | Reason |
| --- | --- | --- |
| Small VPS or dedicated host with authorized SSH/SFTP and certificate control | P0 target profile | Required paths and activation must match a qualified connector |
| Shared hosting with SSH/SFTP and user-managed certificate files | P0 target candidate | Must permit HTTP-01 and a safe activation mechanism |
| WordPress on compatible SSH-accessible hosting | Candidate, hosting-dependent | WordPress itself does not install the edge TLS certificate |
| Control panel with only a proprietary certificate API | Evaluate later | Needs a provider connector, not file guessing |
| Fully managed site builder with no certificate-install control | Not applicable | Use the platform's managed TLS feature |
| CDN or reverse proxy that terminates TLS | Evaluate later | Certificate must be managed at the actual TLS endpoint |

## Notifications

| Channel | Status | Notes |
| --- | --- | --- |
| Desktop status and actionable error state | P0 target | UI may be closed when work runs |
| Windows Event Log | P0 target | Structured and redacted |
| Windows toast notification | P0 target, pending service/UI design | Must work without leaking target details |
| Email, SMS, chat, or webhook | Evaluate later | Requires credential, retry, and abuse controls |

## Qualification rule

A platform becomes supported only when its exact version range and connector
contract have:

1. a reproducible fixture;
2. positive, negative, interrupted-operation, and rollback tests;
3. documented required permissions and paths;
4. public-TLS verification;
5. an owner for security and compatibility updates; and
6. release notes naming the qualified combination.

Community reports are valuable evidence, but they do not expand the supported
matrix by themselves.
