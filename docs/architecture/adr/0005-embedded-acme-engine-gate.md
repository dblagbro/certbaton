# ADR 0005: Use Anvil behind the CertBaton ACME boundary

- Status: Accepted as pre-alpha candidate; one public staging run passed;
  production gate open
- Date: 2026-07-29
- Updated: 2026-08-04
- Decision owners: CertBaton maintainers

## Context

CertBaton must create and maintain ACME accounts, orders, authorizations,
challenges, certificate keys, and renewal timing while running unattended as a
Windows Service. This is a security-sensitive protocol boundary with changing
server behavior, rate limits, and ecosystem support.

Calling a separately installed Certbot executable would make P0 depend on a
Python runtime, subprocess parsing, filesystem conventions, and an external
configuration lifecycle. Bundling a command-line client would still leave
CertBaton responsible for its patching, process isolation, secret locations,
and compatibility.

## Decision

Keep the CertBaton-owned `IAcmeEngine` boundary and use Webprofusion Anvil
3.3.3 as the first embedded pre-alpha implementation. No Anvil or other
third-party ACME type crosses the application boundary. The package and its
transitive dependencies are centrally pinned, locked, and attributed in the
third-party notices.

The Service, not Anvil, owns durable account and certificate-key references.
Account and certificate private-key material is loaded from or committed to the
selected vault through CertBaton interfaces. The live coordinator owns the CSR,
HTTP-01 placement, external pre-validation, cleanup, operation journal,
deployment, public verification, and final success rule.

The enrollment contract accepts only two symbolic authorities, which resolve
to the exact Let's Encrypt staging and production directory URLs. There is no
arbitrary ACME directory in the current public contract. The documented example
and every initial qualification run use staging. Selecting production is an
explicit administrator-authored enrollment choice, but it remains unsupported
until the production gate is separately approved.

Anvil was chosen for this first implementation because it supplies an embedded
.NET ACME v2 client under an MIT license and can be isolated behind the existing
boundary. This selection is reversible: the boundary and engine-neutral tests
remain the product contract, not the package API.

## Evidence present

The source tree contains adapter tests for account creation/reuse, order and
authorization mapping, challenge answer, finalization, error mapping, and
certificate result handling. The complete HTTP-01 coordinator has local
fake-workflow tests for success, cleanup, cancellation, verification failure,
and rollback-required outcomes.

On 2026-08-04, one manually authorized installed-Service run additionally
proved account/order interoperability with Let's Encrypt staging, a public
HTTP-01 route, issuance, cleanup, and durable success after a real Service
restart. It did not exercise the remaining protocol failures below or establish
production readiness.

## Open qualification gate

Before production issuance is enabled, automated or reviewed integration tests
must cover:

- account creation and reuse against the actual CA;
- HTTP-01 authorization success and cleanup;
- invalid authorization and challenge timeout;
- bad nonce and bounded retry;
- rate limiting and `Retry-After`;
- order polling, finalization, alternate chains, and revocation;
- network interruption and Service restart at each durable boundary;
- duplicate-trigger suppression;
- account-key and certificate-key rotation;
- external account binding if it becomes a supported requirement; and
- renewal scheduling with ACME Renewal Information or a documented safe
  fallback.

The current adapter uses fixed polling and does not yet expose complete
`Retry-After`, ACME Renewal Information, external account binding, revocation,
or alternate-chain policy through the CertBaton boundary. These are explicit
limitations, not silently inferred capabilities.

The dependency must also retain an acceptable maintenance and security-response
path, compatible licensing, reproducible source/package provenance, and prompt
patch handling. A material Anvil or transitive cryptography update triggers a
new review and repeat of the interoperability evidence.

## Consequences

- P0 does not invoke a user-installed Certbot or parse its console output.
- CertBaton accepts responsibility for testing, monitoring, and promptly
  updating the selected embedded implementation.
- Package popularity is not support evidence. Repeatable staging
  qualification, failure/recovery tests, vault lifecycle tests, and the
  production approval gate remain mandatory.
- A failed qualification may replace the adapter without changing the domain,
  IPC, vault, SSH, or deployment contracts.
