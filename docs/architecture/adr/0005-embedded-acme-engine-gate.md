# ADR 0005: Keep ACME embedded behind an evaluation gate

- Status: Proposed — blocking dependency decision
- Date: 2026-07-29
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
and compatibility. A lightly maintained .NET library creates a different risk:
the project could inherit stale protocol behavior without an adequate
interoperability suite.

## Direction

P0 will expose a CertBaton-owned `IAcmeEngine` boundary and use an embedded ACME
implementation. No third-party ACME type may cross that boundary.

The exact implementation is not selected by this ADR. Selection is blocked
until candidate source and package options are evaluated for:

1. ACME v2 interoperability and problem-document handling;
2. active maintenance, security response, and a credible update path;
3. license compatibility and complete attribution requirements;
4. deterministic testing against Pebble and Let's Encrypt staging;
5. account-key and certificate-key ownership under the Service vault;
6. cancellation, retry, nonce, rate-limit, and `Retry-After` behavior;
7. renewal-information support or a documented safe fallback;
8. dependency and native-code surface;
9. ability to pin and reproduce the exact reviewed source; and
10. isolation from UI, persistence, SSH, and connector domain models.

If the selected implementation is vendored or maintained as a source subtree,
the repository must record its upstream URL, exact commit, license, local
changes, update procedure, and conformance evidence. If a package is selected,
it must be centrally pinned and locked like other dependencies.

## Required interoperability evidence

Before production issuance is enabled, automated or reviewed staging tests must
cover:

- account creation and reuse;
- HTTP-01 authorization success and cleanup;
- invalid authorization and challenge timeout;
- bad nonce and bounded retry;
- rate limiting and `Retry-After`;
- order polling, finalization, alternate chains, and revocation;
- network interruption and service restart at each durable boundary;
- duplicate-trigger suppression;
- account-key and certificate-key rotation; and
- renewal scheduling with and without server-provided renewal information.

Production directory selection remains an explicit operator action until its
release gate is separately approved.

## Consequences

- P0 will not invoke a user-installed Certbot or parse its console output.
- ACME-dependent work may proceed against a simulator through `IAcmeEngine`,
  but a real engine cannot be merged as production-ready until this gate is
  resolved.
- CertBaton accepts responsibility for testing and promptly updating the chosen
  embedded implementation.
- A candidate's popularity is insufficient evidence; protocol behavior,
  maintenance, licensing, and recovery must all pass.
