# First live staging qualification record

Date: 2026-08-04 UTC

Result: **Passed as pre-alpha evidence; no support or production claim**

## Purpose

This record documents the first manually authorized end-to-end exercise of the
installed CertBaton Windows client against a public ACME staging service and an
isolated remote Nginx target. It intentionally excludes target names, network
addresses, account names, SSH material, filesystem layouts, operation IDs,
certificate fingerprints, and other environment-specific data.

## Build under test

- Source revision: `bb31ba0e7f3b6a857b94876b291aef90f90ee7ed`
- Developer package archive SHA-256:
  `a3fa7d8ade981be67733125f87fb6021b9fa24511972329fd7b228153099dbbb`
- Client form: unsigned, self-contained Windows x64 developer package
- ACME environment: Let's Encrypt staging only
- Remote form: authorized Linux host with isolated Docker/Nginx runtime,
  exact-pinned SSH/SFTP, and the root-owned fixed helper contract

## Preconditions and containment

- The existing trusted runtime was inventoried before the exercise.
- A root-protected rollback package was created and its manifest verified.
- The test runtime was isolated from the existing Nginx and certificate-renewal
  containers.
- The remote helper and sudo policy exposed only fixed, typed operations.
- No production ACME order was requested.

## Result

The installed Windows Service completed the staging operation with terminal
status `succeeded`. The durable operation contained 19 ordered evidence
records, covering:

1. ACME account readiness and order creation;
2. HTTP-01 publication, independent public pre-validation, CA validation, and
   cleanup;
3. certificate-key persistence, finalization, inspection, and artifact
   persistence;
4. remote preparation, validation, activation, and verification;
5. exact staging-leaf and requested-name verification; and
6. helper commit and renewal success.

The independent public TLS probe matched the newly issued staging leaf.
Challenge cleanup was independently confirmed. After stopping and restarting
the installed Windows Service, the operation remained `succeeded`, both public
TLS and cleanup flags remained true, and all 19 evidence records reloaded from
durable state.

## Restoration and installer observations

The original trusted web runtime and renewal timer were restored after the
exercise. Its configuration and trusted certificate identity matched the
pre-exercise inventory, the public endpoint returned successfully, and the
root-protected rollback manifest still verified.

During package repair, four failures before the installer commit boundary
exercised rollback. Each restored the prior installed revision and running
Service without leaving a maintenance marker or partial snapshot. After the
installer defects were corrected, repair, deep audit, offline integrity audit,
Service health, and the post-renewal Service restart check passed.

## Test evidence for the revision

- Release build: zero warnings and zero errors
- Automated .NET tests: 300 passed; two opt-in tests skipped by the default run
- Real pinned-SSH opt-in tests: 2 passed
- Isolated Linux helper fixture: 11 passed
- Formatting, PowerShell syntax, package-script safety, and repository-boundary
  checks: passed

## What this does not prove

This is one successful staging order on one manually prepared target. It does
not establish a supported operating system, hosting provider, Linux/Nginx
layout, or account-permission profile. In particular, the exercise did not
complete the intended dedicated least-privilege account qualification.

The following gates remain open:

- production ACME issuance and deployment;
- clean supported-Windows-VM install, repair, upgrade, and uninstall matrices;
- real-target failure injection at every remote and network boundary;
- rollback failure, full-disk, hostile filesystem race, and process-kill tests;
- unattended scheduled renewal and deduplicated operator alerts;
- WinSCP metadata import, additional connectors, signing, MSI, provenance, and
  external security review.

The result therefore reduces interoperability uncertainty but does not change
CertBaton's pre-alpha, non-production status.
