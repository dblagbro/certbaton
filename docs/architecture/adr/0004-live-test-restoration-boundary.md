# ADR 0004: Live-site testing and restoration boundary

- Status: Accepted
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

CertBaton ultimately changes challenge files, certificate files, and service
configuration on remote systems. A realistic integration test may contend for
public ports, alter an active certificate path, or interrupt an existing edge
service. Even a test site can share infrastructure with unrelated applications.

A successful issuance is not evidence that the original service can be restored.
Recovery must be designed and verified before the first mutation.

## Decision

Local, containerized, and ACME-staging fixtures are the default. A public live
test is exceptional and requires an explicit maintenance plan approved by the
site owner.

Before a live test, the operator must:

- inventory affected services, listeners, mounts, scheduled jobs, watchers, and
  certificate paths;
- identify shared dependencies and unrelated services in the blast radius;
- create a current rollback package sufficient to reconstruct the original
  configuration and required artifacts;
- verify package integrity and rehearse or inspect the restoration procedure;
- record the known-good HTTP and public TLS baseline;
- define the exact resources CertBaton may stop or replace;
- establish a maintenance window, stop conditions, and responsible recovery
  operator; and
- prefer a separately named and isolated test fixture.

During the test:

- mutate only explicitly named resources;
- pause automation that could race with the test;
- do not use project-wide stop, delete, prune, or recreate commands when only a
  specific fixture is in scope;
- preserve the original service instance and data when practical; and
- retain an append-only event record without secrets.

Restoration is complete only after the original service is running, its
configuration validates, dependent automation is restored, and HTTP plus public
TLS checks match the expected post-restoration state.

## Repository boundary

Live-test inventories, credentials, private keys, private host names, user names,
network addresses, provider account data, raw recovery archives, and
machine-specific restoration commands do not belong in the public repository.

Public test documentation uses synthetic names and describes reusable controls,
not a particular operator's infrastructure.

## Consequences

- A maintenance window and rollback proof are test prerequisites, not optional
  polish.
- Shared edge services are treated as production-impacting even when the test
  host name itself is disposable.
- End-to-end tests must support clean interruption and targeted teardown.
- A test that issues a certificate but cannot restore the prior state fails.
- Connector design must expose preflight, staged mutation, verification,
  activation, and rollback as observable phases.
