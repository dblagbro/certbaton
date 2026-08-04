# ADR 0010: UI-first enrollment over typed hosting connectors

- Status: Accepted for incremental implementation
- Date: 2026-08-04
- Decision owners: CertBaton maintainers

## Context

CertBaton is intended for designers, small web developers, and operators who
should not need to construct JSON, run a command-line client, or understand the
difference between certificate issuance and deployment plumbing. A desktop
application that merely displays CLI-created targets fails that product goal.

Hosting environments also differ materially. Some expose SSH with SFTP, some
offer SCP, some expose control-panel APIs such as cPanel, Plesk, or DirectAdmin,
and some terminate TLS at a provider or CDN API. File-transfer access alone
does not prove that a certificate can be activated or rolled back safely.

## Decision

The WPF desktop is the primary product surface for enrollment, inventory,
renewal, evidence, and recovery. The diagnostic CLI may exercise the same IPC
contracts during development, but no user-facing workflow may require it.

Enrollment begins with a friendly hosting-method choice. Each choice maps to a
registered connector descriptor with explicit capabilities:

- read-only connection testing;
- HTTP-01 challenge publication and cleanup;
- certificate transfer;
- activation;
- rollback; and
- independent public TLS verification.

A connector is shown as usable only when every capability required by the
selected renewal plan is implemented. Planned connectors may be named in the
UI to communicate direction, but their controls remain unavailable and they
cannot create a target. Unknown hosts or control panels never fall back to an
arbitrary shell command, guessed path, browser automation, or generic file
copy.

The first working connector is `ssh-sftp`. Its guided flow asks for a website
name, DNS name, contact email, hosting server, SSH username, and private-key
file. The Service performs a read-only authenticated probe, returns the
observed modern host key, and requires explicit confirmation before enrollment.
The key is persisted only after the test and confirmation. Technical Nginx
paths use a reviewed profile and live behind an advanced section.

`ssh-scp`, `cpanel-api`, `plesk-api`, and `directadmin-api` are registered as
planned connector kinds. Registration is not an implementation or support
claim. Each must supply its own authentication, capability diagnosis,
deployment, activation, rollback, verification, fixture, threat-model update,
and qualification evidence.

## Security rules

- Connection discovery is explicitly operator-initiated, read-only, bounded,
  and never treated as trust by itself.
- The UI displays the observed server identity and requires verification
  through the hosting provider or another trusted channel.
- Private-key request buffers are zeroed by the desktop IPC client and Service.
- Only modern allowlisted SSH host-key algorithms are offered during discovery.
- A successful transfer is insufficient; success still requires connector
  activation evidence, independent public TLS verification, and challenge
  cleanup.
- Community connectors cannot be loaded dynamically into the privileged
  Service in P0. New connectors are reviewed, compiled, versioned, and shipped
  with the application.

## Consequences

- The main window presents a multi-site inventory and an **Add website** entry
  point instead of CLI enrollment instructions.
- The installed desktop requests administrator elevation because current live
  IPC authorization is administrator-only. A future operator-group design may
  reduce this requirement without weakening Service ownership.
- WinSCP import becomes an optional convenience that pre-populates reviewed
  non-secret SSH fields; it is not the enrollment architecture.
- Supporting many backends means maintaining a deliberately versioned catalog,
  not claiming universal compatibility from SSH, SFTP, or SCP access alone.
