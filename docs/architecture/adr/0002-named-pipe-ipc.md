# ADR 0002: Versioned named-pipe IPC

- Status: Accepted
- Date: 2026-07-29
- Decision owners: CertBaton maintainers

## Context

The desktop application and diagnostic CLI need to communicate with a
long-running Windows Service. The boundary may carry target metadata and request
security-sensitive operations. It must not become an implicit privilege bridge,
remote API, or unbounded deserialization surface.

## Decision

P0 uses `System.IO.Pipes` with a small, versioned, length-prefixed JSON protocol.
The wire contract is documented in
[`docs/protocols/ipc-v1.md`](../../protocols/ipc-v1.md).

The implementation must:

- create a local-only named pipe with an installer-reviewed DACL;
- deny network and anonymous SIDs in every security profile;
- give the installed service's exact `NT SERVICE\CertBaton` SID full-control
  server rights while giving local Users and Administrators only the client
  rights required for the health exchange;
- make that exact service SID the pipe owner and use an Owner Rights ACE to
  suppress implicit owner DACL-write access from a shared service account;
- restrict the console/development profile to the current Windows user;
- authenticate the installed server to each client before transmitting a
  request by comparing the connected pipe server PID with the running
  `CertBaton` process reported by Windows Service Control Manager;
- permit a separate expected-PID pin only inside the integration test assembly,
  never as a production fallback or configuration setting;
- have clients request Identification-level token access so the server can read
  the caller SID and role membership without gaining a token that can act as
  the caller;
- authorize every operation independently of the DACL and endpoint identity;
- use a fixed-width length prefix and a documented maximum frame size;
- parse UTF-8 JSON into explicit contract types;
- require protocol version, request ID, message type, and deadline;
- apply cancellation and operation-specific deadlines;
- return stable, sanitized error codes;
- use opaque secret references instead of secret values; and
- treat disconnects as cancellation signals, not proof that remote work was
  rolled back.

Raw named pipes are chosen over a larger RPC framework for P0 so that transport,
identity, framing, and compatibility remain explicit and auditable. The
protocol implementation belongs in its own assembly and is tested independently
from the UI and service.

The health-exchange implementation includes the two endpoint-identity checks
and a negative test that rejects a mismatched pipe server before request bytes
are sent. This does not complete the installed-service boundary. The installer
must still create and configure the exact service identity, and clean-machine
tests must qualify the SCM query, service SID, DACL, UI/CLI connection, and
service process lifecycle before release.

## Consequences

### Positive

- No listening TCP port or browser-origin security model is required.
- Clients bind the connected pipe endpoint to the running SCM-registered
  service process before sharing request data.
- The service reads the caller's Windows identity at Identification level
  without receiving delegation or impersonation authority.
- Installed-service and current-user development DACLs are separate rather than
  weakening the installed policy for console convenience.
- The initial health and status surface can remain small.
- Framing and compatibility behavior can be fuzzed and integration-tested.

### Costs and constraints

- The project owns framing, schema evolution, error mapping, and cancellation.
- Installed clients depend on the `CertBaton` SCM registration being available,
  running, and consistent with the pipe server process.
- Process-ID binding relies on Windows kernel and SCM integrity and is not
  intended to resist a local administrator or kernel compromise.
- The installer must configure the service SID and prove the installed DACL;
  source-level and integration-test evidence alone is insufficient.
- A pipe DACL alone is not sufficient; per-request authorization remains
  mandatory.
- JSON payloads must be bounded before allocation and deserialization.
- Long-running work needs durable job identifiers rather than holding a pipe
  request open indefinitely.
- An IPC timeout can discard a non-cooperative handler's late response and
  release the pipe slot, but cannot safely terminate arbitrary in-process work.
  Mutating operations must therefore enqueue durable work rather than execute
  inside the request handler.

## Rejected alternatives

- **Local HTTP server:** adds port, origin, proxy, and authentication concerns
  without improving the P0 local-only use case.
- **Pipe-name or ACL-only server trust:** does not authenticate the process that
  accepted the client connection and leaves clients exposed to pipe-name
  squatting.
- **Anonymous or ACL-only client trust:** does not provide adequate
  operation-level authorization.
- **In-process UI worker:** renewal would stop when the user closes or updates
  the UI.
- **Arbitrary .NET object serialization:** unsafe and unsuitable for a stable
  cross-version boundary.
