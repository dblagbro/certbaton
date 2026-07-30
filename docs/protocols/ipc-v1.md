# CertBaton local IPC protocol v1

Status: **Implemented draft for the P0 health exchange**

This document describes the current local protocol between the CertBaton
Windows Service and the desktop application or diagnostic CLI. It is not a
remote API or a public compatibility promise.

## Transport and endpoint identity

- Transport: local Windows named pipe `CertBaton.Service.v1`.
- Production client server: the SCM-registered CertBaton Windows Service.
- Development server: a console-mode host exercised by the integration tests;
  production Desktop and CLI clients do not trust a console process.
- Remote and anonymous access: explicitly denied by the pipe DACL.
- Current operation: a read-only health request available to authenticated
  local users.
- Client authentication of the installed service: after connecting, and before
  sending a request, the client obtains the pipe server's process ID. It queries
  Windows Service Control Manager for the running process registered as the
  `CertBaton` service and requires an exact process-ID match.
- Service authentication of the client: the client requests
  Identification-level token access. The server briefly reads that token to
  obtain the caller's Windows SID, administrator-group result, and
  impersonation level. Identity values in JSON are never trusted. The service
  does not receive a token that permits it to act as the caller.

The installed-service health DACL is protected from inherited rules. It denies
the network and anonymous SIDs, permits local Users and Administrators the
client read/write rights needed for the exchange, and grants full-control
server rights and object ownership to the exact `NT SERVICE\CertBaton` SID. An
Owner Rights ACE removes an owner's implicit DACL-write authority and grants
only permission inspection; the exact service SID receives its required rights
through its explicit ACE. This prevents a shared service account from regaining
pipe-instance creation through default object ownership. It does not grant
broad server ownership to Local System or Local Service.

The console/development security profile also denies network and anonymous
SIDs, but grants access and pipe ownership only to the current Windows user. An
internal expected-server-process-ID option exists solely for the integration
test assembly so that a test host can be pinned without an installed Windows
service. It is not a production setting or a server-authentication bypass.

The endpoint-authentication code and negative tests exist. The actual SCM
registration, service SID type, installed DACL, and service process lifecycle
have not yet been created and qualified by a real installer on a clean machine.
That evidence remains a release gate.

Before a mutating operation is added, the installer and service must establish
narrower Operator and Administrator authorization and test filtered UAC
tokens. Knowing the pipe name, being a local User, or passing endpoint
authentication is never authorization for a mutating operation.

## Framing

Each message is one frame:

```text
4-byte little-endian positive payload length
N bytes of UTF-8 JSON payload
```

Implemented rules:

- payload length is between 1 and 65,536 bytes;
- JSON nesting depth is at most 32;
- comments, trailing commas, unknown properties, duplicate property names, JSON
  `null` messages, malformed JSON, and truncated frames are rejected;
- JSON property matching is case-sensitive;
- one request and one response are exchanged per connection;
- a client has five seconds to complete the health exchange before its
  connection slot is released.

The protocol must never carry certificate private keys, SSH credentials,
passwords, arbitrary logs, or recovery archives.

## Health request

```json
{
  "protocolVersion": 1,
  "requestId": "31ee6769-0ad0-4c47-95b2-e3d7601d663c",
  "method": "health",
  "sentAtUtc": "2026-07-29T20:00:00Z",
  "deadlineUtc": "2026-07-29T20:00:03Z"
}
```

| Field | Rule |
| --- | --- |
| `protocolVersion` | Must equal `1` |
| `requestId` | Non-empty UUID; correlates this request and response |
| `method` | Exact, case-sensitive registered method; currently only `health` |
| `sentAtUtc` | Timestamp within the allowed local clock window |
| `deadlineUtc` | Later than `sentAtUtc`, in the future, and no more than 30 seconds ahead |

The request ID is not an authorization token or an idempotency guarantee.

## Successful health response

```json
{
  "protocolVersion": 1,
  "requestId": "31ee6769-0ad0-4c47-95b2-e3d7601d663c",
  "success": true,
  "result": {
    "status": "healthy",
    "serviceVersion": "0.1.0-dev",
    "startedAtUtc": "2026-07-29T19:55:00Z",
    "respondedAtUtc": "2026-07-29T20:00:00Z"
  },
  "error": null
}
```

## Error response

```json
{
  "protocolVersion": 1,
  "requestId": "31ee6769-0ad0-4c47-95b2-e3d7601d663c",
  "success": false,
  "result": null,
  "error": {
    "code": "protocol_version_unsupported",
    "message": "Protocol version 2 is not supported."
  }
}
```

Current error codes include:

- `invalid_request`
- `protocol_version_unsupported`
- `deadline_exceeded`
- `invalid_deadline`
- `method_not_found`
- `internal_error`

Messages are display-safe and do not include stack traces, credentials, remote
output, or private storage paths. A malformed frame that cannot be correlated
safely is closed without an error response.

## Compatibility and evolution

- A v1 client sends exactly one protocol version in each request.
- A v1 service rejects another version when it can parse and correlate the
  request safely.
- Unknown methods fail closed.
- Removing a field, changing a field's type or meaning, changing framing, or
  relaxing an authorization boundary requires a new protocol version.
- Any future mutating method requires a payload schema, operation-specific
  authorization, durable idempotency, a deadline, redacted audit fields, and
  negative tests before registration.

Long-running certificate work will not hold a pipe connection open. A future
short request will create a durable job whose state can be queried separately.

## Test coverage

The current automated suite covers:

- health request/response over an ACL-protected pipe;
- observation of the actual caller SID and Identification impersonation level;
- rejection of a mismatched pipe-name squatter before any request byte is sent;
- frame round-trip;
- over-limit frames;
- unknown and duplicate JSON members;
- unsupported protocol versions;
- unreasonable deadlines;
- cancellation of a cooperative handler at the request deadline;
- rejection of late success from a non-cooperative handler, without retaining
  its client slot; and
- stalled clients releasing their bounded connection slot.

Still required before the IPC boundary exits Phase 0:

- clean-machine installer tests proving the exact `CertBaton` SCM registration,
  `NT SERVICE\CertBaton` SID configuration, installed DACL, and UI/CLI
  connection;
- service unavailable, stop/restart, status-query failure, and relevant
  process-ID race tests;
- partial and truncated reads;
- zero-length and exact-maximum frames;
- malformed UTF-8;
- missing required properties;
- expired deadlines;
- unauthorized local callers and remote/anonymous attempts;
- slow readers/writers, connection saturation, and disconnects;
- shutdown while clients are connected; and
- verified redaction of every response and event field.

An IPC handler that ignores cancellation can continue executing in process,
but its late result is discarded and its client slot is released. Mutating or
long-running certificate work is therefore prohibited inside an IPC handler;
future requests will validate and enqueue durable jobs with their own
cancellation and recovery boundaries.

Server-process validation relies on the integrity of the Windows kernel and
Service Control Manager. It does not claim to resist a local administrator or
kernel-level attacker.
