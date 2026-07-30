# CertBaton local IPC protocol v1

Status: **Health and developer-only durable simulation dispatch implemented**

This document describes the current local protocol between the CertBaton
Windows Service and the desktop application or diagnostic CLI. It is not a
remote API or a public compatibility promise.

## Transport and endpoint identity

- Transport: local Windows named pipe `CertBaton.Service.v1`.
- Production client server: the SCM-registered CertBaton Windows Service.
- Development server: a console-mode host exercised by the integration tests;
  production Desktop and CLI clients do not trust a console process.
- Remote and anonymous access: explicitly denied by the pipe DACL.
- Implemented service operations: read-only `health` and `simulation.latest`,
  plus narrowly authorized synthetic `simulation.start`.
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

The synthetic start operation is authorized only for the current user on the
development pipe or an elevated local administrator on the installed-service
profile. This temporary policy does not authorize real certificate or remote
host changes. Before a production mutation is added, the installer and service
must establish a narrower Operator role and test filtered UAC tokens. Knowing
the pipe name, being a local User, or passing endpoint authentication is never
authorization for a production mutation.

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
- a client has five seconds to complete the exchange before its
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
  "deadlineUtc": "2026-07-29T20:00:03Z",
  "payload": null
}
```

| Field | Rule |
| --- | --- |
| `protocolVersion` | Must equal `1` |
| `requestId` | Non-empty UUID; correlates this request and response |
| `method` | Exact, case-sensitive registered method |
| `sentAtUtc` | Timestamp within the allowed local clock window |
| `deadlineUtc` | Later than `sentAtUtc`, in the future, and no more than 30 seconds ahead |
| `payload` | Typed start payload for `simulation.start`; `null` for `health` and `simulation.latest` |

The request ID is not an authorization token or an idempotency guarantee.

## Simulation requests

`simulation.latest` has no payload:

```json
{
  "protocolVersion": 1,
  "requestId": "7a963936-129a-4f37-aafb-c7b90bc9e060",
  "method": "simulation.latest",
  "sentAtUtc": "2026-07-29T20:00:00Z",
  "deadlineUtc": "2026-07-29T20:00:03Z",
  "payload": null
}
```

`simulation.start` carries a non-empty idempotency UUID and an optional
synthetic failure stage:

```json
{
  "protocolVersion": 1,
  "requestId": "e69c6a10-0b52-46bf-9251-59aa03b1913e",
  "method": "simulation.start",
  "sentAtUtc": "2026-07-29T20:00:00Z",
  "deadlineUtc": "2026-07-29T20:00:03Z",
  "payload": {
    "idempotencyKey": "0c09079b-9297-480d-9973-360fac79703a",
    "failureStage": "challenge"
  }
}
```

`failureStage` is either `null` or exactly one of these case-sensitive,
lower-case wire values: `preflight`, `order`, `challenge`, `issuance`,
`deployment`, `activation`, `verification`, or `cleanup`.

The idempotency UUID identifies the requested simulation plan. Retrying the
same UUID and failure stage returns the same durable job, including while it is
active. Reusing a UUID with a different plan fails closed. Replaying an older
terminal request returns that historical job to the caller but does not replace
the service's global latest-job view.

The contract layer validates message shape; it does not authorize work.
Authorization for `simulation.start` is service policy, described in ADR 0007,
and is not implemented by the contract layer. The service enqueues accepted
simulation work in its single-reader coordinator, persists it before returning,
and performs it independently of the desktop connection.

## Successful health response

```json
{
  "protocolVersion": 1,
  "requestId": "31ee6769-0ad0-4c47-95b2-e3d7601d663c",
  "success": true,
  "result": {
    "health": {
      "status": "healthy",
      "serviceVersion": "0.1.0-dev",
      "startedAtUtc": "2026-07-29T19:55:00Z",
      "respondedAtUtc": "2026-07-29T20:00:00Z"
    },
    "simulationRun": null
  },
  "error": null
}
```

## Successful simulation response

Both simulation methods return the same typed run snapshot:

```json
{
  "protocolVersion": 1,
  "requestId": "e69c6a10-0b52-46bf-9251-59aa03b1913e",
  "success": true,
  "result": {
    "health": null,
    "simulationRun": {
      "runId": "0198fbc8-e3a8-7595-af47-2d0e30a010c5",
      "status": "failed",
      "currentStage": null,
      "terminalStage": "challenge",
      "outcome": "failed",
      "requestedAtUtc": "2026-07-29T20:00:00Z",
      "startedAtUtc": "2026-07-29T20:00:00Z",
      "completedAtUtc": "2026-07-29T20:00:01Z",
      "evidence": [
        {
          "sequence": 1,
          "stage": "challenge",
          "outcome": "failed",
          "recordedAtUtc": "2026-07-29T20:00:01Z",
          "code": "simulation.injected_failure",
          "description": "The configured simulated failure occurred."
        }
      ]
    }
  },
  "error": null
}
```

A successful result envelope contains exactly one non-null payload:
`health` or `simulationRun`. Clients reject zero or multiple payloads and
reject a payload that does not match the requested method.

Simulation `status` is exactly `queued`, `running`, `succeeded`, `failed`,
`cancelled`, or `interrupted`. Terminal `outcome` uses `succeeded`, `failed`,
`cancelled`, or `interrupted`. Stage and outcome fields are JSON strings, never
numeric enum ordinals. All timestamps are UTC. Started/completed and
current/terminal state are nullable where the lifecycle permits. An interrupted
run may have no terminal stage when recovery occurs before the first stage.

Evidence is typed, sequential from one, ordered, and limited to 64 records.
Codes are limited to 128 characters and descriptions to 1,024 characters. A
`succeeded` snapshot must contain successful evidence for all eight stages in
pipeline order, including verification and cleanup.

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
- `simulation_not_found`
- `simulation_start_forbidden`
- `simulation_already_active`
- `simulation_idempotency_conflict`
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
- `simulation.start` uses operation-specific authorization, a caller-provided
  idempotency UUID, bounded enqueueing, durable state, redacted evidence, and
  negative tests.

The simulation start request returns after durable job creation; the service
continues the run independently and `simulation.latest` queries its state.
Future certificate work must retain this short enqueue/query shape rather than
holding a pipe connection open for network or deployment work.

`simulation.latest` is the job with the greatest durable insertion sequence,
not the greatest wall-clock timestamp. It is a global development view and may
change when another authorized client starts a later run. A client that polls
after `simulation.start` must correlate the returned `runId` and must not
attribute a different run's evidence to its accepted run.

Cancellation before the coordinator claims a queued start command creates no
job. Once claim wins, job creation completes even if the IPC deadline later
expires. The caller must treat that result as indeterminate and retry the same
idempotency UUID; the Desktop preserves it for this purpose.

## Test coverage

The current automated suite covers:

- health request/response over an ACL-protected pipe;
- typed simulation start/latest request and response framing;
- authorized development dispatch and denial of an ordinary installed-service
  caller before enqueue;
- service-owned successful and injected-failure simulation persistence;
- active and terminal same-key retries without duplicate work or latest-view
  rollback;
- pre-claim cancellation without a durable job and post-claim durable
  acceptance;
- durable latest selection across a backward wall-clock adjustment;
- rejection of persistence writes from the wrong service execution epoch;
- desktop reuse of an ambiguous request key and rejection of a mismatched
  latest-run ID;
- method/payload shape validation and exact lower-case contract values;
- rejection of zero-payload and multiple-payload successful envelopes;
- bounded evidence and terminal lifecycle validation;
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
but its late result is discarded and its client slot is released. Long-running
work is therefore prohibited inside an IPC handler. The current synthetic start
handler performs only validation, authorization, bounded enqueueing, and
durable job creation; the service-owned coordinator runs the stages with its
own recovery boundary.

Server-process validation relies on the integrity of the Windows kernel and
Service Control Manager. It does not claim to resist a local administrator or
kernel-level attacker.
