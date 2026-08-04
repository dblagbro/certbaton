# CertBaton Nginx helper fixture

This is the version 1 least-privilege activation helper used by the P0 Nginx
fixture. It is not a general remote shell. Its command surface is a fixed verb
plus a canonical lower-case UUID, and all paths, the one permitted DNS name,
and Nginx controls come from a root-owned local configuration file.

Install the script as
`/usr/local/libexec/certbaton/certbaton-helper-v1`, owned by root and mode 0755.
Install a host-specific copy of `helper-v1.conf.example` as
`/etc/certbaton/helper-v1.conf`, owned by root and mode 0644 or stricter. The
configuration directory must also be root-owned and not writable by group or
other. The configured SSH user must be a dedicated non-root account. It needs
SFTP access only to the transaction directory created by `prepare`; it does not
need membership in `docker`, access to the release tree, or general sudo. Its
sudo policy should permit only this exact root-owned helper executable. The
helper itself rejects extra arguments, unknown verbs, and noncanonical IDs.

The incoming root, release root, bootstrap directory, and every directory in
their ancestry must be real directories (no symlink components), root-owned,
and not writable by group or other. Incoming and release roots cannot contain
one another. This deliberately excludes a release tree below an SFTP user's
writable home directory. For Docker Nginx, bind-mount the root-owned stable
release path into the container instead.

The stable Nginx certificate paths are `RELEASE_ROOT/current/fullchain.pem` and
`RELEASE_ROOT/current/privkey.pem`. Before enrollment, an administrator creates
the `current` symlink to the existing `bootstrap_target`, changes Nginx to use
the stable paths, validates configuration, reloads, and verifies public TLS.

The workflow is `prepare`, SFTP upload of exactly `fullchain.pem` and
`privkey.pem`, `validate`, `activate`, `verify`, independent public TLS
verification, then `commit`. `validate` freezes the SFTP-owned transaction
directory before root copies from it, rejects links and unexpected entries,
checks bounded file sizes and ownership, and validates the DNS name, validity
window, and certificate/private-key match. Encrypted private keys are rejected.
Both a new and an idempotently repeated `prepare` response include an
`uploadPath` field containing the exact canonical
`INCOMING_ROOT/<transaction-id>` directory. The client must require an exact
match with the path derived from its enrolled incoming root and transaction ID
before uploading. Configuration and transaction path characters are restricted
to a JSON-safe ASCII allowlist; the helper never interpolates an unrestricted
string into this response.

`activate` records an `activating` write-ahead state before changing the stable
symlink. `rollback` similarly records `rolling-back`. Repeating the same verb
after an SSH response is lost is safe. A `status` response marks either
transitional state with `recoveryRequired: true`; rerun `activate` to finish an
activation or run `rollback` to restore the recorded prior target. A failed
public check uses `rollback`. `abort` cleans a prepared, validated, or already
rolled-back transaction, but refuses active, transitional, and committed
transactions. The helper keeps immutable committed generations so rollback
does not depend on overwritten certificate files.

`commit` deliberately removes the incoming transaction, including its uploaded
private key, while the durable state is still `active`. Only after that cleanup
succeeds does it atomically replace the state with `committed`. Therefore,
`committed` is a postcondition proving the incoming transaction path was absent
when the state was written. If the helper stops after cleanup but before the
state replacement, `status` remains `active` and retrying `commit` is safe. A
retry also cleans incoming material left by an older helper that recorded
`committed` too early.

All helper operations are serialized with a root-only runtime lock. Lock waits
and Nginx test/reload subprocesses are bounded, so a stuck peer or Nginx command
does not hold an SSH session forever. Helper JSON deliberately contains only
fixed error messages and non-secret transaction/certificate metadata.

## Local qualification test

`test-helper-v1.sh` creates an isolated fixture below `/var/lib`, rewrites a
temporary copy of the helper to use that fixture, and substitutes harmless
Nginx/systemd shims. Run it as root in a disposable Linux VM or WSL instance:

```bash
sudo bash ./test-helper-v1.sh
```

It tests exact new/repeated prepare upload paths, happy-path renewal and retries, failed activation restoration,
interrupted rollback and activation recovery, staged-release recovery, input
symlink/extra-file rejection, key mismatch rejection, root overlap rejection,
commit cleanup failure and retry, rollback, abort, verify, and status behavior.
It does not contact a remote host or public ACME service.

This fixture still requires qualification on each supported OS and Nginx
packaging model, real Docker-mode testing, process-kill/fault-injection testing,
and hostile local-filesystem testing before it becomes a supported deployment
recipe. Version 1 does not garbage-collect old committed generations, validate
the public trust chain, or replace the client's independent public TLS check.
