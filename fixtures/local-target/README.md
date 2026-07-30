# CertBaton local target fixture

This directory contains a disposable, loopback-only SSH/SFTP and Nginx target
for CertBaton integration development. It uses synthetic identities and
certificates only.

Read [`docs/fixtures/local-target.md`](../../docs/fixtures/local-target.md)
before starting it. The short path is:

```powershell
.\fixture.ps1 init
.\fixture.ps1 config
.\fixture.ps1 up
.\fixture.ps1 smoke
```

No Docker daemon or live infrastructure is contacted by `init` or `config`.
`up`, `smoke`, injection, and teardown require a local Linux-container Docker
engine.
