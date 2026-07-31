# ADR 0008: Windows installer toolchain

- Status: Proposed — product-owner EULA acceptance required
- Date: 2026-07-31
- Decision owners: CertBaton maintainers

## Context

CertBaton needs a machine-wide Windows 11 x64 package that can install three
self-contained applications, register and harden a Windows Service, create
protected operational-data directories, support transactional repair and major
upgrade, reject downgrades, and remove privileged launch points cleanly.

The package must use standard Windows Installer facilities wherever possible.
Privileged custom actions, script interpreters, inbound firewall rules, PATH
changes, an updater, and a bootstrapper are unnecessary for P0 and increase the
attack surface.

The evaluated toolchains were WiX Toolset, MSIX, Inno Setup, NSIS, Visual
Studio Installer Projects, and Advanced Installer. MSIX does not fit the
required conventional service, protected mutable data, and MSI lifecycle
semantics. Inno Setup and NSIS produce scripted executable installers rather
than the required MSI. Visual Studio Installer Projects pushes important
service work into application custom actions. Advanced Installer is a viable
commercial fallback but would make the contributor build dependent on
proprietary tooling.

WiX Toolset 7 is the strongest technical fit. Its SDK-style project works with
`dotnet build`, and its core schema can author files, services, service SID
configuration, failure actions, full SDDL security descriptors, repair, and
major upgrades without CertBaton-authored custom actions.

WiX 7 also requires an explicit acceptance of the Open Source Maintenance Fee
EULA. Under the published terms, organizations over the EULA's defined
US$10,000 annual-revenue threshold must sponsor the WiX project. CertBaton is
intended to begin as a free open-source client but may later support a paid
service, so accepting that obligation is a product-owner decision rather than
an invisible build detail.

Sources:

- [WiX Open Source Maintenance Fee](https://docs.firegiant.com/wix/osmf/)
- [WiX release notes](https://docs.firegiant.com/wix/whatsnew/releasenotes/)
- [WiX MSBuild SDK](https://docs.firegiant.com/wix/tools/msbuild/)
- [WiX ServiceInstall](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/)
- [WiX core PermissionEx](https://docs.firegiant.com/wix/schema/wxs/permissionex/)

## Proposed decision

After explicit product-owner acceptance of the WiX 7 OSMF EULA:

- pin `WixToolset.Sdk` to exact version `7.0.0`;
- declare EULA acceptance visibly in the installer project and release
  documentation;
- build a per-machine x64 MSI with Windows Installer 5.0 as its minimum;
- publish Desktop, Service, and CLI as self-contained, untrimmed, non-single-
  file `win-x64` payloads in separate directories;
- use only core MSI/WiX service and ACL tables for the first package;
- use a stable upgrade identity, a new product code per major-upgrade package,
  and block downgrades;
- install the service as the passwordless virtual account
  `NT SERVICE\CertBaton`, subject to the secret-vault decision in ADR 0003;
- enable the exact unrestricted service SID before service start;
- create protected `%ProgramData%\CertBaton\State` and `Backups` directories
  using full SDDL, with SYSTEM ownership, SYSTEM and Administrators Full
  Control, and the exact service SID Modify without owner/DACL rights;
- keep operational data on developer-preview uninstall by default;
- add no bootstrapper, installer UI, custom action, firewall rule, PATH entry,
  scheduled task, or automatic updater; and
- require signed application binaries and MSI before public beta.

Before that acceptance, the repository may provide a clearly labeled,
repeatable developer installation script. That script is an Increment 1
engineering aid, not the selected public distribution format and not evidence
that MSI lifecycle gates have passed.

## Consequences

### Positive

- Installation, repair, rollback, upgrade, downgrade detection, and removal use
  native Windows Installer semantics.
- A clean machine does not need the .NET runtime or developer tools.
- The installer remains reviewable source and buildable in CI.
- P0 does not need a CertBaton-authored privileged custom action.

### Costs and constraints

- The OSMF EULA and possible future sponsorship cost must be reviewed before
  adoption and again before monetization or a material ownership change.
- Self-contained payloads are larger and require an explicit .NET runtime
  patch cadence.
- MSI component identity and upgrade rules become long-lived compatibility
  contracts.
- An unsigned developer MSI is never a public release artifact.

## Validation gates

The decision is not Accepted, and no WiX EULA acceptance may be committed or
executed, until the product owner approves it.

After approval, acceptance requires:

1. static MSI-table assertions for platform, scope, service configuration,
   SDDL, upgrade identity, payload exclusions, and absence of custom actions,
   firewall entries, PATH mutation, and unexpected privileged behavior;
2. clean install, repair, upgrade, downgrade rejection, rollback, retain-data
   uninstall, delete-data uninstall, and reinstall on a supported snapshot VM;
3. exact service account, service SID, token, service-object DACL, executable
   ACL, data ACL, Event Log source, and named-pipe checks;
4. service restart, reboot auto-start, UI-closed execution, and interruption
   recovery evidence; and
5. hashes, SBOM, provenance, and Authenticode verification for a release build.

The current Windows 11 23H2 development workstation can provide functional
developer evidence only. It is not a supported clean-machine qualification
target.
