[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptNames = @(
    'build-developer-package.ps1',
    'install-developer-package.ps1',
    'test-installed-developer-package.ps1',
    'invoke-developer-install.ps1'
)

foreach ($scriptName in $scriptNames) {
    $scriptPath = Join-Path $PSScriptRoot $scriptName
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$errors)
    if ($errors.Count -ne 0) {
        throw (
            "PowerShell parser errors were found in '$scriptName':" +
            [Environment]::NewLine +
            (($errors | ForEach-Object { $_.ToString() }) -join
                [Environment]::NewLine))
    }

    if ($null -eq $ast) {
        throw "PowerShell did not return an AST for '$scriptName'."
    }
}

$installerSource = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'install-developer-package.ps1') -Raw
$auditSource = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'test-installed-developer-package.ps1') -Raw
$builderSource = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'build-developer-package.ps1') -Raw
$serviceSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'src\CertBaton.Service\Program.cs') -Raw
$coordinatorSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot `
        'src\CertBaton.Service\LiveRenewalCoordinator.cs') -Raw
$simulationCoordinatorSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot `
        'src\CertBaton.Service\SimulationCoordinator.cs') -Raw
$ipcWorkerSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot `
        'src\CertBaton.Service\IpcWorker.cs') -Raw

$requiredInstallerTokens = @(
    'AllowDeveloperSourceChange',
    'AllowDeveloperDowngrade',
    'New-OperationalDataSnapshot',
    'Restore-OperationalDataSnapshot',
    'Get-OperationalAclSnapshot',
    'CertBaton.upgrade-',
    'Disable-ServiceStartupAndRestarts',
    'Set-ServiceAuditConfiguration',
    'Set-ServiceProductionConfiguration',
    '$commitBoundaryCrossed = $true',
    "StartMode = 'Manual'",
    'ExcludeService',
    '--maintenance-inspect-state',
    '-MaintenanceExpected'
)
foreach ($token in $requiredInstallerTokens) {
    if (-not $installerSource.Contains($token)) {
        throw "The installer is missing its required '$token' safety hook."
    }
}

foreach ($token in @(
        'packageSchemaVersion',
        'stateSchema',
        'CurrentVersion')) {
    if (-not $builderSource.Contains($token)) {
        throw "The package builder is missing '$token' compatibility metadata."
    }
}

foreach ($token in @(
        'Get-SecretInventory',
        'MaintenanceExpected',
        'temporary, residue, nested')) {
    if (-not $auditSource.Contains($token)) {
        throw "The installed audit is missing its '$token' check."
    }
}

if (-not $serviceSource.Contains('--maintenance-inspect-state') -or
    -not $serviceSource.Contains('LiveMaintenanceGate') -or
    -not $coordinatorSource.Contains('WaitUntilOpenAsync') -or
    -not $coordinatorSource.Contains('ThrowIfPaused') -or
    -not $simulationCoordinatorSource.Contains('WaitUntilOpenAsync') -or
    -not $simulationCoordinatorSource.Contains('ThrowIfPaused') -or
    -not $ipcWorkerSource.Contains('service_maintenance')) {
    throw 'The Service is missing its installer-maintenance execution gate.'
}

if ($installerSource.Contains("StartMode = 'Automatic'")) {
    throw 'The installer enables automatic service startup before acceptance.'
}

$commitBoundaryIndex = $installerSource.LastIndexOf(
    '$commitBoundaryCrossed = $true',
    [StringComparison]::Ordinal)
$markerRemovalIndex = $installerSource.LastIndexOf(
    'Remove-ValidatedMaintenanceMarker -Path $maintenanceMarkerPath',
    [StringComparison]::Ordinal)
if ($commitBoundaryIndex -lt 0 -or
    $markerRemovalIndex -lt $commitBoundaryIndex) {
    throw 'The installer removes maintenance before its durable commit boundary.'
}

$schemaSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot `
        'src\CertBaton.Persistence.Sqlite\SqliteSchema.cs') -Raw
$schemaVersion = [regex]::Match(
    $schemaSource,
    'public\s+const\s+int\s+CurrentVersion\s*=\s*(\d+)\s*;')
if (-not $schemaVersion.Success -or
    [int]$schemaVersion.Groups[1].Value -lt 1) {
    throw 'The package builder cannot derive a valid SQLite schema version.'
}

[pscustomobject]@{
    Product = 'CertBaton'
    Check = 'developer-package-script-static-safety'
    ParsedScripts = $scriptNames.Count
    StateSchemaVersion = [int]$schemaVersion.Groups[1].Value
    Passed = $true
} | ConvertTo-Json
