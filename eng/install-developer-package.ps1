[CmdletBinding()]
param(
    [string] $PackageRoot = $PSScriptRoot,

    [string] $InstallRoot = (Join-Path $env:ProgramFiles 'CertBaton'),

    [string] $DataRoot = (Join-Path $env:ProgramData 'CertBaton'),

    [switch] $AllowDeveloperSourceChange,

    [switch] $AllowDeveloperDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'CertBaton'
$serviceDisplayName = 'CertBaton Certificate Renewal Service'
$serviceSidValue =
    'S-1-5-80-2998542184-680993539-724725283-631637665-607464993'
$uninstallKey =
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CertBatonDeveloper'
$serviceSddl =
    'O:SYG:SYD:P' +
    '(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)' +
    '(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' +
    '(A;;LC;;;BU)'
$packageSchemaVersion = 2
$certBatonApplicationId = 0x4342544E
$maintenanceMarkerName = 'maintenance.lock'

function Assert-ElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw (
            'This developer installer must run from an elevated Windows ' +
            'PowerShell session.')
    }
}

function Assert-LocalFixedNtfsPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw "UNC paths are not permitted: '$fullPath'."
    }

    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "The path does not have a local volume root: '$fullPath'."
    }

    $drive = New-Object IO.DriveInfo($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or
        $drive.DriveFormat -ine 'NTFS') {
        throw "The path must be on a fixed NTFS volume: '$fullPath'."
    }

    $cursor = $fullPath
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }

        $cursor = $parent.FullName
    }

    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are not permitted in the path: '$cursor'."
        }

        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }

        $cursor = $parent.FullName
    }

    return $fullPath
}

function Assert-NoReparsePointsInTree {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $reparsePoint = Get-ChildItem -LiteralPath $Path -Recurse -Force |
        Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        } |
        Select-Object -First 1
    if ($null -ne $reparsePoint) {
        throw (
            'Reparse points are not permitted in the CertBaton data tree: ' +
            "'$($reparsePoint.FullName)'.")
    }
}

function Invoke-Sc {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [switch] $AllowMissing
    )

    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not ($AllowMissing -and $exitCode -eq 1060)) {
        throw (
            "sc.exe $($Arguments -join ' ') failed with code " +
            "$exitCode`:$([Environment]::NewLine)$($output -join [Environment]::NewLine)")
    }

    return @($output)
}

function Get-CertBatonServiceRecord {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'" `
        -ErrorAction SilentlyContinue
}

function Assert-PackageManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [object] $Manifest,

        [Parameter(Mandatory = $true)]
        [string] $ManifestPath
    )

    if ($Manifest.sourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'The package manifest contains an invalid source commit.'
    }

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rootPrefix = $rootPath + '\'
    $expectedFiles = @{}
    foreach ($entry in @($Manifest.files)) {
        $relativePath = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath)) {
            throw 'The package manifest contains an invalid relative path.'
        }

        $candidatePath = [IO.Path]::GetFullPath(
            (Join-Path $rootPath $relativePath.Replace('/', '\')))
        if (-not $candidatePath.StartsWith(
                $rootPrefix,
                [StringComparison]::OrdinalIgnoreCase) -or
            $candidatePath -ieq $ManifestPath) {
            throw (
                'The package manifest path escapes the package root or ' +
                "targets the manifest itself: '$relativePath'.")
        }
        if ($expectedFiles.ContainsKey($candidatePath)) {
            throw "The package manifest repeats '$relativePath'."
        }
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "The package manifest file is missing: '$relativePath'."
        }

        $file = Get-Item -LiteralPath $candidatePath
        if ([int64]$entry.size -ne $file.Length) {
            throw "The package file size does not match: '$relativePath'."
        }

        $actualHash = (
            Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256
        ).Hash
        if ($actualHash -ine [string]$entry.sha256) {
            throw "The package file hash does not match: '$relativePath'."
        }

        $expectedFiles[$candidatePath] = $true
    }

    $actualFiles = @(
        Get-ChildItem -LiteralPath $rootPath -Recurse -File |
            Where-Object { $_.FullName -ine $ManifestPath }
    )
    if ($actualFiles.Count -ne $expectedFiles.Count) {
        throw 'The package contains files that are absent from its manifest.'
    }
    foreach ($actualFile in $actualFiles) {
        if (-not $expectedFiles.ContainsKey($actualFile.FullName)) {
            throw (
                'The package contains an unmanifested file: ' +
                "'$($actualFile.FullName)'.")
        }
    }
}

function Assert-DesktopNotRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $desktopExecutable = Join-Path $Root 'Desktop\CertBaton.Desktop.exe'
    $runningDesktop = @(
        Get-CimInstance Win32_Process `
            -Filter "Name='CertBaton.Desktop.exe'" `
            -ErrorAction SilentlyContinue |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
                $_.ExecutablePath -ieq $desktopExecutable
            }
    )
    if ($runningDesktop.Count -ne 0) {
        throw (
            'Close the installed CertBaton desktop application before ' +
            'installing or repairing the developer preview.')
    }
}

function Set-ProtectedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $ServiceRights,

        [switch] $GrantUsersReadExecute,

        [switch] $ExcludeService
    )

    $systemSid = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-544')
    $usersSid = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-545')
    $serviceSid = New-Object Security.Principal.SecurityIdentifier(
        $serviceSidValue)
    $inheritance =
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow

    $setOwnerOutput = & icacls.exe $Path /setowner '*S-1-5-18' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw (
            "Unable to set SYSTEM as owner of '$Path':" +
            "$([Environment]::NewLine)$($setOwnerOutput -join [Environment]::NewLine)")
    }

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($systemSid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule(
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $systemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow)))
    $acl.AddAccessRule(
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $administratorsSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow)))
    if ($GrantUsersReadExecute) {
        $acl.AddAccessRule(
            (New-Object Security.AccessControl.FileSystemAccessRule(
                $usersSid,
                [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                $inheritance,
                $propagation,
                $allow)))
    }

    if (-not $ExcludeService) {
        $acl.AddAccessRule(
            (New-Object Security.AccessControl.FileSystemAccessRule(
                $serviceSid,
                $ServiceRights,
                $inheritance,
                $propagation,
                $allow)))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Reset-DescendantAcls {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $children = @(Get-ChildItem -LiteralPath $Path -Force)
    foreach ($child in $children) {
        $resetOutput = & icacls.exe $child.FullName /reset /T /C 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw (
                "Unable to reset child ACLs below '$Path':" +
                "$([Environment]::NewLine)$($resetOutput -join [Environment]::NewLine)")
        }

        $ownerOutput = & icacls.exe $child.FullName `
            /setowner '*S-1-5-18' /T /C 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw (
                "Unable to set child ownership below '$Path':" +
                "$([Environment]::NewLine)$($ownerOutput -join [Environment]::NewLine)")
        }
    }
}

function Set-OperationalDataSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $statePath = Join-Path $Root 'State'
    $backupPath = Join-Path $Root 'Backups'
    $secretsPath = Join-Path $Root 'Secrets'
    New-Item -ItemType Directory -Path $Root -Force | Out-Null

    $null = Assert-LocalFixedNtfsPath -Path $Root
    Assert-NoReparsePointsInTree -Path $Root
    Set-ProtectedDirectoryAcl -Path $Root `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)

    New-Item -ItemType Directory -Path $statePath -Force | Out-Null
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    New-Item -ItemType Directory -Path $secretsPath -Force | Out-Null
    foreach ($protectedPath in @($statePath, $backupPath, $secretsPath)) {
        if (-not (Test-Path -LiteralPath $protectedPath -PathType Container)) {
            throw (
                "The protected CertBaton data path is not a directory: " +
                "'$protectedPath'.")
        }

        $null = Assert-LocalFixedNtfsPath -Path $protectedPath
        Assert-NoReparsePointsInTree -Path $protectedPath
    }

    Set-ProtectedDirectoryAcl -Path $statePath `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)
    Reset-DescendantAcls -Path $statePath
    Set-ProtectedDirectoryAcl -Path $backupPath `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)
    Reset-DescendantAcls -Path $backupPath
    Set-ProtectedDirectoryAcl -Path $secretsPath `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)
    Reset-DescendantAcls -Path $secretsPath
}

function Wait-ForServiceStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Status,

        [int] $TimeoutSeconds = 30
    )

    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $desiredStatus = [Enum]::Parse(
        [ServiceProcess.ServiceControllerStatus],
        $Status)
    $service.WaitForStatus(
        $desiredStatus,
        [TimeSpan]::FromSeconds($TimeoutSeconds))
}

function ConvertTo-PackageVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Value
    )

    if ($Value -notmatch '^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?') {
        throw "The developer package version is invalid: '$Value'."
    }

    $revision = if ([string]::IsNullOrWhiteSpace($Matches[4])) {
        0
    }
    else {
        [int]$Matches[4]
    }
    return [Version]::new(
        [int]$Matches[1],
        [int]$Matches[2],
        [int]$Matches[3],
        $revision)
}

function Get-TreeInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The inventory root is missing: '$root'."
    }

    Assert-NoReparsePointsInTree -Path $root
    $directories = @(
        Get-ChildItem -LiteralPath $root -Recurse -Force -Directory |
            Sort-Object FullName |
            ForEach-Object {
                $_.FullName.Substring($root.Length + 1).Replace('\', '/')
            }
    )
    $files = @(
        Get-ChildItem -LiteralPath $root -Recurse -Force -File |
            Sort-Object FullName |
            ForEach-Object {
                $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                [ordered]@{
                    path = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
                    size = $_.Length
                    sha256 = $hash.Hash.ToLowerInvariant()
                }
            }
    )

    return [pscustomobject][ordered]@{
        directories = $directories
        files = $files
    }
}

function Get-OperationalDataInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $result = [ordered]@{}
    foreach ($name in @('State', 'Secrets')) {
        $path = Join-Path $Root $name
        $exists = Test-Path -LiteralPath $path -PathType Container
        $result[$name] = [pscustomobject][ordered]@{
            exists = $exists
            inventory = if ($exists) {
                Get-TreeInventory -Path $path
            }
            else {
                $null
            }
        }
    }

    return [pscustomobject]$result
}

function Get-OperationalAclSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $result = [ordered]@{}
    foreach ($name in @('', 'State', 'Backups', 'Secrets')) {
        $key = if ($name -eq '') { 'Root' } else { $name }
        $path = if ($name -eq '') { $Root } else { Join-Path $Root $name }
        $exists = Test-Path -LiteralPath $path -PathType Container
        $result[$key] = [pscustomobject][ordered]@{
            exists = $exists
            sddl = if ($exists) {
                (Get-Acl -LiteralPath $path).Sddl
            }
            else {
                $null
            }
        }
    }

    return [pscustomobject]$result
}

function Restore-OperationalAclSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [object] $Snapshot
    )

    foreach ($name in @('State', 'Backups', 'Secrets', '')) {
        $key = if ($name -eq '') { 'Root' } else { $name }
        $entry = $Snapshot.$key
        $path = if ($name -eq '') { $Root } else { Join-Path $Root $name }
        if ($entry.exists) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                New-Item -ItemType Directory -Path $path | Out-Null
            }

            $acl = New-Object Security.AccessControl.DirectorySecurity
            $acl.SetSecurityDescriptorSddlForm([string]$entry.sddl)
            Set-Acl -LiteralPath $path -AclObject $acl
        }
        elseif (Test-Path -LiteralPath $path) {
            Remove-ExactOperationalTree -Path $path -ExpectedPath $path
        }
    }
}

function Compare-Inventory {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Expected,

        [Parameter(Mandatory = $true)]
        [object] $Actual,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    $expectedJson = $Expected | ConvertTo-Json -Depth 8 -Compress
    $actualJson = $Actual | ConvertTo-Json -Depth 8 -Compress
    if ($expectedJson -cne $actualJson) {
        throw "$Description does not match its exact file inventory."
    }
}

function Copy-DirectoryContent {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    New-Item -ItemType Directory -Path $Destination | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Source -Force)) {
        Copy-Item -LiteralPath $item.FullName -Destination $Destination `
            -Recurse -Force
    }
}

function Write-DurableUtf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Content
    )

    $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes($Content)
    try {
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Flush-TreeFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    foreach ($file in @(
            Get-ChildItem -LiteralPath $Path -Recurse -Force -File)) {
        $stream = [IO.FileStream]::new(
            $file.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::Read,
            4096,
            [IO.FileOptions]::WriteThrough)
        try {
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
}

function New-OperationalDataSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [string] $SnapshotRoot,

        [Parameter(Mandatory = $true)]
        [string] $SourceCommit
    )

    $inventory = Get-OperationalDataInventory -Root $Root
    $aclSnapshot = Get-OperationalAclSnapshot -Root $Root
    New-Item -ItemType Directory -Path $SnapshotRoot | Out-Null
    foreach ($name in @('State', 'Secrets')) {
        if ($inventory.$name.exists) {
            Copy-DirectoryContent -Source (Join-Path $Root $name) `
                -Destination (Join-Path $SnapshotRoot $name)
        }
    }

    $snapshotContent = [ordered]@{
        product = 'CertBaton'
        kind = 'developer-upgrade-rollback'
        version = 2
        sourceCommit = $SourceCommit
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        inventory = $inventory
        acls = $aclSnapshot
    } | ConvertTo-Json -Depth 8
    Write-DurableUtf8File `
        -Path (Join-Path $SnapshotRoot 'snapshot.json') `
        -Content $snapshotContent

    Set-ProtectedDirectoryAcl -Path $SnapshotRoot `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify) `
        -ExcludeService
    Reset-DescendantAcls -Path $SnapshotRoot
    Assert-NoReparsePointsInTree -Path $SnapshotRoot
    Flush-TreeFiles -Path $SnapshotRoot

    $copied = Get-OperationalDataInventory -Root $SnapshotRoot
    Compare-Inventory -Expected $inventory -Actual $copied `
        -Description 'The protected rollback snapshot'
}

function Get-ValidatedSnapshotInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SnapshotRoot
    )

    Assert-NoReparsePointsInTree -Path $SnapshotRoot
    $manifestPath = Join-Path $SnapshotRoot 'snapshot.json'
    $snapshot = Get-Content -LiteralPath $manifestPath -Raw |
        ConvertFrom-Json
    if ($snapshot.product -ne 'CertBaton' -or
        $snapshot.kind -ne 'developer-upgrade-rollback' -or
        $snapshot.version -ne 2 -or $null -eq $snapshot.acls) {
        throw 'The rollback snapshot manifest is invalid.'
    }

    $actual = Get-OperationalDataInventory -Root $SnapshotRoot
    Compare-Inventory -Expected $snapshot.inventory -Actual $actual `
        -Description 'The protected rollback snapshot'
    return $snapshot
}

function Remove-ExactOperationalTree {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedPath
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullExpected = [IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\')
    if ($fullPath -ine $fullExpected) {
        throw (
            "Refusing recursive removal because '$fullPath' is not " +
            "the exact expected path '$fullExpected'.")
    }

    if (Test-Path -LiteralPath $fullPath) {
        Assert-NoReparsePointsInTree -Path $fullPath
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

function Restore-OperationalDataSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [string] $SnapshotRoot
    )

    $snapshot = Get-ValidatedSnapshotInventory -SnapshotRoot $SnapshotRoot
    $statePath = Join-Path $Root 'State'
    $secretsPath = Join-Path $Root 'Secrets'
    Remove-ExactOperationalTree -Path $statePath -ExpectedPath $statePath
    Remove-ExactOperationalTree -Path $secretsPath -ExpectedPath $secretsPath
    foreach ($name in @('State', 'Secrets')) {
        if ($snapshot.inventory.$name.exists) {
            Copy-DirectoryContent -Source (Join-Path $SnapshotRoot $name) `
                -Destination (Join-Path $Root $name)
            Flush-TreeFiles -Path (Join-Path $Root $name)
        }
    }
    Restore-OperationalAclSnapshot -Root $Root -Snapshot $snapshot.acls
    $restored = Get-OperationalDataInventory -Root $Root
    Compare-Inventory -Expected $snapshot.inventory -Actual $restored `
        -Description 'The restored operational data'
}

function Invoke-OfflineStateInspection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ServiceExecutable,

        [Parameter(Mandatory = $true)]
        [string] $DatabasePath
    )

    $output = @(
        & $ServiceExecutable --maintenance-inspect-state $DatabasePath 2>&1
    )
    if ($LASTEXITCODE -ne 0) {
        throw (
            'The offline CertBaton state inspection failed:' +
            [Environment]::NewLine +
            ($output -join [Environment]::NewLine))
    }

    try {
        return ($output -join [Environment]::NewLine) | ConvertFrom-Json
    }
    catch {
        throw 'The offline CertBaton state inspection returned invalid JSON.'
    }
}

function Write-MaintenanceMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $SourceCommit
    )

    if (Test-Path -LiteralPath $Path) {
        throw (
            "A prior installation-maintenance marker remains at '$Path'. " +
            'Refusing to overwrite it; inspect the prior repair first.')
    }

    $content = [ordered]@{
        product = 'CertBaton'
        kind = 'installation-maintenance'
        targetSourceCommit = $SourceCommit
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json -Compress
    Write-DurableUtf8File -Path $Path -Content $content
}

function Disable-ServiceStartupAndRestarts {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }

    Invoke-Sc -Arguments @(
        'failure', $serviceName,
        'reset=', '0',
        'actions=', ''
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'failureflag', $serviceName, '0'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'config', $serviceName,
        'start=', 'disabled'
    ) | Out-Null

    $service.Refresh()
    if ($service.Status -ne
        [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $serviceName -Force
        Wait-ForServiceStatus -Status 'Stopped'
    }
}

function Set-ServiceAuditConfiguration {
    Invoke-Sc -Arguments @(
        'failure', $serviceName,
        'reset=', '0',
        'actions=', ''
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'failureflag', $serviceName, '0'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'config', $serviceName,
        'start=', 'demand'
    ) | Out-Null
}

function Set-ServiceProductionConfiguration {
    Invoke-Sc -Arguments @(
        'config', $serviceName,
        'start=', 'delayed-auto'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'failure', $serviceName,
        'reset=', '86400',
        'actions=', 'restart/5000/restart/15000/restart/60000'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'failureflag', $serviceName, '1'
    ) | Out-Null
}

function Remove-ValidatedMaintenanceMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $marker = Get-Item -LiteralPath $Path -Force
    if (($marker.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The installation-maintenance marker became a reparse point.'
    }

    Remove-Item -LiteralPath $Path -Force
}

function Wait-ForCliHealth {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CliPath
    )

    $healthOutput = @()
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $healthOutput = & $CliPath health --json 2>&1
            if ($LASTEXITCODE -eq 0) {
                return @($healthOutput)
            }

            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }

    throw (
        "The installed service did not pass its health check:" +
        "$([Environment]::NewLine)$($healthOutput -join [Environment]::NewLine)")
}

Assert-ElevatedAdministrator
$PackageRoot = Assert-LocalFixedNtfsPath -Path $PackageRoot
$InstallRoot = Assert-LocalFixedNtfsPath -Path $InstallRoot
$DataRoot = Assert-LocalFixedNtfsPath -Path $DataRoot
Assert-NoReparsePointsInTree -Path $PackageRoot

$requiredInstallRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramFiles 'CertBaton')).TrimEnd('\')
$requiredDataRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'CertBaton')).TrimEnd('\')
if ($InstallRoot.TrimEnd('\') -ine $requiredInstallRoot) {
    throw (
        'The developer installer only permits the exact installation path ' +
        "'$requiredInstallRoot'.")
}
if ($DataRoot.TrimEnd('\') -ine $requiredDataRoot) {
    throw (
        'The developer installer only permits the exact operational-data ' +
        "path '$requiredDataRoot'.")
}

$payloadRoot = Join-Path $PackageRoot 'payload'
$packageManifestPath = Join-Path $PackageRoot 'manifest.json'
$requiredPackageFiles = @(
    (Join-Path $payloadRoot 'Service\CertBaton.Service.exe'),
    (Join-Path $payloadRoot 'Desktop\CertBaton.Desktop.exe'),
    (Join-Path $payloadRoot 'Cli\certbatonctl.exe'),
    (Join-Path $PackageRoot 'uninstall-developer-package.ps1'),
    (Join-Path $PackageRoot 'test-installed-developer-package.ps1'),
    (Join-Path $PackageRoot 'LICENSE'),
    (Join-Path $PackageRoot 'NOTICE'),
    (Join-Path $PackageRoot 'THIRD-PARTY-NOTICES.txt'),
    (Join-Path $PackageRoot 'licenses\dotnet\LICENSE.txt'),
    (Join-Path $PackageRoot 'licenses\dotnet\ThirdPartyNotices.txt'),
    $packageManifestPath
)
foreach ($requiredFile in $requiredPackageFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "The developer package is incomplete: '$requiredFile' is missing."
    }
}

$manifest = Get-Content -LiteralPath $packageManifestPath -Raw |
    ConvertFrom-Json
if ($manifest.product -ne 'CertBaton' -or
    $manifest.channel -ne 'developer-preview' -or
    $manifest.packageSchemaVersion -ne $packageSchemaVersion -or
    $manifest.runtime -ne 'win-x64' -or
    -not $manifest.selfContained) {
    throw 'The package manifest does not describe a supported CertBaton developer package.'
}
if ($null -eq $manifest.stateSchema -or
    [int]$manifest.stateSchema.current -lt 1 -or
    [int]$manifest.stateSchema.minimumReadable -lt 1 -or
    [int]$manifest.stateSchema.minimumReadable -gt
        [int]$manifest.stateSchema.current -or
    [int]$manifest.stateSchema.maximumReadable -lt
        [int]$manifest.stateSchema.current) {
    throw 'The package manifest contains invalid state-schema compatibility metadata.'
}
Assert-PackageManifest -Root $PackageRoot -Manifest $manifest `
    -ManifestPath $packageManifestPath

$expectedServiceExecutable = Join-Path $InstallRoot `
    'Service\CertBaton.Service.exe'
$expectedImagePath = '"{0}"' -f $expectedServiceExecutable
$existingService = Get-CertBatonServiceRecord
$serviceExisted = $null -ne $existingService
if ($serviceExisted -and
    $existingService.PathName -ine $expectedImagePath -and
    $existingService.PathName -ine $expectedServiceExecutable) {
    throw (
        "A service named '$serviceName' already exists with an unexpected " +
        "image path. Refusing to modify it: '$($existingService.PathName)'.")
}

$installRootExists = Test-Path -LiteralPath $InstallRoot
$installedMarker = Join-Path $InstallRoot 'install-metadata.json'
$existingMarker = $null
$existingSourceCommit = 'legacy-unknown'
$legacyDeveloperInstall = $false
if ($installRootExists) {
    Assert-NoReparsePointsInTree -Path $InstallRoot
}
if (Test-Path -LiteralPath $DataRoot) {
    Assert-NoReparsePointsInTree -Path $DataRoot
}
if ($serviceExisted -or $installRootExists) {
    if (-not (Test-Path -LiteralPath $installedMarker -PathType Leaf)) {
        throw (
            'An existing CertBaton installation has no developer-preview ' +
            "marker: '$InstallRoot'.")
    }

    $existingMarker = Get-Content -LiteralPath $installedMarker -Raw |
        ConvertFrom-Json
    if ($existingMarker.product -ne 'CertBaton' -or
        $existingMarker.channel -ne 'developer-preview') {
        throw (
            'The existing installation marker is not a compatible ' +
            "CertBaton developer preview: '$installedMarker'.")
    }

    $existingProperties = @($existingMarker.PSObject.Properties.Name)
    $legacyDeveloperInstall =
        $existingProperties -notcontains 'packageSchemaVersion'
    if ($existingProperties -contains 'sourceCommit') {
        $existingSourceCommit = [string]$existingMarker.sourceCommit
    }
    $sourceChanged =
        $existingProperties -notcontains 'sourceCommit' -or
        [string]$existingMarker.sourceCommit -cne [string]$manifest.sourceCommit
    if ($sourceChanged -and -not $AllowDeveloperSourceChange) {
        throw (
            'The package source commit differs from the installed developer ' +
            'build. Re-run with -AllowDeveloperSourceChange only after ' +
            'reviewing the package provenance and rollback plan.')
    }

    if ($existingProperties -contains 'version') {
        $installedVersion = ConvertTo-PackageVersion `
            -Value ([string]$existingMarker.version)
        $incomingVersion = ConvertTo-PackageVersion `
            -Value ([string]$manifest.version)
        if ($incomingVersion -lt $installedVersion -and
            -not $AllowDeveloperDowngrade) {
            throw (
                'The package version is older than the installed version. ' +
                'An intentionally compatible downgrade also requires ' +
                '-AllowDeveloperDowngrade.')
        }
    }

    if ($existingProperties -contains 'packageSchemaVersion' -and
        [int]$existingMarker.packageSchemaVersion -ne $packageSchemaVersion) {
        throw 'The installed package metadata schema is not supported.'
    }
    if ($existingProperties -notcontains 'packageSchemaVersion' -and
        -not $AllowDeveloperSourceChange) {
        throw (
            'Legacy developer metadata requires the explicit ' +
            '-AllowDeveloperSourceChange transition gate.')
    }
}

Assert-DesktopNotRunning -Root $InstallRoot

$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$installParent = [IO.Path]::GetDirectoryName($InstallRoot)
if ($installParent -ine $programFilesRoot) {
    throw (
        "The developer installer currently requires a direct Program Files " +
        "install directory. Received '$InstallRoot'.")
}

$stagingRoot = Join-Path $programFilesRoot (
    'CertBaton.install-{0}' -f [Guid]::NewGuid().ToString('N'))
$backupRoot = Join-Path $programFilesRoot (
    'CertBaton.backup-{0}' -f [Guid]::NewGuid().ToString('N'))
$replacementCommitted = $false
$backupCreated = $false
$commitBoundaryCrossed = $false
$isRepair = $serviceExisted -or $installRootExists
$serviceWasRunning = $serviceExisted -and
    $existingService.State -eq 'Running'
$dataRootExisted = Test-Path -LiteralPath $DataRoot
$maintenanceMarkerPath = Join-Path $DataRoot $maintenanceMarkerName
$maintenanceMarkerCreated = $false
$snapshotRoot = Join-Path ([IO.Path]::GetDirectoryName($DataRoot)) (
    'CertBaton.upgrade-{0}' -f [Guid]::NewGuid().ToString('N'))
$snapshotCreated = $false
$deepAuditOutput = @()

if (Test-Path -LiteralPath $maintenanceMarkerPath) {
    throw (
        "A prior installation-maintenance marker remains at " +
        "'$maintenanceMarkerPath'. Inspect and complete or roll back that " +
        'transaction before starting another installation.')
}

if ($isRepair) {
    foreach ($requiredDataPath in @(
            $DataRoot,
            (Join-Path $DataRoot 'State'))) {
        if (-not (Test-Path -LiteralPath $requiredDataPath -PathType Container)) {
            throw (
                'The existing developer installation is missing protected ' +
                "operational data: '$requiredDataPath'.")
        }
    }

    $existingSecretsPath = Join-Path $DataRoot 'Secrets'
    if (-not (Test-Path -LiteralPath $existingSecretsPath -PathType Container) -and
        -not ($legacyDeveloperInstall -and $AllowDeveloperSourceChange)) {
        throw (
            'The existing developer installation is missing its protected ' +
            "secrets directory: '$existingSecretsPath'.")
    }
}

try {
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    foreach ($payloadName in @('Service', 'Desktop', 'Cli')) {
        $destination = Join-Path $stagingRoot $payloadName
        New-Item -ItemType Directory -Path $destination | Out-Null
        Copy-Item -Path (Join-Path $payloadRoot "$payloadName\*") `
            -Destination $destination -Recurse -Force
    }
    Assert-NoReparsePointsInTree -Path $stagingRoot

    $toolsRoot = Join-Path $stagingRoot 'Tools'
    New-Item -ItemType Directory -Path $toolsRoot | Out-Null
    foreach ($scriptName in @(
            'install-developer-package.ps1',
            'uninstall-developer-package.ps1',
            'test-installed-developer-package.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PackageRoot $scriptName) `
            -Destination (Join-Path $toolsRoot $scriptName)
    }
    Copy-Item -LiteralPath $packageManifestPath `
        -Destination (Join-Path $stagingRoot 'package-manifest.json')

    [ordered]@{
        product = 'CertBaton'
        channel = 'developer-preview'
        packageSchemaVersion = $packageSchemaVersion
        version = [string]$manifest.version
        sourceCommit = [string]$manifest.sourceCommit
        stateSchemaVersion = [int]$manifest.stateSchema.current
        installedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json |
        Set-Content -LiteralPath (
            Join-Path $stagingRoot 'install-metadata.json') -Encoding UTF8

    Set-ProtectedDirectoryAcl -Path $stagingRoot `
        -ServiceRights (
            [Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -GrantUsersReadExecute
    Reset-DescendantAcls -Path $stagingRoot

    $stagedServiceExecutable = Join-Path $stagingRoot `
        'Service\CertBaton.Service.exe'
    $databasePath = Join-Path $DataRoot 'State\certbaton.db'

    if ($serviceExisted) {
        Disable-ServiceStartupAndRestarts
    }

    $stateInspection = Invoke-OfflineStateInspection `
        -ServiceExecutable $stagedServiceExecutable `
        -DatabasePath $databasePath
    if ($stateInspection.DatabaseExists) {
        if ([int]$stateInspection.ApplicationId -ne $certBatonApplicationId) {
            throw 'The existing SQLite database is not a CertBaton database.'
        }
        if ($stateInspection.IntegrityCheck -cne 'ok') {
            throw 'The existing SQLite database failed its offline integrity check.'
        }
        if ([int]$stateInspection.SchemaVersion -lt
                [int]$manifest.stateSchema.minimumReadable -or
            [int]$stateInspection.SchemaVersion -gt
                [int]$manifest.stateSchema.maximumReadable) {
            throw (
                'The existing SQLite schema is outside the incoming ' +
                'package compatibility range.')
        }
        if ([int64]$stateInspection.ActiveLiveOperationCount -ne 0) {
            throw (
                'At least one queued or active live renewal exists. ' +
                'The developer repair will not cross that recovery boundary.')
        }

        if ($null -ne $existingMarker -and
            @($existingMarker.PSObject.Properties.Name) -contains
                'stateSchemaVersion' -and
            [int]$existingMarker.stateSchemaVersion -ne
                [int]$stateInspection.SchemaVersion) {
            throw (
                'The installed schema metadata does not match the offline ' +
                'database inspection result.')
        }
    }

    if ($isRepair) {
        New-OperationalDataSnapshot -Root $DataRoot `
            -SnapshotRoot $snapshotRoot `
            -SourceCommit $existingSourceCommit
        $snapshotCreated = $true
    }

    Set-OperationalDataSecurity -Root $DataRoot
    Write-MaintenanceMarker -Path $maintenanceMarkerPath `
        -SourceCommit ([string]$manifest.sourceCommit)
    $maintenanceMarkerCreated = $true

    if (Test-Path -LiteralPath $InstallRoot) {
        Move-Item -LiteralPath $InstallRoot -Destination $backupRoot
        $backupCreated = $true
    }

    Move-Item -LiteralPath $stagingRoot -Destination $InstallRoot
    $replacementCommitted = $true

    $serviceExecutable = Join-Path $InstallRoot `
        'Service\CertBaton.Service.exe'
    $quotedImagePath = '"{0}"' -f $serviceExecutable
    $serviceMethodArguments = @{
        DisplayName = $serviceDisplayName
        PathName = $quotedImagePath
        ServiceType = 16
        ErrorControl = 1
        StartMode = 'Manual'
        StartName = "NT SERVICE\$serviceName"
    }
    if ($serviceExisted) {
        $serviceChange = Invoke-CimMethod `
            -InputObject (Get-CertBatonServiceRecord) `
            -MethodName Change `
            -Arguments $serviceMethodArguments
        if ($serviceChange.ReturnValue -ne 0) {
            throw (
                'Win32_Service.Change failed with code ' +
                "$($serviceChange.ReturnValue).")
        }
    }
    else {
        $serviceCreateArguments = @{
            Name = $serviceName
            DisplayName = $serviceDisplayName
            PathName = $quotedImagePath
            ServiceType = 16
            ErrorControl = 1
            StartMode = 'Manual'
            StartName = "NT SERVICE\$serviceName"
        }
        $serviceCreate = Invoke-CimMethod `
            -ClassName Win32_Service `
            -MethodName Create `
            -Arguments $serviceCreateArguments
        if ($serviceCreate.ReturnValue -ne 0) {
            throw (
                'Win32_Service.Create failed with code ' +
                "$($serviceCreate.ReturnValue).")
        }
    }

    Set-ServiceAuditConfiguration

    $storedImagePath = Get-ItemPropertyValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
        -Name ImagePath
    if ($storedImagePath -cne $quotedImagePath) {
        throw (
            'Windows did not retain the required quoted service image path. ' +
            "Expected '$quotedImagePath'; found '$storedImagePath'.")
    }

    Invoke-Sc -Arguments @(
        'description', $serviceName,
        'Renews and deploys certificates for explicitly enrolled targets.'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'sidtype', $serviceName, 'unrestricted'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'sdset', $serviceName, $serviceSddl
    ) | Out-Null

    $resolvedServiceSid = (
        New-Object Security.Principal.NTAccount(
            'NT SERVICE',
            $serviceName)
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($resolvedServiceSid -cne $serviceSidValue) {
        throw (
            "The Windows service SID '$resolvedServiceSid' does not match " +
            "the expected CertBaton SID '$serviceSidValue'.")
    }

    if ([Diagnostics.EventLog]::SourceExists($serviceName)) {
        $sourceLog = [Diagnostics.EventLog]::LogNameFromSourceName(
            $serviceName,
            '.')
        if ($sourceLog -ne 'Application') {
            Remove-EventLog -Source $serviceName
        }
    }
    if (-not [Diagnostics.EventLog]::SourceExists($serviceName)) {
        New-EventLog -LogName Application -Source $serviceName
    }

    $commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
    $shortcutDirectory = Join-Path $commonPrograms 'CertBaton'
    New-Item -ItemType Directory -Path $shortcutDirectory -Force | Out-Null
    $shortcutPath = Join-Path $shortcutDirectory 'CertBaton.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot `
        'Desktop\CertBaton.Desktop.exe'
    $shortcut.WorkingDirectory = Join-Path $InstallRoot 'Desktop'
    $shortcut.Description = 'CertBaton developer preview'
    $shortcut.Save()

    New-Item -Path $uninstallKey -Force | Out-Null
    $uninstallScript = Join-Path $InstallRoot `
        'Tools\uninstall-developer-package.ps1'
    $uninstallString =
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f
        $uninstallScript
    New-ItemProperty -Path $uninstallKey -Name DisplayName `
        -Value 'CertBaton Developer Preview' `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayVersion `
        -Value ([string]$manifest.version) `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name Publisher `
        -Value 'CertBaton contributors' `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name InstallLocation `
        -Value $InstallRoot -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayIcon `
        -Value (Join-Path $InstallRoot 'Desktop\CertBaton.Desktop.exe') `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString `
        -Value $uninstallString -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify `
        -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoRepair `
        -Value 1 -PropertyType DWord -Force | Out-Null

    Start-Service -Name $serviceName
    Wait-ForServiceStatus -Status 'Running'

    $installedAuditPath = Join-Path $InstallRoot `
        'Tools\test-installed-developer-package.ps1'
    $deepAuditOutput = @(
        & $installedAuditPath -InstallRoot $InstallRoot -DataRoot $DataRoot `
            -MaintenanceExpected 2>&1
    )
    if (-not (Test-Path -LiteralPath $maintenanceMarkerPath -PathType Leaf)) {
        throw 'The maintenance marker disappeared during the installed audit.'
    }

    Stop-Service -Name $serviceName -Force
    Wait-ForServiceStatus -Status 'Stopped'
    $acceptedState = Invoke-OfflineStateInspection `
        -ServiceExecutable $serviceExecutable `
        -DatabasePath $databasePath
    if (-not $acceptedState.DatabaseExists -or
        [int]$acceptedState.ApplicationId -ne $certBatonApplicationId -or
        [int]$acceptedState.SchemaVersion -ne
            [int]$manifest.stateSchema.current -or
        $acceptedState.IntegrityCheck -cne 'ok' -or
        [int64]$acceptedState.ActiveLiveOperationCount -ne 0) {
        throw (
            'The migrated database did not pass the exact offline ' +
            'post-audit schema, integrity, and idle-state checks.')
    }
    $commitBoundaryCrossed = $true
    Remove-ValidatedMaintenanceMarker -Path $maintenanceMarkerPath
    $maintenanceMarkerCreated = $false
    Set-ServiceProductionConfiguration
    Start-Service -Name $serviceName
    Wait-ForServiceStatus -Status 'Running'

    $cliPath = Join-Path $InstallRoot 'Cli\certbatonctl.exe'
    $healthOutput = Wait-ForCliHealth -CliPath $cliPath

    try {
        if ($snapshotCreated -and (Test-Path -LiteralPath $snapshotRoot)) {
            $null = Get-ValidatedSnapshotInventory -SnapshotRoot $snapshotRoot
            Remove-ExactOperationalTree -Path $snapshotRoot `
                -ExpectedPath $snapshotRoot
            $snapshotCreated = $false
        }
        if ($backupCreated -and (Test-Path -LiteralPath $backupRoot)) {
            Assert-NoReparsePointsInTree -Path $backupRoot
            Remove-Item -LiteralPath $backupRoot -Recurse -Force
            $backupCreated = $false
        }
    }
    catch {
        Write-Warning (
            'The installation was accepted, but a verified rollback ' +
            "snapshot could not be removed: $($_.Exception.Message)")
    }

    [pscustomobject]@{
        Product = 'CertBaton'
        Channel = 'developer-preview'
        Version = [string]$manifest.version
        InstallRoot = $InstallRoot
        DataRoot = $DataRoot
        ServiceName = $serviceName
        ServiceStatus = 'Running'
        Health = ($healthOutput -join [Environment]::NewLine)
        StateInspection = $acceptedState
        InstalledAudit = ($deepAuditOutput -join [Environment]::NewLine)
    } | ConvertTo-Json
}
catch {
    $installError = $_
    try {
        Disable-ServiceStartupAndRestarts
        if ((Test-Path -LiteralPath $DataRoot -PathType Container) -and
            -not (Test-Path -LiteralPath $maintenanceMarkerPath)) {
            Write-MaintenanceMarker -Path $maintenanceMarkerPath `
                -SourceCommit ([string]$manifest.sourceCommit)
            $maintenanceMarkerCreated = $true
        }

        if ($commitBoundaryCrossed) {
            Write-Warning (
                'The new installation crossed its durable commit boundary ' +
                'but did not become healthy. New binaries and operational ' +
                'data were retained, automatic service startup was disabled, ' +
                "and maintenance remains active at '$maintenanceMarkerPath'. " +
                'Run a reviewed repair; no snapshot rollback was attempted.')
        }
        else {
            if ($replacementCommitted -and
                (Test-Path -LiteralPath $InstallRoot)) {
                Assert-NoReparsePointsInTree -Path $InstallRoot
                Remove-ExactOperationalTree -Path $InstallRoot `
                    -ExpectedPath (Join-Path $env:ProgramFiles 'CertBaton')
            }
            if ($backupCreated -and (Test-Path -LiteralPath $backupRoot)) {
                Assert-NoReparsePointsInTree -Path $backupRoot
                Move-Item -LiteralPath $backupRoot -Destination $InstallRoot
                $backupCreated = $false
            }

            if ($snapshotCreated -and (Test-Path -LiteralPath $snapshotRoot)) {
                Restore-OperationalDataSnapshot -Root $DataRoot `
                    -SnapshotRoot $snapshotRoot
            }

            if (-not $serviceExisted -and
                $null -ne (Get-CertBatonServiceRecord)) {
                Invoke-Sc -Arguments @(
                    'delete', $serviceName
                ) | Out-Null
            }
            elseif ($serviceExisted) {
                Set-ServiceProductionConfiguration
            }

            if (-not $serviceExisted) {
                $commonPrograms = [Environment]::GetFolderPath(
                    'CommonPrograms')
                $shortcutDirectory = Join-Path $commonPrograms 'CertBaton'
                if (Test-Path -LiteralPath $shortcutDirectory) {
                    Remove-Item -LiteralPath $shortcutDirectory `
                        -Recurse -Force
                }
                if ([Diagnostics.EventLog]::SourceExists($serviceName)) {
                    Remove-EventLog -Source $serviceName
                }
                if (Test-Path -LiteralPath $uninstallKey) {
                    Remove-Item -LiteralPath $uninstallKey -Recurse -Force
                }
            }
            elseif ($null -ne $existingMarker -and
                (Test-Path -LiteralPath $uninstallKey) -and
                @($existingMarker.PSObject.Properties.Name) -contains 'version') {
                New-ItemProperty -Path $uninstallKey -Name DisplayVersion `
                    -Value ([string]$existingMarker.version) `
                    -PropertyType String -Force | Out-Null
            }

            if (Test-Path -LiteralPath $maintenanceMarkerPath) {
                Remove-ValidatedMaintenanceMarker -Path $maintenanceMarkerPath
                $maintenanceMarkerCreated = $false
            }

            if ($serviceExisted -and $serviceWasRunning -and
                (Test-Path -LiteralPath $expectedServiceExecutable)) {
                Start-Service -Name $serviceName
                Wait-ForServiceStatus -Status 'Running'
                $oldCliPath = Join-Path $InstallRoot 'Cli\certbatonctl.exe'
                $null = Wait-ForCliHealth -CliPath $oldCliPath
            }

            if ($snapshotCreated -and (Test-Path -LiteralPath $snapshotRoot)) {
                $null = Get-ValidatedSnapshotInventory `
                    -SnapshotRoot $snapshotRoot
                Remove-ExactOperationalTree -Path $snapshotRoot `
                    -ExpectedPath $snapshotRoot
                $snapshotCreated = $false
            }

            if (-not $serviceExisted -and -not $dataRootExisted -and
                (Test-Path -LiteralPath $DataRoot)) {
                Remove-ExactOperationalTree -Path $DataRoot `
                    -ExpectedPath (Join-Path $env:ProgramData 'CertBaton')
            }
        }
    }
    catch {
        $rollbackError = $_
        try {
            Disable-ServiceStartupAndRestarts
            if ((Test-Path -LiteralPath $DataRoot -PathType Container) -and
                -not (Test-Path -LiteralPath $maintenanceMarkerPath)) {
                Write-MaintenanceMarker -Path $maintenanceMarkerPath `
                    -SourceCommit ([string]$manifest.sourceCommit)
                $maintenanceMarkerCreated = $true
            }
        }
        catch {
            $barrierError = $_
            Write-Warning (
                'The installer could not re-establish its final maintenance ' +
                "barrier: $($barrierError.Exception.Message)")
        }
        Write-Warning (
            'The developer installer encountered an additional rollback ' +
            "error: $($rollbackError.Exception.Message)")
    }

    throw $installError
}
finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}
