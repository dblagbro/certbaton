[CmdletBinding()]
param(
    [string] $PackageRoot = $PSScriptRoot,

    [string] $InstallRoot = (Join-Path $env:ProgramFiles 'CertBaton'),

    [string] $DataRoot = (Join-Path $env:ProgramData 'CertBaton')
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

        [switch] $GrantUsersReadExecute
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

    $acl.AddAccessRule(
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $serviceSid,
            $ServiceRights,
            $inheritance,
            $propagation,
            $allow)))
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
    New-Item -ItemType Directory -Path $Root -Force | Out-Null

    $null = Assert-LocalFixedNtfsPath -Path $Root
    Assert-NoReparsePointsInTree -Path $Root
    Set-ProtectedDirectoryAcl -Path $Root `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)

    New-Item -ItemType Directory -Path $statePath -Force | Out-Null
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    foreach ($protectedPath in @($statePath, $backupPath)) {
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
    $manifest.runtime -ne 'win-x64' -or
    -not $manifest.selfContained) {
    throw 'The package manifest does not describe a supported CertBaton developer package.'
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
        version = [string]$manifest.version
        sourceCommit = [string]$manifest.sourceCommit
        installedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json |
        Set-Content -LiteralPath (
            Join-Path $stagingRoot 'install-metadata.json') -Encoding UTF8

    Set-ProtectedDirectoryAcl -Path $stagingRoot `
        -ServiceRights (
            [Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -GrantUsersReadExecute
    Reset-DescendantAcls -Path $stagingRoot

    if ($serviceExisted) {
        $service = Get-Service -Name $serviceName
        if ($service.Status -ne
            [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $serviceName -Force
            Wait-ForServiceStatus -Status 'Stopped'
        }
    }

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
        StartMode = 'Automatic'
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
            StartMode = 'Automatic'
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

    Invoke-Sc -Arguments @(
        'config', $serviceName,
        'start=', 'delayed-auto'
    ) | Out-Null

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
        'failure', $serviceName,
        'reset=', '86400',
        'actions=', 'restart/5000/restart/15000/restart/60000'
    ) | Out-Null
    Invoke-Sc -Arguments @(
        'failureflag', $serviceName, '1'
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

    Set-OperationalDataSecurity -Root $DataRoot

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

    $cliPath = Join-Path $InstallRoot 'Cli\certbatonctl.exe'
    $healthSucceeded = $false
    $healthOutput = @()
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $healthOutput = & $cliPath health --json 2>&1
            if ($LASTEXITCODE -eq 0) {
                $healthSucceeded = $true
                break
            }

            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if (-not $healthSucceeded) {
        throw (
            "The installed service did not pass its health check:" +
            "$([Environment]::NewLine)$($healthOutput -join [Environment]::NewLine)")
    }

    if ($backupCreated -and (Test-Path -LiteralPath $backupRoot)) {
        Remove-Item -LiteralPath $backupRoot -Recurse -Force
        $backupCreated = $false
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
    } | ConvertTo-Json
}
catch {
    $installError = $_
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -ne
            [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(15))
        }

        if ($replacementCommitted -and
            (Test-Path -LiteralPath $InstallRoot)) {
            Remove-Item -LiteralPath $InstallRoot -Recurse -Force
        }
        if ($backupCreated -and (Test-Path -LiteralPath $backupRoot)) {
            Move-Item -LiteralPath $backupRoot -Destination $InstallRoot
        }
        if (-not $serviceExisted -and
            $null -ne (Get-CertBatonServiceRecord)) {
            Invoke-Sc -Arguments @(
                'delete', $serviceName
            ) | Out-Null
        }
        elseif ($serviceExisted -and
            (Test-Path -LiteralPath $expectedServiceExecutable)) {
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
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
    }
    catch {
        Write-Warning (
            'The developer installer encountered an additional rollback ' +
            "error: $($_.Exception.Message)")
    }

    throw $installError
}
finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}
