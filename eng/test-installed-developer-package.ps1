[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramFiles 'CertBaton'),

    [string] $DataRoot = (Join-Path $env:ProgramData 'CertBaton')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'CertBaton'
$serviceSidValue =
    'S-1-5-80-2998542184-680993539-724725283-631637665-607464993'
$serviceDacl =
    'D:P' +
    '(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)' +
    '(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' +
    '(A;;LC;;;BU)'
$uninstallKey =
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CertBatonDeveloper'

function Assert-ElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The installed audit must run from an elevated session.'
    }
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)]
        [bool] $Condition,

        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-NormalizedRules {
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.DirectorySecurity] $Acl
    )

    $normalized = @{}
    $rules = $Acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        Assert-Condition `
            -Condition (-not $rule.IsInherited) `
            -Message 'An expected protected directory contains an inherited ACE.'
        Assert-Condition `
            -Condition (
                $rule.AccessControlType -eq
                [Security.AccessControl.AccessControlType]::Allow) `
            -Message 'An expected protected directory contains a deny ACE.'
        Assert-Condition `
            -Condition (
                $rule.InheritanceFlags -eq (
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit)) `
            -Message 'A protected directory ACE has unexpected inheritance flags.'
        Assert-Condition `
            -Condition (
                $rule.PropagationFlags -eq
                [Security.AccessControl.PropagationFlags]::None) `
            -Message 'A protected directory ACE has unexpected propagation flags.'

        $sid = $rule.IdentityReference.Value
        $current = 0
        if ($normalized.ContainsKey($sid)) {
            $current = [int]$normalized[$sid]
        }
        $normalized[$sid] = $current -bor [int]$rule.FileSystemRights
    }

    return $normalized
}

function Assert-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [hashtable] $ExpectedRules
    )

    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    Assert-Condition -Condition ($owner -eq 'S-1-5-18') `
        -Message "'$Path' is not owned by SYSTEM."
    Assert-Condition -Condition $acl.AreAccessRulesProtected `
        -Message "'$Path' does not have protected inheritance."

    $actualRules = Get-NormalizedRules -Acl $acl
    Assert-Condition `
        -Condition ($actualRules.Count -eq $ExpectedRules.Count) `
        -Message "'$Path' has an unexpected number of access principals."
    foreach ($sid in $ExpectedRules.Keys) {
        Assert-Condition `
            -Condition ($actualRules.ContainsKey($sid)) `
            -Message "'$Path' is missing its required '$sid' access rule."
        Assert-Condition `
            -Condition (
                [int]$actualRules[$sid] -eq [int]$ExpectedRules[$sid]) `
            -Message "'$Path' grants unexpected rights to '$sid'."
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        Assert-Condition `
            -Condition (
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -eq 0) `
            -Message "The installed path contains a reparse point: '$cursor'."
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $cursor = $parent.FullName
    }
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
            "The installed tree contains a reparse point: " +
            "'$($reparsePoint.FullName)'.")
    }
}

function Assert-InstalledPayloadMatchesManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $manifestPath = Join-Path $Root 'package-manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw |
        ConvertFrom-Json
    foreach ($entry in @($manifest.files)) {
        $relativePath = [string]$entry.path
        if (-not $relativePath.StartsWith(
                'payload/',
                [StringComparison]::Ordinal)) {
            continue
        }

        $installedRelativePath = $relativePath.Substring('payload/'.Length)
        $installedPath = Join-Path $Root `
            $installedRelativePath.Replace('/', '\')
        Assert-Condition `
            -Condition (Test-Path -LiteralPath $installedPath -PathType Leaf) `
            -Message "An installed payload file is missing: '$installedPath'."
        $installedFile = Get-Item -LiteralPath $installedPath
        Assert-Condition `
            -Condition ($installedFile.Length -eq [int64]$entry.size) `
            -Message "An installed payload file has the wrong size: '$installedPath'."
        $installedHash = (
            Get-FileHash -LiteralPath $installedPath -Algorithm SHA256
        ).Hash
        Assert-Condition `
            -Condition ($installedHash -ieq [string]$entry.sha256) `
            -Message "An installed payload file has the wrong hash: '$installedPath'."
    }
}

Assert-ElevatedAdministrator

$requiredFiles = @(
    (Join-Path $InstallRoot 'Service\CertBaton.Service.exe'),
    (Join-Path $InstallRoot 'Desktop\CertBaton.Desktop.exe'),
    (Join-Path $InstallRoot 'Cli\certbatonctl.exe'),
    (Join-Path $InstallRoot 'install-metadata.json'),
    (Join-Path $InstallRoot 'package-manifest.json'),
    $DataRoot,
    (Join-Path $DataRoot 'State'),
    (Join-Path $DataRoot 'Backups')
)
foreach ($requiredFile in $requiredFiles) {
    Assert-Condition `
        -Condition (Test-Path -LiteralPath $requiredFile) `
        -Message "An installed CertBaton path is missing: '$requiredFile'."
}

Assert-NoReparsePoint -Path $InstallRoot
Assert-NoReparsePoint -Path $DataRoot
Assert-NoReparsePoint -Path (Join-Path $DataRoot 'State')
Assert-NoReparsePoint -Path (Join-Path $DataRoot 'Backups')
Assert-NoReparsePointsInTree -Path $InstallRoot
Assert-NoReparsePointsInTree -Path $DataRoot
Assert-NoReparsePointsInTree -Path (Join-Path $DataRoot 'State')
Assert-NoReparsePointsInTree -Path (Join-Path $DataRoot 'Backups')
Assert-InstalledPayloadMatchesManifest -Root $InstallRoot

$serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
Assert-Condition -Condition ($null -ne $serviceRecord) `
    -Message 'The CertBaton Windows Service is not registered.'
$expectedImagePath = '"{0}"' -f (
    Join-Path $InstallRoot 'Service\CertBaton.Service.exe')
Assert-Condition `
    -Condition ($serviceRecord.PathName -ieq $expectedImagePath) `
    -Message (
        "The service image path is not the expected quoted path. Expected " +
        "'$expectedImagePath'; found '$($serviceRecord.PathName)'.")
$storedImagePath = Get-ItemPropertyValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
    -Name ImagePath
Assert-Condition `
    -Condition ($storedImagePath -ceq $expectedImagePath) `
    -Message (
        "The service registry ImagePath is not quoted exactly. Expected " +
        "'$expectedImagePath'; found '$storedImagePath'.")
Assert-Condition `
    -Condition ($serviceRecord.StartName -ieq "NT SERVICE\$serviceName") `
    -Message 'The service does not use the dedicated CertBaton virtual account.'
Assert-Condition -Condition ($serviceRecord.StartMode -eq 'Auto') `
    -Message 'The service is not configured for automatic start.'
Assert-Condition -Condition ($serviceRecord.State -eq 'Running') `
    -Message 'The CertBaton service is not running.'

$delayedAutoStart = Get-ItemPropertyValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
    -Name DelayedAutoStart
Assert-Condition -Condition ($delayedAutoStart -eq 1) `
    -Message 'The service is not configured for delayed automatic start.'

$serviceRegistryPath =
    "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$serviceSidType = Get-ItemPropertyValue -Path $serviceRegistryPath `
    -Name ServiceSidType
Assert-Condition -Condition ($serviceSidType -eq 1) `
    -Message 'The CertBaton service SID type is not unrestricted.'

$resolvedServiceSid = (
    New-Object Security.Principal.NTAccount(
        'NT SERVICE',
        $serviceName)
).Translate([Security.Principal.SecurityIdentifier]).Value
Assert-Condition -Condition ($resolvedServiceSid -ceq $serviceSidValue) `
    -Message 'The resolved CertBaton service SID is not the expected SID.'

$securityOutput = @(& sc.exe sdshow $serviceName 2>&1)
Assert-Condition -Condition ($LASTEXITCODE -eq 0) `
    -Message 'Unable to query the CertBaton service security descriptor.'
$actualServiceSddl = @(
    $securityOutput |
        ForEach-Object { ([string]$_).Trim() } |
        Where-Object { $_ -match '^(O:|G:|D:|S:)' }
) | Select-Object -First 1
$actualServiceDacl = [regex]::Match(
    $actualServiceSddl,
    'D:.*?(?=S:|$)').Value
Assert-Condition -Condition ($actualServiceDacl -ceq $serviceDacl) `
    -Message (
        'The CertBaton service DACL is not exact. Expected ' +
        "'$serviceDacl'; found '$actualServiceDacl'.")

$expectedFailureActions =
    '80-51-01-00-00-00-00-00-00-00-00-00-03-00-00-00-' +
    '14-00-00-00-01-00-00-00-88-13-00-00-01-00-00-00-' +
    '98-3A-00-00-01-00-00-00-60-EA-00-00'
$failureActions = Get-ItemPropertyValue -Path $serviceRegistryPath `
    -Name FailureActions
$actualFailureActions = [BitConverter]::ToString($failureActions)
Assert-Condition -Condition (
    $actualFailureActions -ceq $expectedFailureActions) `
    -Message 'The service restart actions, delays, or reset period are not exact.'
$failureActionsOnNonCrash = Get-ItemPropertyValue `
    -Path $serviceRegistryPath `
    -Name FailureActionsOnNonCrashFailures
Assert-Condition -Condition ($failureActionsOnNonCrash -eq 1) `
    -Message 'The service failure-actions flag is not enabled.'

$fullControl = [int][Security.AccessControl.FileSystemRights]::FullControl
$readExecute = [int](
    [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [Security.AccessControl.FileSystemRights]::Synchronize)
$modify = [int](
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::Synchronize)

Assert-ProtectedAcl -Path $InstallRoot -ExpectedRules @{
    'S-1-5-18' = $fullControl
    'S-1-5-32-544' = $fullControl
    'S-1-5-32-545' = $readExecute
    $serviceSidValue = $readExecute
}
Assert-ProtectedAcl -Path $DataRoot -ExpectedRules @{
    'S-1-5-18' = $fullControl
    'S-1-5-32-544' = $fullControl
    $serviceSidValue = $modify
}
Assert-ProtectedAcl -Path (Join-Path $DataRoot 'State') -ExpectedRules @{
    'S-1-5-18' = $fullControl
    'S-1-5-32-544' = $fullControl
    $serviceSidValue = $modify
}
Assert-ProtectedAcl -Path (Join-Path $DataRoot 'Backups') -ExpectedRules @{
    'S-1-5-18' = $fullControl
    'S-1-5-32-544' = $fullControl
    $serviceSidValue = $modify
}

Assert-Condition `
    -Condition ([Diagnostics.EventLog]::SourceExists($serviceName)) `
    -Message 'The CertBaton Event Log source is missing.'
Assert-Condition `
    -Condition (
        [Diagnostics.EventLog]::LogNameFromSourceName($serviceName, '.') -eq
        'Application') `
    -Message 'The CertBaton Event Log source is registered to the wrong log.'

$shortcutPath = Join-Path (
    Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'CertBaton') `
    'CertBaton.lnk'
Assert-Condition -Condition (Test-Path -LiteralPath $shortcutPath -PathType Leaf) `
    -Message 'The all-users CertBaton Start Menu shortcut is missing.'
Assert-Condition -Condition (Test-Path -LiteralPath $uninstallKey) `
    -Message 'The CertBaton developer uninstall registration is missing.'

$firewallRules = @(
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like '*CertBaton*' -or
            $_.DisplayName -like '*CertBaton*'
        }
)
Assert-Condition -Condition ($firewallRules.Count -eq 0) `
    -Message 'An unexpected CertBaton firewall rule exists.'

$cliPath = Join-Path $InstallRoot 'Cli\certbatonctl.exe'
$healthJson = (& $cliPath health --json 2>&1) -join [Environment]::NewLine
Assert-Condition -Condition ($LASTEXITCODE -eq 0) `
    -Message "The installed CLI health check failed: $healthJson"
$health = $healthJson | ConvertFrom-Json
Assert-Condition -Condition ($health.status -eq 'healthy') `
    -Message 'The installed service did not report healthy.'

[pscustomobject]@{
    Product = 'CertBaton'
    Channel = 'developer-preview'
    ServiceName = $serviceName
    ServiceProcessId = $serviceRecord.ProcessId
    ServiceAccount = $serviceRecord.StartName
    ServiceSid = $resolvedServiceSid
    InstallRoot = $InstallRoot
    DataRoot = $DataRoot
    Health = $health
    FirewallRulesAdded = 0
    VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 5
