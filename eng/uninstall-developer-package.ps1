[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramFiles 'CertBaton'),

    [string] $DataRoot = (Join-Path $env:ProgramData 'CertBaton'),

    [switch] $RemoveData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'CertBaton'
$uninstallKey =
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CertBatonDeveloper'

function Assert-ElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw (
            'This developer uninstaller must run from an elevated Windows ' +
            'PowerShell session.')
    }
}

function Assert-ExactRemovalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Actual,

        [Parameter(Mandatory = $true)]
        [string] $Expected
    )

    $actualFull = [IO.Path]::GetFullPath($Actual).TrimEnd('\')
    $expectedFull = [IO.Path]::GetFullPath($Expected).TrimEnd('\')
    if ($actualFull -ine $expectedFull) {
        throw (
            "Refusing recursive removal because '$actualFull' is not the " +
            "expected path '$expectedFull'.")
    }

    return $actualFull
}

function Get-ServiceRecord {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'" `
        -ErrorAction SilentlyContinue
}

function Assert-NoReparsePointsInTree {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $rootItem = Get-Item -LiteralPath $Path -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove the reparse-point path '$Path'."
    }

    $reparsePoint = Get-ChildItem -LiteralPath $Path -Recurse -Force |
        Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        } |
        Select-Object -First 1
    if ($null -ne $reparsePoint) {
        throw (
            'Refusing recursive removal because the tree contains a ' +
            "reparse point: '$($reparsePoint.FullName)'.")
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
            'Close the CertBaton desktop application before uninstalling ' +
            'the developer preview.')
    }
}

Assert-ElevatedAdministrator
$InstallRoot = Assert-ExactRemovalPath `
    -Actual $InstallRoot `
    -Expected (Join-Path $env:ProgramFiles 'CertBaton')
$DataRoot = Assert-ExactRemovalPath `
    -Actual $DataRoot `
    -Expected (Join-Path $env:ProgramData 'CertBaton')

$markerPath = Join-Path $InstallRoot 'install-metadata.json'
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    throw (
        "The install directory has no developer installation marker. " +
        "Refusing to uninstall '$InstallRoot'.")
}

$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.product -ne 'CertBaton' -or
    $marker.channel -ne 'developer-preview') {
    throw (
        "The install directory marker is not a CertBaton developer " +
        "installation. Refusing to uninstall '$InstallRoot'.")
}

Assert-NoReparsePointsInTree -Path $InstallRoot
if ($RemoveData -and (Test-Path -LiteralPath $DataRoot)) {
    Assert-NoReparsePointsInTree -Path $DataRoot
}
Assert-DesktopNotRunning -Root $InstallRoot

$expectedServiceExecutable = Join-Path $InstallRoot `
    'Service\CertBaton.Service.exe'
$expectedImagePath = '"{0}"' -f $expectedServiceExecutable
$serviceRecord = Get-ServiceRecord
if ($null -ne $serviceRecord -and
    $serviceRecord.PathName -ine $expectedImagePath) {
    throw (
        "A service named '$serviceName' has an unexpected image path. " +
        "Refusing to remove it: '$($serviceRecord.PathName)'.")
}

if ($null -ne $serviceRecord) {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne
        [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30))
    }

    $deleteOutput = & sc.exe delete $serviceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw (
            "Unable to delete the CertBaton service:" +
            "$([Environment]::NewLine)$($deleteOutput -join [Environment]::NewLine)")
    }

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($null -eq (Get-ServiceRecord)) {
            break
        }

        Start-Sleep -Milliseconds 250
    }
    if ($null -ne (Get-ServiceRecord)) {
        throw 'The CertBaton service remained pending deletion.'
    }
}

$commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
$shortcutDirectory = Join-Path $commonPrograms 'CertBaton'
if (Test-Path -LiteralPath $shortcutDirectory) {
    Remove-Item -LiteralPath $shortcutDirectory -Recurse -Force
}

if ([Diagnostics.EventLog]::SourceExists($serviceName)) {
    Remove-EventLog -Source $serviceName
}

if (Test-Path -LiteralPath $uninstallKey) {
    Remove-Item -LiteralPath $uninstallKey -Recurse -Force
}

if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

$dataDisposition = 'retained'
if ($RemoveData -and (Test-Path -LiteralPath $DataRoot)) {
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    $dataDisposition = 'removed'
}

[pscustomobject]@{
    Product = 'CertBaton'
    Channel = 'developer-preview'
    ServiceRemoved = $true
    InstallRootRemoved = -not (Test-Path -LiteralPath $InstallRoot)
    DataRoot = $DataRoot
    DataDisposition = $dataDisposition
} | ConvertTo-Json
