[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackageRoot,

    [Parameter(Mandatory = $true)]
    [string] $LogPath,

    [string] $InstallerPath,

    [switch] $AllowDeveloperSourceChange,

    [switch] $AllowDeveloperDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $InstallerPath = Join-Path $PackageRoot 'install-developer-package.ps1'
}
try {
    $installerArguments = @{
        PackageRoot = $PackageRoot
        AllowDeveloperSourceChange = $AllowDeveloperSourceChange
        AllowDeveloperDowngrade = $AllowDeveloperDowngrade
    }
    $output = & $InstallerPath @installerArguments 2>&1
    $output | Out-File -LiteralPath $LogPath -Encoding UTF8
    $output
    exit 0
}
catch {
    $details = $_ | Format-List * -Force | Out-String
    $details | Out-File -LiteralPath $LogPath -Encoding UTF8
    Write-Error $details
    exit 1
}
