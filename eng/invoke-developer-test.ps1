[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $TestScriptPath,

    [Parameter(Mandatory = $true)]
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $output = & $TestScriptPath 2>&1
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
