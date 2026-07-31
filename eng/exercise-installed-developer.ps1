[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramFiles 'CertBaton')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'CertBaton'
$cliPath = Join-Path $InstallRoot 'Cli\certbatonctl.exe'

function Assert-ElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The installed exercise must run from an elevated session.'
    }
}

function Invoke-CertBatonCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [switch] $AllowFailure
    )

    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $cliPath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw (
            "certbatonctl $($Arguments -join ' ') failed with code " +
            "$exitCode`:$([Environment]::NewLine)$($output -join [Environment]::NewLine)")
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = ($output -join [Environment]::NewLine)
    }
}

function Start-Simulation {
    param(
        [string] $FailureStage
    )

    $arguments = @('simulation', 'start', '--json')
    if (-not [string]::IsNullOrWhiteSpace($FailureStage)) {
        $arguments += @('--fail-stage', $FailureStage)
    }

    $result = Invoke-CertBatonCli -Arguments $arguments
    return $result.Output | ConvertFrom-Json
}

function Get-LatestSimulation {
    $result = Invoke-CertBatonCli `
        -Arguments @('simulation', 'latest', '--json') `
        -AllowFailure
    if ($result.ExitCode -ne 0) {
        return $null
    }

    return $result.Output | ConvertFrom-Json
}

function Wait-ForRunStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RunId,

        [Parameter(Mandatory = $true)]
        [string[]] $Statuses,

        [int] $TimeoutSeconds = 45
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $latest = Get-LatestSimulation
        if ($null -ne $latest -and
            $latest.runId -eq $RunId -and
            $Statuses -contains [string]$latest.status) {
            return $latest
        }

        Start-Sleep -Milliseconds 150
    }

    throw (
        "Simulation '$RunId' did not reach one of the expected states: " +
        "$($Statuses -join ', ').")
}

function Wait-ForReplacementServiceProcess {
    param(
        [Parameter(Mandatory = $true)]
        [uint32] $PreviousProcessId,

        [int] $TimeoutSeconds = 45
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-CimInstance Win32_Service `
            -Filter "Name='$serviceName'" `
            -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.State -eq 'Running' -and
            $service.ProcessId -ne 0 -and
            $service.ProcessId -ne $PreviousProcessId) {
            $health = Invoke-CertBatonCli `
                -Arguments @('health', '--json') `
                -AllowFailure
            if ($health.ExitCode -eq 0) {
                return $service
            }
        }

        Start-Sleep -Milliseconds 250
    }

    throw 'The service did not recover with a replacement process.'
}

Assert-ElevatedAdministrator
if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
    throw "The installed CLI is missing: '$cliPath'."
}

$successAccepted = Start-Simulation
$successRun = Wait-ForRunStatus `
    -RunId ([string]$successAccepted.runId) `
    -Statuses @('succeeded')

$failureAccepted = Start-Simulation -FailureStage 'verification'
$failureRun = Wait-ForRunStatus `
    -RunId ([string]$failureAccepted.runId) `
    -Statuses @('failed')
if ($failureRun.terminalStage -ne 'verification' -or
    $failureRun.outcome -ne 'failed') {
    throw 'The injected verification failure did not remain a proven failure.'
}

$interruptionAccepted = Start-Simulation
$runningRun = Wait-ForRunStatus `
    -RunId ([string]$interruptionAccepted.runId) `
    -Statuses @('running')
$serviceBeforeKill = Get-CimInstance Win32_Service `
    -Filter "Name='$serviceName'"
if ($serviceBeforeKill.ProcessId -eq 0) {
    throw 'The running CertBaton service did not have a process identifier.'
}

$oldProcessId = [uint32]$serviceBeforeKill.ProcessId
Stop-Process -Id $oldProcessId -Force
$serviceAfterKill = Wait-ForReplacementServiceProcess `
    -PreviousProcessId $oldProcessId
$interruptedRun = Wait-ForRunStatus `
    -RunId ([string]$interruptionAccepted.runId) `
    -Statuses @('interrupted')
if ($interruptedRun.outcome -ne 'interrupted') {
    throw 'The killed service run was not recorded as interrupted.'
}

$recoveryAccepted = Start-Simulation
$recoveryRun = Wait-ForRunStatus `
    -RunId ([string]$recoveryAccepted.runId) `
    -Statuses @('succeeded')

[pscustomobject]@{
    Product = 'CertBaton'
    Exercise = 'installed-developer-simulations'
    SuccessfulRun = [pscustomobject]@{
        RunId = $successRun.runId
        Status = $successRun.status
        EvidenceCount = @($successRun.evidence).Count
    }
    InjectedFailureRun = [pscustomobject]@{
        RunId = $failureRun.runId
        Status = $failureRun.status
        TerminalStage = $failureRun.terminalStage
        EvidenceCount = @($failureRun.evidence).Count
    }
    InterruptedRun = [pscustomobject]@{
        RunId = $interruptedRun.runId
        Status = $interruptedRun.status
        OldServiceProcessId = $oldProcessId
        NewServiceProcessId = [uint32]$serviceAfterKill.ProcessId
        EvidenceCount = @($interruptedRun.evidence).Count
    }
    PostRecoveryRun = [pscustomobject]@{
        RunId = $recoveryRun.runId
        Status = $recoveryRun.status
        EvidenceCount = @($recoveryRun.evidence).Count
    }
    CompletedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 6
