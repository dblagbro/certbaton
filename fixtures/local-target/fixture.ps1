[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "init",
        "config",
        "up",
        "down",
        "reset",
        "status",
        "logs",
        "smoke",
        "inject",
        "connection")]
    [string] $Command = "status",

    [Parameter(Position = 1)]
    [ValidateSet(
        "none",
        "unwritable-challenge",
        "invalid-config",
        "reload-failure",
        "stale-endpoint",
        "rollback-failure",
        "stale-rollback-failure")]
    [string] $Mode = "none"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$FixtureRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$ComposeFile = Join-Path $FixtureRoot "compose.yaml"
$RuntimeRoot = Join-Path $FixtureRoot "runtime"
$PrivateKey = Join-Path $RuntimeRoot "ssh\fixture_ed25519"
$PublicKey = "$PrivateKey.pub"
$KnownHosts = Join-Path $RuntimeRoot "ssh\known_hosts"
$FixtureHostname = "certbaton-fixture.test"

function Get-Settings {
    $settings = @{
        SSH = 12222
        HTTP = 18080
        HTTPS = 18443
    }

    $envFile = Join-Path $FixtureRoot ".env"
    if (Test-Path -LiteralPath $envFile) {
        foreach ($line in Get-Content -LiteralPath $envFile) {
            if ($line -match "^\s*CERTBATON_FIXTURE_(SSH|HTTP|HTTPS)_PORT\s*=\s*(\d+)\s*$") {
                $settings[$Matches[1]] = [int] $Matches[2]
            }
        }
    }

    foreach ($name in @("SSH", "HTTP", "HTTPS")) {
        $environmentName = "CERTBATON_FIXTURE_${name}_PORT"
        $environmentValue = [Environment]::GetEnvironmentVariable($environmentName)
        if ($environmentValue) {
            $settings[$name] = [int] $environmentValue
        }
        if ($settings[$name] -lt 1 -or $settings[$name] -gt 65535) {
            throw "$environmentName must be a valid TCP port."
        }
    }

    return $settings
}

function Assert-ScopedChild {
    param([Parameter(Mandatory)][string] $Path)

    $candidate = [IO.Path]::GetFullPath($Path)
    $prefix = $FixtureRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar

    if (-not $candidate.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing an operation outside the fixture root: $candidate"
    }
}

function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $rootItem = Get-Item -LiteralPath $Path -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a recursive operation through a reparse point: $Path"
    }

    $nestedReparsePoint = Get-ChildItem `
        -LiteralPath $Path `
        -Force `
        -Recurse `
        -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        } |
        Select-Object -First 1
    if ($nestedReparsePoint) {
        throw "Refusing a recursive operation containing a reparse point: $($nestedReparsePoint.FullName)"
    }
}

function Invoke-Compose {
    param([Parameter(Mandatory)][string[]] $Arguments)

    $dockerArguments = @(
        "compose",
        "--project-directory", $FixtureRoot,
        "--file", $ComposeFile
    ) + $Arguments

    & docker @dockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE."
    }
}

function Assert-DockerEngine {
    $null = & docker version --format "{{.Server.Version}}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The local Linux-container Docker engine is not available."
    }
}

function Initialize-Runtime {
    foreach ($directory in @(
            (Join-Path $RuntimeRoot "ssh"),
            (Join-Path $RuntimeRoot "pki"),
            (Join-Path $RuntimeRoot "smoke"))) {
        Assert-ScopedChild $directory
        $null = New-Item -ItemType Directory -Force -Path $directory
    }

    $privateExists = Test-Path -LiteralPath $PrivateKey
    $publicExists = Test-Path -LiteralPath $PublicKey
    if ($privateExists -xor $publicExists) {
        throw "The generated fixture key pair is incomplete. Run reset after checking that no fixture process is active."
    }

    if (-not $privateExists) {
        $sshKeygen = Get-Command "ssh-keygen.exe" -ErrorAction SilentlyContinue
        if (-not $sshKeygen) {
            $sshKeygen = Get-Command "ssh-keygen" -ErrorAction SilentlyContinue
        }
        if (-not $sshKeygen) {
            throw "ssh-keygen is required to create the disposable development key."
        }

        & $sshKeygen.Source `
            -q `
            -t ed25519 `
            -N '""' `
            -C "certbaton-local-fixture-client" `
            -f $PrivateKey
        if ($LASTEXITCODE -ne 0) {
            throw "ssh-keygen failed."
        }

        if ($env:OS -eq "Windows_NT") {
            $principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls.exe $PrivateKey /inheritance:r /grant:r "${principal}:(F)" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to restrict the generated private-key ACL."
            }
        }
    }

    Write-Host "Runtime initialized with a generated, fixture-only SSH key."
}

function Update-KnownHosts {
    $settings = Get-Settings
    $hostPublicKey = Join-Path $RuntimeRoot "pki\ssh_host_ed25519_key.pub"
    if (-not (Test-Path -LiteralPath $hostPublicKey)) {
        throw "The fixture did not export its synthetic SSH host public key."
    }

    $parts = (Get-Content -LiteralPath $hostPublicKey -Raw).Trim() -split "\s+"
    if ($parts.Count -lt 2 -or $parts[0] -ne "ssh-ed25519") {
        throw "The exported fixture SSH host key is invalid."
    }

    $knownHostLine = "[127.0.0.1]:$($settings.SSH) $($parts[0]) $($parts[1])"
    [IO.File]::WriteAllText($KnownHosts, "$knownHostLine`n")
}

function Invoke-SmokeTest {
    $settings = Get-Settings
    foreach ($program in @("curl.exe", "ssh.exe", "sftp.exe")) {
        if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
            throw "$program is required for the fixture smoke test."
        }
    }

    Update-KnownHosts

    $httpResult = & curl.exe `
        --fail `
        --silent `
        --show-error `
        --noproxy "*" `
        "http://127.0.0.1:$($settings.HTTP)/healthz"
    if ($LASTEXITCODE -ne 0 -or $httpResult.Trim() -ne "fixture-http-ok") {
        throw "The HTTP health check failed."
    }

    $caFile = Join-Path $RuntimeRoot "pki\ca.crt"
    $httpsResult = & curl.exe `
        --fail `
        --silent `
        --show-error `
        --noproxy "*" `
        --cacert $caFile `
        --resolve "${FixtureHostname}:$($settings.HTTPS):127.0.0.1" `
        "https://${FixtureHostname}:$($settings.HTTPS)/healthz"
    if ($LASTEXITCODE -ne 0 -or $httpsResult.Trim() -ne "fixture-tls-ok") {
        throw "The TLS health check failed."
    }

    $commonSshOptions = @(
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=$KnownHosts",
        "-i", $PrivateKey,
        "-p", [string] $settings.SSH
    )
    $remoteUid = & ssh.exe @commonSshOptions "fixture@127.0.0.1" "id -u"
    if ($LASTEXITCODE -ne 0 -or $remoteUid.Trim() -ne "10001") {
        throw "The non-root SSH identity check failed."
    }

    $tokenName = "smoke-$PID"
    $localToken = Join-Path $RuntimeRoot "smoke\$tokenName"
    $remoteToken = "/srv/certbaton/webroot/.well-known/acme-challenge/$tokenName"
    [IO.File]::WriteAllText($localToken, "fixture-sftp-ok")
    $sftpLocalToken = ([IO.Path]::GetFullPath($localToken)).Replace("\", "/")
    $uploadBatch = Join-Path $RuntimeRoot "smoke\upload.batch"
    $removeBatch = Join-Path $RuntimeRoot "smoke\remove.batch"
    [IO.File]::WriteAllText($uploadBatch, "put `"$sftpLocalToken`" `"$remoteToken`"`n")
    [IO.File]::WriteAllText($removeBatch, "rm `"$remoteToken`"`n")

    $sftpOptions = @(
        "-q",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=$KnownHosts",
        "-i", $PrivateKey,
        "-P", [string] $settings.SSH
    )

    try {
        & sftp.exe @sftpOptions -b $uploadBatch "fixture@127.0.0.1"
        if ($LASTEXITCODE -ne 0) {
            throw "The SFTP upload check failed."
        }

        $challengeResult = & curl.exe `
            --fail `
            --silent `
            --show-error `
            --noproxy "*" `
            "http://127.0.0.1:$($settings.HTTP)/.well-known/acme-challenge/$tokenName"
        if ($LASTEXITCODE -ne 0 -or $challengeResult.Trim() -ne "fixture-sftp-ok") {
            throw "The uploaded challenge was not served over HTTP."
        }
    }
    finally {
        & sftp.exe @sftpOptions -b $removeBatch "fixture@127.0.0.1" 2>$null
    }

    Write-Host "PASS: HTTP, trusted synthetic TLS, non-root SSH, SFTP, and challenge serving."
}

switch ($Command) {
    "init" {
        Initialize-Runtime
    }
    "config" {
        Initialize-Runtime
        Invoke-Compose @("config", "--quiet")
        Write-Host "PASS: compose model is valid."
    }
    "up" {
        Initialize-Runtime
        Assert-DockerEngine
        Invoke-Compose @("up", "--build", "--detach", "--wait", "--wait-timeout", "120")
        Update-KnownHosts
        Write-Host "Fixture is healthy and bound only to loopback."
    }
    "down" {
        Assert-DockerEngine
        Invoke-Compose @("down", "--remove-orphans")
    }
    "reset" {
        Assert-DockerEngine
        Invoke-Compose @("down", "--volumes", "--remove-orphans")
        foreach ($name in @("ssh", "pki", "smoke")) {
            $path = Join-Path $RuntimeRoot $name
            Assert-ScopedChild $path
            if (Test-Path -LiteralPath $path) {
                Assert-NoReparsePoint $path
                Remove-Item -LiteralPath $path -Recurse -Force
            }
        }
        Initialize-Runtime
        Write-Host "Fixture state reset. The next up creates new synthetic host and TLS identities."
    }
    "status" {
        Assert-DockerEngine
        Invoke-Compose @("ps")
    }
    "logs" {
        Assert-DockerEngine
        Invoke-Compose @("logs", "--tail", "200", "target")
    }
    "smoke" {
        Assert-DockerEngine
        Invoke-SmokeTest
    }
    "inject" {
        Assert-DockerEngine
        Invoke-Compose @(
            "exec",
            "--no-TTY",
            "--user", "0",
            "target",
            "/usr/local/sbin/fixture-inject",
            $Mode)
    }
    "connection" {
        Initialize-Runtime
        $settings = Get-Settings
        Write-Host "Host: 127.0.0.1"
        Write-Host "SSH port: $($settings.SSH)"
        Write-Host "HTTP port: $($settings.HTTP)"
        Write-Host "HTTPS port: $($settings.HTTPS)"
        Write-Host "SSH user: fixture"
        Write-Host "Identity file: $PrivateKey"
        Write-Host "Synthetic TLS name: $FixtureHostname"
    }
}
