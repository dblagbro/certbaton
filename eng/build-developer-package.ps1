[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repositoryRoot 'artifacts\developer'
}

$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$directoryBuildProps = [xml](Get-Content -Raw (
    Join-Path $repositoryRoot 'Directory.Build.props'))
$versionPrefixNode = $directoryBuildProps.SelectSingleNode(
    '/Project/PropertyGroup/VersionPrefix')
$versionSuffixNode = $directoryBuildProps.SelectSingleNode(
    '/Project/PropertyGroup/VersionSuffix')
if ($null -eq $versionPrefixNode) {
    throw 'Directory.Build.props does not define VersionPrefix.'
}

$versionPrefix = [string]$versionPrefixNode.InnerText
$versionSuffix = if ($null -eq $versionSuffixNode) {
    ''
}
else {
    [string]$versionSuffixNode.InnerText
}
$packageVersion = $versionPrefix
if (-not [string]::IsNullOrWhiteSpace($versionSuffix)) {
    $packageVersion = '{0}-{1}' -f $versionPrefix, $versionSuffix
}

$packageName = 'CertBaton-{0}-win-x64' -f $packageVersion
$packageRoot = Join-Path $OutputRoot $packageName
$archivePath = Join-Path $OutputRoot ($packageName + '.zip')

function Get-CleanSourceCommit {
    $commit = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to resolve the source commit.'
    }

    $sourceStatus = (& git.exe -C $repositoryRoot status `
            --porcelain=v1 --untracked-files=all) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the source worktree.'
    }
    if (-not [string]::IsNullOrWhiteSpace($sourceStatus)) {
        throw (
            'Refusing to build a provenance-bearing developer package from ' +
            'a dirty worktree. Commit or remove every source change first.')
    }

    $ignoredItems = @(
        & git.exe -C $repositoryRoot ls-files --others --ignored `
            --exclude-standard --directory
    )
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect ignored worktree content.'
    }
    $unexpectedIgnoredItems = @(
        $ignoredItems |
            Where-Object {
                $_ -notmatch '^(artifacts|publish|packages|\.store|\.vs|\.vscode|\.idea)/' -and
                $_ -notmatch '(^|/)(bin|obj|TestResults)/' -and
                $_ -notmatch '^installer/output/' -and
                $_ -notmatch '^fixtures/local-target/runtime/(pki|smoke|ssh)/'
            }
    )
    if ($unexpectedIgnoredItems.Count -ne 0) {
        throw (
            'Refusing to build while ignored source-adjacent content could ' +
            'influence the package:' +
            [Environment]::NewLine +
            ($unexpectedIgnoredItems -join [Environment]::NewLine))
    }

    return $commit
}

$sourceCommit = Get-CleanSourceCommit

function Remove-DeveloperArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $AllowedRoot
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullAllowedRoot = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $requiredPrefix = $fullAllowedRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith(
            $requiredPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove an artifact outside '$fullAllowedRoot': '$fullPath'."
    }

    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & dotnet.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet exited with code $LASTEXITCODE."
    }
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
Remove-DeveloperArtifact -Path $packageRoot -AllowedRoot $OutputRoot
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}

$payloadRoot = Join-Path $packageRoot 'payload'
$serviceOutput = Join-Path $payloadRoot 'Service'
$desktopOutput = Join-Path $payloadRoot 'Desktop'
$cliOutput = Join-Path $payloadRoot 'Cli'
New-Item -ItemType Directory -Path $serviceOutput -Force | Out-Null
New-Item -ItemType Directory -Path $desktopOutput -Force | Out-Null
New-Item -ItemType Directory -Path $cliOutput -Force | Out-Null

Push-Location $repositoryRoot
try {
    Invoke-DotNet -Arguments @(
        'restore',
        'CertBaton.slnx',
        '--locked-mode'
    )

    $publishProperties = @(
        '--configuration', $Configuration,
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore',
        '-p:PublishSingleFile=false',
        '-p:PublishTrimmed=false',
        '-p:PublishReadyToRun=false',
        '-p:DebugSymbols=false',
        '-p:DebugType=None'
    )

    Invoke-DotNet -Arguments (
        @(
            'publish',
            'src\CertBaton.Service\CertBaton.Service.csproj',
            '--output', $serviceOutput
        ) + $publishProperties)
    Invoke-DotNet -Arguments (
        @(
            'publish',
            'src\CertBaton.Desktop\CertBaton.Desktop.csproj',
            '--output', $desktopOutput
        ) + $publishProperties)
    Invoke-DotNet -Arguments (
        @(
            'publish',
            'src\CertBaton.Ctl\CertBaton.Ctl.csproj',
            '--output', $cliOutput
        ) + $publishProperties)
}
finally {
    Pop-Location
}

$requiredFiles = @(
    (Join-Path $serviceOutput 'CertBaton.Service.exe'),
    (Join-Path $desktopOutput 'CertBaton.Desktop.exe'),
    (Join-Path $cliOutput 'certbatonctl.exe')
)
foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "The required published file is missing: '$requiredFile'."
    }
}

$secretExtensions = @(
    '.pfx',
    '.p12',
    '.pem',
    '.key',
    '.ppk',
    '.cer',
    '.crt',
    '.csr',
    '.jks',
    '.keystore',
    '.kdbx',
    '.env',
    '.snk'
)
$forbiddenPayloads = Get-ChildItem -LiteralPath $payloadRoot -Recurse -File |
    Where-Object {
        $_.Extension -ieq '.pdb' -or
        $_.Name -match '^appsettings\..+\.json$' -or
        $_.Name -ieq 'secrets.json' -or
        $_.Name -match '\.db(?:-shm|-wal)?$' -or
        $_.Name -match '^id_(rsa|dsa|ecdsa|ed25519)$' -or
        $secretExtensions -contains $_.Extension
    }
if ($forbiddenPayloads) {
    $forbiddenNames = ($forbiddenPayloads.FullName -join [Environment]::NewLine)
    throw "The developer package contains forbidden payloads:$([Environment]::NewLine)$forbiddenNames"
}

$packageScripts = @(
    'install-developer-package.ps1',
    'uninstall-developer-package.ps1',
    'test-installed-developer-package.ps1'
)
foreach ($scriptName in $packageScripts) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) `
        -Destination (Join-Path $packageRoot $scriptName)
}

foreach ($legalFileName in @(
        'LICENSE',
        'NOTICE',
        'THIRD-PARTY-NOTICES.txt')) {
    Copy-Item -LiteralPath (Join-Path $repositoryRoot $legalFileName) `
        -Destination (Join-Path $packageRoot $legalFileName)
}

$dotnetRoot = Split-Path (Get-Command dotnet.exe).Source
$dotnetNoticesRoot = Join-Path $packageRoot 'licenses\dotnet'
New-Item -ItemType Directory -Path $dotnetNoticesRoot -Force | Out-Null
foreach ($runtimeLegalFileName in @('LICENSE.txt', 'ThirdPartyNotices.txt')) {
    $runtimeLegalSource = Join-Path $dotnetRoot $runtimeLegalFileName
    if (-not (Test-Path -LiteralPath $runtimeLegalSource -PathType Leaf)) {
        throw "The .NET redistribution notice is missing: '$runtimeLegalSource'."
    }

    Copy-Item -LiteralPath $runtimeLegalSource `
        -Destination (Join-Path $dotnetNoticesRoot $runtimeLegalFileName)
}

$sourceCommitAfterPublish = Get-CleanSourceCommit
if ($sourceCommitAfterPublish -cne $sourceCommit) {
    throw 'The source commit changed while the developer package was built.'
}

$files = Get-ChildItem -LiteralPath $packageRoot -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        $relativePath = $_.FullName.Substring($packageRoot.Length + 1)
        $fileHash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        [ordered]@{
            path = $relativePath.Replace('\', '/')
            size = $_.Length
            sha256 = $fileHash.Hash.ToLowerInvariant()
        }
    }

$manifest = [ordered]@{
    product = 'CertBaton'
    channel = 'developer-preview'
    version = $packageVersion
    runtime = 'win-x64'
    selfContained = $true
    sourceCommit = $sourceCommit
    builtAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    files = @($files)
}
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $packageRoot 'manifest.json') `
        -Encoding UTF8

Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath `
    -CompressionLevel Optimal

$archiveFileHash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
$archiveHash = $archiveFileHash.Hash.ToLowerInvariant()

[pscustomobject]@{
    PackageRoot = $packageRoot
    ArchivePath = $archivePath
    ArchiveSha256 = $archiveHash
    Version = $packageVersion
} | ConvertTo-Json
