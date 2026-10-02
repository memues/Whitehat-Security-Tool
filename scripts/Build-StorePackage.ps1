# SPDX-License-Identifier: MIT
# Builds the EXE/ MSI submission route's standalone self-installer. Never submits it.
[CmdletBinding()]
param(
    [string] $CertificateThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string] $CertificateStore = 'CurrentUser',
    [string] $SignToolPath,
    [uri] $TimestampUrl = 'http://timestamp.digicert.com',
    [string] $OutputDirectory,
    # Internal entry point used by the generated pre-bundle MSBuild target.
    [string] $BundleContextPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-StoreSigningCertificate([string] $Thumbprint, [string] $Store) {
    $normalized = $Thumbprint -replace '\s', ''
    if ($normalized -notmatch '^[0-9A-Fa-f]{40}$') {
        throw 'Supply the SHA-1 thumbprint of your CA-issued code-signing certificate. A self-signed certificate is not accepted.'
    }
    $certificate = Get-Item -LiteralPath "Cert:\$Store\My\$normalized" -ErrorAction Stop
    if (-not $certificate.HasPrivateKey) { throw 'The signing certificate has no accessible private key.' }
    if ($certificate.Subject -eq $certificate.Issuer) { throw 'A self-signed signing certificate cannot be used for this Store package.' }
    if ($certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date)) {
        throw 'The signing certificate is not currently valid.'
    }
    if (@($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }).Count -eq 0) {
        throw 'The certificate must permit Code Signing (1.3.6.1.5.5.7.3.3).'
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = 'Online'
        if (-not $chain.Build($certificate)) {
            throw ('The signing certificate chain is not trusted or revocation could not be checked: ' +
                (($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; '))
        }
    }
    finally { $chain.Dispose() }
    return $certificate
}

function Resolve-SignTool([string] $ExplicitPath) {
    if ($ExplicitPath) {
        $resolved = (Get-Item -LiteralPath $ExplicitPath -ErrorAction Stop).FullName
    }
    else {
        $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($command) { $resolved = $command.Source }
        else {
            $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
            $candidates = @(Get-ChildItem -Path "$sdkRoot\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending)
            if ($candidates.Count -eq 0) { throw 'SignTool was not found. Install the Windows SDK Signing Tools, or pass -SignToolPath.' }
            $resolved = $candidates[0].FullName
        }
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw 'SignTool must have a valid Microsoft Authenticode signature.'
    }
    return $resolved
}

function Invoke-SignFile([string] $Path, $Context) {
    $arguments = @('sign', '/sha1', $Context.Thumbprint, '/s', 'My', '/fd', 'SHA256',
        '/tr', $Context.TimestampUrl, '/td', 'SHA256')
    if ($Context.CertificateStore -eq 'LocalMachine') { $arguments += '/sm' }
    & $Context.SignToolPath @arguments $Path | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Signing failed: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Thumbprint -ne $Context.Thumbprint -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "The new signature or RFC 3161 timestamp did not validate: $Path"
    }
}

function Assert-SignedFile([string] $Path, $Context) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) {
        throw "A PE file lacks a valid CA-issued signature: $Path ($($signature.Status))"
    }
    & $Context.SignToolPath verify /pa /all $Path | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "SignTool rejected a PE signature: $Path" }
    return [ordered]@{
        File = $Path
        SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Signer = $signature.SignerCertificate.Subject
        Thumbprint = $signature.SignerCertificate.Thumbprint
    }
}

function Test-PortableExecutable([string] $Path) {
    $stream = [IO.File]::OpenRead($Path)
    try { return $stream.Length -ge 2 -and $stream.ReadByte() -eq 0x4D -and $stream.ReadByte() -eq 0x5A }
    finally { $stream.Dispose() }
}

if ($BundleContextPath) {
    $context = Get-Content -LiteralPath $BundleContextPath -Raw | ConvertFrom-Json
    $null = Get-StoreSigningCertificate $context.Thumbprint $context.CertificateStore
    $context.SignToolPath = Resolve-SignTool $context.SignToolPath
    $payloadRoot = [IO.Path]::GetFullPath($context.PayloadDirectory).TrimEnd('\') + '\'
    $inventory = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content -LiteralPath $context.ManifestPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line.Split('|')
        if ($parts.Count -ne 2 -or [IO.Path]::IsPathRooted($parts[1])) { throw 'Invalid bundle input manifest.' }
        $destination = [IO.Path]::GetFullPath((Join-Path $payloadRoot $parts[1]))
        if (-not $destination.StartsWith($payloadRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not $seen.Add($destination)) { throw 'A bundle path escapes staging or is duplicated.' }
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force
        Copy-Item -LiteralPath $parts[0] -Destination $destination
        # The apphost becomes the outer executable and is signed after bundling.
        if ($parts[1] -eq 'WhitehatSecurity.exe') { continue }
        if (-not (Test-PortableExecutable $destination)) { continue }
        $signature = Get-AuthenticodeSignature -LiteralPath $destination
        if ($signature.Status -eq 'NotSigned') { Invoke-SignFile $destination $context }
        elseif ($signature.Status -ne 'Valid') { throw "Refusing to replace an invalid existing signature: $destination" }
        $record = Assert-SignedFile $destination $context
        $record.File = $parts[1]
        $inventory.Add($record)
    }
    if ($inventory.Count -eq 0) { throw 'No bundled PE files were checked; refusing to publish.' }
    ConvertTo-Json -InputObject @($inventory.ToArray()) -Depth 5 |
        Set-Content -LiteralPath $context.InventoryPath -Encoding UTF8
    return
}

if ($env:OS -ne 'Windows_NT') { throw 'Store EXE signing requires Windows.' }
if ($TimestampUrl.Scheme -notin @('http', 'https') -or -not $TimestampUrl.IsAbsoluteUri) {
    throw 'TimestampUrl must be an absolute HTTP(S) RFC 3161 timestamp endpoint.'
}
$certificate = Get-StoreSigningCertificate $CertificateThumbprint $CertificateStore
$resolvedSignTool = Resolve-SignTool $SignToolPath
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$projectPath = Join-Path $repoRoot 'WhitehatSecurity.csproj'
[xml] $project = Get-Content -LiteralPath $projectPath -Raw
$version = [string] $project.Project.PropertyGroup[0].Version
if ($version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'The project must define a four-part version.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'artifacts\store' }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if ($outputRoot.TrimEnd('\') -eq [IO.Path]::GetPathRoot($outputRoot).TrimEnd('\')) {
    throw 'OutputDirectory must not be a drive root.'
}
# MSBuild uses both XML and a Windows command line. Fail closed on metacharacters.
if (($repoRoot + $outputRoot + $PSCommandPath) -match '[%$;&|<>"''\r\n]') {
    throw 'Build paths must not contain MSBuild or shell metacharacters.'
}
$buildRoot = Join-Path $outputRoot ($version + '-' + [Guid]::NewGuid().ToString('N'))
$payloadDir = Join-Path $buildRoot 'payload'
$publishDir = Join-Path $buildRoot 'publish'
$releaseDir = Join-Path $buildRoot 'release'
foreach ($directory in @($payloadDir, $publishDir, $releaseDir)) {
    $null = New-Item -ItemType Directory -Path $directory -Force
}
$manifestPath = Join-Path $buildRoot 'bundle-inputs.txt'
$inventoryPath = Join-Path $buildRoot 'payload-signatures.json'
$contextPath = Join-Path $buildRoot 'signing-context.json'
$context = [ordered]@{
    Thumbprint = $certificate.Thumbprint
    CertificateStore = $CertificateStore
    SignToolPath = $resolvedSignTool
    TimestampUrl = $TimestampUrl.AbsoluteUri
    PayloadDirectory = $payloadDir
    ManifestPath = $manifestPath
    InventoryPath = $inventoryPath
}
$context | ConvertTo-Json | Set-Content -LiteralPath $contextPath -Encoding UTF8
$shellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $shellPath)) { $shellPath = Join-Path $PSHOME 'pwsh.exe' }
function ConvertTo-XmlText([string] $Value) { return [Security.SecurityElement]::Escape($Value) }
$command = '"{0}" -NoProfile -NonInteractive -File "{1}" -BundleContextPath "{2}"' -f
    $shellPath, $PSCommandPath, $contextPath
$targetTemplate = @'
<Project>
  <Target Name="WhitehatSignStorePayload" BeforeTargets="GenerateSingleFileBundle" DependsOnTargets="PrepareForBundle">
    <ItemGroup><_WhsOriginalBundleFile Include="@(FilesToBundle)" /></ItemGroup>
    <WriteLinesToFile File="__MANIFEST__" Lines="@(_WhsOriginalBundleFile->'%(FullPath)|%(RelativePath)')" Overwrite="true" Encoding="UTF-8" />
    <Exec Command="__COMMAND__" />
    <ItemGroup>
      <FilesToBundle Remove="@(FilesToBundle)" />
      <FilesToBundle Include="@(_WhsOriginalBundleFile->'__PAYLOAD__\%(RelativePath)')">
        <RelativePath>%(_WhsOriginalBundleFile.RelativePath)</RelativePath>
      </FilesToBundle>
    </ItemGroup>
  </Target>
</Project>
'@
$targetsPath = Join-Path $buildRoot 'StoreSigning.targets'
$targetTemplate.Replace('__MANIFEST__', (ConvertTo-XmlText $manifestPath)).
    Replace('__COMMAND__', (ConvertTo-XmlText $command)).
    Replace('__PAYLOAD__', (ConvertTo-XmlText $payloadDir)) |
    Set-Content -LiteralPath $targetsPath -Encoding UTF8

& dotnet publish $projectPath -c Release -r win-x64 --self-contained true -o $publishDir `
    '-p:StoreBuild=true' '-p:PublishSingleFile=true' '-p:IncludeNativeLibrariesForSelfExtract=true' `
    '-p:DebugType=embedded' "-p:CustomAfterMicrosoftCommonTargets=$targetsPath"
if ($LASTEXITCODE -ne 0) { throw 'Store publish failed. No submission artifact was produced.' }
if (-not (Test-Path -LiteralPath $inventoryPath)) { throw 'The pre-bundle signing hook did not run.' }
$publishedFiles = @(Get-ChildItem -LiteralPath $publishDir -File -Recurse)
if ($publishedFiles.Count -ne 1 -or $publishedFiles[0].Name -ne 'WhitehatSecurity.exe') {
    throw 'Expected exactly one standalone EXE. The self-installer cannot deploy loose dependencies.'
}
$exePath = $publishedFiles[0].FullName
Invoke-SignFile $exePath $context
$finalRecord = Assert-SignedFile $exePath $context
$releaseName = "WhitehatSecurity-$version-win-x64.exe"
$releasePath = Join-Path $releaseDir $releaseName
Copy-Item -LiteralPath $exePath -Destination $releasePath
$finalRecord.File = $releaseName
[ordered]@{
    Version = $version
    Architecture = 'x64'
    Format = 'EXE'
    StoreBuild = $true
    Installer = $finalRecord
    SilentInstallArguments = '--install --quiet'
    SilentUninstallArguments = '--uninstall --quiet'
    BundledPortableExecutables = @(Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json)
    CertificationStatus = 'Not submitted; clean-VM install/uninstall and Microsoft review still required.'
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseDir 'store-package.json') -Encoding UTF8
Write-Output "Signed EXE candidate: $releasePath"
Write-Output 'This script did not install the app, change Windows settings, upload, or submit anything.'
