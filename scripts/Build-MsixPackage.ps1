# SPDX-License-Identifier: MIT
#requires -Version 7.0
<#
Builds an unsigned MSIX for isolated development testing. Microsoft Store signs
accepted MSIX packages; no paid signing certificate is needed for this route.
StoreSubmission mode checks an existing candidate and explicit review evidence.
Neither mode uploads anything or grants capability/certification approval.
#>
[CmdletBinding()]
param(
    [ValidateSet('Development', 'StoreSubmission')]
    [string] $Mode = 'Development',
    [string] $DotNetPath,
    [string] $MakeAppxPath,
    [string] $OutputDirectory,
    [version] $MinimumOsVersion = '10.0.19041.0',
    [version] $MaximumOsVersion = '10.0.19041.0',
    [string] $CandidateRecordPath,
    [string] $ReviewEvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
$identityName = 'omni.apps.WhitehatSecurityTool'
$publisher = 'CN=79C00735-EF73-493D-AE6B-36BE09C31052'
$requiredReviews = @(
    'RestrictedCapabilities', 'PublisherAccount', 'MinimumOsRuntime',
    'AdministratorAndStandardUser', 'StartupAndUpdate',
    'ExternalChangesAndRecovery', 'InstallResetAndUninstall',
    'SecurityAndStoreValidation', 'ListingAndPrivacy'
)

function Assert-Manifest([xml] $Manifest) {
    if ($Manifest.Package.Identity.Name -ne $identityName -or
        $Manifest.Package.Identity.Publisher -ne $publisher -or
        $Manifest.Package.Identity.ProcessorArchitecture -ne 'x64' -or
        $Manifest.Package.Properties.DisplayName -ne 'Whitehat Security Tool' -or
        $Manifest.Package.Properties.PublisherDisplayName -ne 'omni.apps') {
        throw 'The package does not match the reserved Whitehat Security Tool identity.'
    }
    if ($Manifest.OuterXml -match '__[A-Z_]+__') { throw 'The package manifest contains unresolved tokens.' }
    $capabilities = @($Manifest.Package.Capabilities.ChildNodes |
        Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element } |
        ForEach-Object { $_.GetAttribute('Name') })
    if ($capabilities.Count -ne 2 -or 'runFullTrust' -notin $capabilities -or 'allowElevation' -notin $capabilities) {
        throw 'Unexpected capability set. Review the manifest before producing a new candidate.'
    }
}

function Read-PackageManifest([string] $PackagePath) {
    $zip = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        if ($zip.GetEntry('AppxSignature.p7x')) { throw 'Expected the original unsigned candidate, not a modified or test-signed package.' }
        $entry = $zip.GetEntry('AppxManifest.xml')
        if (-not $entry) { throw 'The package has no manifest.' }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { return [xml]$reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $zip.Dispose() }
}

if ($Mode -eq 'StoreSubmission') {
    if (-not $CandidateRecordPath -or -not $ReviewEvidencePath) {
        throw 'StoreSubmission requires -CandidateRecordPath and -ReviewEvidencePath for the exact tested package.'
    }
    $recordFile = Get-Item -LiteralPath $CandidateRecordPath
    $record = Get-Content -LiteralPath $recordFile.FullName -Raw | ConvertFrom-Json
    $evidenceFile = Get-Item -LiteralPath $ReviewEvidencePath
    $evidence = Get-Content -LiteralPath $evidenceFile.FullName -Raw | ConvertFrom-Json
    $packageFile = Get-Item -LiteralPath $record.PackagePath
    $packageHash = (Get-FileHash -LiteralPath $packageFile.FullName -Algorithm SHA256).Hash
    if ($record.SchemaVersion -ne 1 -or $evidence.SchemaVersion -ne 1 -or
        $packageHash -ne $record.PackageSha256 -or $packageHash -ne $evidence.PackageSha256) {
        throw 'Candidate or review evidence does not match the current package SHA-256.'
    }
    if ($record.SourceCommit -notmatch '^[a-fA-F0-9]{40}$' -or $record.SourceWorktreeClean -ne $true) {
        throw 'Submission review requires a package built from an identified, clean committed source tree.'
    }
    Assert-Manifest (Read-PackageManifest $packageFile.FullName)
    if ([string]::IsNullOrWhiteSpace($evidence.ReviewedBy) -or
        [string]::IsNullOrWhiteSpace($evidence.ReviewedAtUtc)) {
        throw 'Review evidence must identify the reviewer and review time.'
    }
    $null = [datetimeoffset]::Parse($evidence.ReviewedAtUtc)
    $verifiedEvidence = @()
    foreach ($name in $requiredReviews) {
        $property = $evidence.Reviews.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value.Status -ne 'Verified' -or
            [string]::IsNullOrWhiteSpace($property.Value.EvidenceFile)) {
            throw "Submission is blocked: $name has no affirmative, documented review."
        }
        $proofPath = $property.Value.EvidenceFile
        if (-not [IO.Path]::IsPathFullyQualified($proofPath)) {
            $proofPath = Join-Path $evidenceFile.DirectoryName $proofPath
        }
        $proof = Get-Item -LiteralPath $proofPath
        if ($proof.PSIsContainer -or $proof.Length -eq 0) { throw "Empty review evidence: $name" }
        $verifiedEvidence += [ordered]@{
            Review = $name; EvidenceFile = $proof.FullName
            EvidenceSha256 = (Get-FileHash -LiteralPath $proof.FullName -Algorithm SHA256).Hash
        }
    }
    $approvalRecord = [ordered]@{
        SchemaVersion = 1; Status = 'Review evidence verified; certification not yet granted'
        PackagePath = $packageFile.FullName; PackageSha256 = $packageHash
        ReviewedBy = $evidence.ReviewedBy; ReviewedAtUtc = $evidence.ReviewedAtUtc
        Evidence = $verifiedEvidence
        Note = 'Human review attestations and referenced files are recorded, not independently authenticated. No submission is performed.'
    }
    $approvalPath = Join-Path $recordFile.DirectoryName ('submission-review-' + [guid]::NewGuid().ToString('N') + '.json')
    $approvalRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $approvalPath -Encoding utf8
    Write-Output $approvalPath
    return
}

if ($CandidateRecordPath -or $ReviewEvidencePath) { throw 'Review evidence parameters are only valid in StoreSubmission mode.' }
if (-not $IsWindows) { throw 'MSIX packaging requires Windows and Windows SDK MakeAppx.' }
if ($MinimumOsVersion -lt [version]'10.0.19041.0' -or $MaximumOsVersion -lt $MinimumOsVersion) {
    throw 'The package requires Windows 10 build 19041 or later, and the maximum target cannot precede the minimum.'
}
foreach ($target in @($MinimumOsVersion, $MaximumOsVersion)) {
    if ($target.Revision -lt 0 -or $target.Build -gt 65535 -or $target.Revision -gt 65535) {
        throw 'OS versions must have four components, each fitting the Windows package version range.'
    }
}
if (-not $DotNetPath) { $DotNetPath = (Get-Command dotnet.exe -ErrorAction Stop).Source }
$DotNetPath = (Get-Item -LiteralPath $DotNetPath).FullName
if (-not $MakeAppxPath) {
    $command = Get-Command makeappx.exe -ErrorAction SilentlyContinue
    if ($command) { $MakeAppxPath = $command.Source }
    else {
        $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $candidates = @(Get-ChildItem -Path "$sdkRoot\*\x64\makeappx.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
        if ($candidates.Count -eq 0) { throw 'Pass -MakeAppxPath or install Windows SDK packaging tools.' }
        $MakeAppxPath = $candidates[0].FullName
    }
}
$MakeAppxPath = (Get-Item -LiteralPath $MakeAppxPath).FullName
$toolSignature = Get-AuthenticodeSignature -LiteralPath $MakeAppxPath
if ($toolSignature.Status -ne 'Valid' -or $toolSignature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
    throw 'MakeAppx must have a valid Microsoft Authenticode signature.'
}

[xml]$project = Get-Content -LiteralPath (Join-Path $repoRoot 'WhitehatSecurity.csproj') -Raw
$versionNode = $project.SelectSingleNode('/Project/PropertyGroup/Version')
if ($null -eq $versionNode) { throw 'The project must declare its package version.' }
$versionText = $versionNode.InnerText
$packageVersion = [version]$versionText
if ($packageVersion.Major -lt 1 -or $packageVersion.Revision -ne 0 -or
    @(@($packageVersion.Major, $packageVersion.Minor, $packageVersion.Build) | Where-Object { $_ -lt 0 -or $_ -gt 65535 }).Count -ne 0) {
    throw 'Store package versions must use four components, a nonzero major and zero revision, within 0..65535.'
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'artifacts\msix' }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if ($outputRoot.TrimEnd('\') -eq [IO.Path]::GetPathRoot($outputRoot).TrimEnd('\')) {
    throw 'A drive or share root is not a build output directory.'
}
if ((Test-Path -LiteralPath $outputRoot) -and (Get-Item -LiteralPath $outputRoot).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'The output directory must not be a link or junction.'
}
# Every run is isolated; no caller-specified directory is removed or overwritten.
$runRoot = Join-Path $outputRoot ('development-' + [guid]::NewGuid().ToString('N'))
$payload = Join-Path $runRoot 'payload'
$null = New-Item -ItemType Directory -Path $payload -Force
$packagePath = Join-Path $runRoot "WhitehatSecurityTool_${versionText}_x64.development.msix"
$buildArtifacts = Join-Path $runRoot 'build'
$sourceCommit = $null
$sourceWorktreeClean = $false
if (Get-Command git.exe -ErrorAction SilentlyContinue) {
    $gitHead = & git -C $repoRoot rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitHead -match '^[a-fA-F0-9]{40}$') {
        $sourceCommit = [string]$gitHead
        $gitStatus = & git -C $repoRoot status --porcelain --untracked-files=normal 2>$null
        $sourceWorktreeClean = $LASTEXITCODE -eq 0 -and @($gitStatus).Count -eq 0
    }
}

& $DotNetPath restore (Join-Path $repoRoot 'WhitehatSecurity.csproj') -r win-x64 `
    --artifacts-path $buildArtifacts -p:Configuration=Release -p:StoreBuild=true -p:SelfContained=true `
    -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=false -p:EnableCompressionInSingleFile=false `
    -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low `
    '-warnaserror:NU1900,NU1901,NU1902,NU1903,NU1904' `
    2>&1 | Tee-Object -FilePath (Join-Path $runRoot 'restore.log') | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Restore/audit failed. Development logs: $runRoot" }
& (Join-Path $PSScriptRoot 'Update-ThirdPartyNotices.ps1') `
    -AssetsPath (Join-Path $buildArtifacts 'obj\WhitehatSecurity\project.assets.json') -Check
& $DotNetPath publish (Join-Path $repoRoot 'WhitehatSecurity.csproj') -c Release -r win-x64 --self-contained true `
    --artifacts-path $buildArtifacts --output $payload --no-restore `
    -p:StoreBuild=true -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=false `
    -p:EnableCompressionInSingleFile=false -p:PublishTrimmed=false -p:DebugType=embedded -p:TreatWarningsAsErrors=true `
    2>&1 | Tee-Object -FilePath (Join-Path $runRoot 'publish.log') | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Publish failed. Development logs: $runRoot" }
if (-not (Test-Path -LiteralPath (Join-Path $payload 'WhitehatSecurity.exe'))) { throw 'Publish did not produce the application executable.' }

# Reuse the product's shield/checkmark geometry (TrayApplicationContext), drawn
# directly at tile resolution rather than stretching a small screenshot/icon.
Add-Type -AssemblyName System.Drawing
$assetsDirectory = Join-Path $payload 'Assets'
$null = New-Item -ItemType Directory -Path $assetsDirectory
function New-ShieldAsset([int] $Size, [string] $Path) {
    $bitmap = [Drawing.Bitmap]::new($Size, $Size)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $outerBrush = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(0, 180, 255))
    $innerBrush = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(0, 120, 200))
    $pen = [Drawing.Pen]::new([Drawing.Color]::White, 3)
    try {
        $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.Clear([Drawing.Color]::Transparent)
        $graphics.ScaleTransform($Size / 32.0, $Size / 32.0)
        $outer = [Drawing.Point[]]@([Drawing.Point]::new(16, 2), [Drawing.Point]::new(28, 6), [Drawing.Point]::new(28, 16), [Drawing.Point]::new(16, 30), [Drawing.Point]::new(4, 16), [Drawing.Point]::new(4, 6))
        $inner = [Drawing.Point[]]@([Drawing.Point]::new(16, 6), [Drawing.Point]::new(24, 9), [Drawing.Point]::new(24, 15), [Drawing.Point]::new(16, 26), [Drawing.Point]::new(8, 15), [Drawing.Point]::new(8, 9))
        $graphics.FillPolygon($outerBrush, $outer)
        $graphics.FillPolygon($innerBrush, $inner)
        $graphics.DrawLine($pen, 10, 16, 14, 21)
        $graphics.DrawLine($pen, 14, 21, 22, 11)
        $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    }
    finally { $pen.Dispose(); $innerBrush.Dispose(); $outerBrush.Dispose(); $graphics.Dispose(); $bitmap.Dispose() }
}
New-ShieldAsset 50 (Join-Path $assetsDirectory 'StoreLogo.png')
New-ShieldAsset 44 (Join-Path $assetsDirectory 'Square44x44Logo.png')
New-ShieldAsset 150 (Join-Path $assetsDirectory 'Square150x150Logo.png')

$manifestText = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging\msix\AppxManifest.xml.template') -Raw
$manifestText = $manifestText.Replace('__PACKAGE_VERSION__', $versionText).
    Replace('__MINIMUM_OS_VERSION__', $MinimumOsVersion.ToString()).
    Replace('__MAXIMUM_OS_VERSION__', $MaximumOsVersion.ToString())
Assert-Manifest ([xml]$manifestText)
$manifestText | Set-Content -LiteralPath (Join-Path $payload 'AppxManifest.xml') -Encoding utf8

# /nv is intentionally absent: MakeAppx must perform semantic validation.
& $MakeAppxPath pack /d $payload /p $packagePath /h SHA256 /no `
    2>&1 | Set-Content -LiteralPath (Join-Path $runRoot 'makeappx.log') -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw "MakeAppx validation failed. Development logs: $runRoot" }
Write-Host 'MakeAppx semantic validation and package creation succeeded.'
Assert-Manifest (Read-PackageManifest $packagePath)
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
if ($sourceWorktreeClean) {
    $gitHeadAfterBuild = & git -C $repoRoot rev-parse HEAD 2>$null
    $gitStatusAfterBuild = & git -C $repoRoot status --porcelain --untracked-files=normal 2>$null
    $sourceWorktreeClean = $LASTEXITCODE -eq 0 -and $gitHeadAfterBuild -eq $sourceCommit -and @($gitStatusAfterBuild).Count -eq 0
}
$recordPath = Join-Path $runRoot 'candidate-record.json'
$inventory = @(Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{ Path = [IO.Path]::GetRelativePath($payload, $_.FullName); SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
[ordered]@{
    SchemaVersion = 1; Status = 'Development only; not cleared for Store submission'
    CreatedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    SourceCommit = $sourceCommit; SourceWorktreeClean = $sourceWorktreeClean
    PackagePath = $packagePath; PackageSha256 = $packageHash; Signing = 'Unsigned'
    IdentityName = $identityName; Publisher = $publisher; Version = $versionText
    MinimumOsTarget = $MinimumOsVersion.ToString(); MaximumOsTarget = $MaximumOsVersion.ToString()
    OsTestingStatus = 'Not established by packaging; exact minimum and actual tested builds require evidence'
    PackageValidation = 'MakeAppx semantic validation succeeded; no /nv bypass'
    DependencyValidation = 'NuGet audit all/low succeeded with NU1900-NU1904 rejected; embedded dependency notices match restored payload'
    MakeAppxPath = $MakeAppxPath; DotNetPath = $DotNetPath; Payload = $inventory
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding utf8
$reviews = [ordered]@{}
foreach ($name in $requiredReviews) { $reviews[$name] = [ordered]@{ Status = 'Pending'; EvidenceFile = '' } }
[ordered]@{
    SchemaVersion = 1; PackageSha256 = $packageHash; ReviewedBy = ''; ReviewedAtUtc = ''
    Reviews = $reviews
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runRoot 'review-evidence.pending.json') -Encoding utf8
Write-Warning 'DEVELOPMENT PACKAGE ONLY. Capability approval, lifecycle checks and real packaged VM testing remain release gates. Nothing was submitted.'
Write-Output $recordPath
