# SPDX-License-Identifier: MIT
#requires -Version 7.0
# Preserve the license texts supplied by restored runtime dependencies.
[CmdletBinding()]
param(
    [string] $AssetsPath = (Join-Path $PSScriptRoot '../obj/project.assets.json'),
    [string] $OutputPath = (Join-Path $PSScriptRoot '../THIRD-PARTY-NOTICES.txt'),
    [string] $TargetFramework = 'net8.0-windows',
    [string] $RuntimeIdentifier = 'win-x64',
    [switch] $Check
)

$ErrorActionPreference = 'Stop'
$assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
$framework = @($assets.project.frameworks.PSObject.Properties | Where-Object {
    $_.Name -eq $TargetFramework -or $_.Value.targetAlias -eq $TargetFramework
})
if ($framework.Count -ne 1) { throw "Cannot identify restored framework $TargetFramework." }
$targetName = $framework[0].Name + '/' + $RuntimeIdentifier
$target = $assets.targets.PSObject.Properties[$targetName]
if ($null -eq $target) {
    throw "Restore the project for $RuntimeIdentifier before generating dependency notices."
}

$packageIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($package in $target.Value.PSObject.Properties) {
    if ($package.Value.type -ne 'package') { continue }
    # ILLink and similar build-only packages have no runtime or native assets.
    $hasRuntimeAssets = @($package.Value.PSObject.Properties | Where-Object {
        $_.Name -in @('runtime', 'native', 'runtimeTargets') -and
        @($_.Value.PSObject.Properties | Where-Object { $_.Name -notmatch '(^|/)_\._$' }).Count -gt 0
    }).Count -gt 0
    if ($hasRuntimeAssets) { $null = $packageIds.Add($package.Name) }
}

foreach ($reference in $framework[0].Value.frameworkReferences.PSObject.Properties.Name) {
    $packName = switch -Wildcard ($reference) {
        'Microsoft.NETCore.App' { "Microsoft.NETCore.App.Runtime.$RuntimeIdentifier" }
        'Microsoft.WindowsDesktop.App*' { "Microsoft.WindowsDesktop.App.Runtime.$RuntimeIdentifier" }
        'Microsoft.AspNetCore.App' { "Microsoft.AspNetCore.App.Runtime.$RuntimeIdentifier" }
        default { throw "Review the runtime-pack license mapping for $reference." }
    }
    $download = @($framework[0].Value.downloadDependencies | Where-Object { $_.name -eq $packName })
    if ($download.Count -ne 1 -or $download[0].version -notmatch '^\[([^,]+),\s*\1\]$') {
        throw "No exact restored version found for runtime pack $packName. Restore Release first."
    }
    $null = $packageIds.Add($packName + '/' + $Matches[1])
}

$records = [System.Collections.Generic.List[object]]::new()
$texts = [System.Collections.Generic.List[object]]::new()
$textIds = @{}
foreach ($packageId in ($packageIds | Sort-Object)) {
    $parts = $packageId.Split('/')
    if ($parts.Length -ne 2 -or $parts[0] -notmatch '^[A-Za-z0-9_.-]+$' -or
        $parts[1] -notmatch '^[A-Za-z0-9_.+-]+$') { throw "Invalid package identity $packageId." }
    $packageDirectory = $null
    foreach ($root in $assets.packageFolders.PSObject.Properties.Name) {
        $candidate = Join-Path (Join-Path $root $parts[0].ToLowerInvariant()) $parts[1].ToLowerInvariant()
        if (Test-Path -LiteralPath $candidate -PathType Container) { $packageDirectory = $candidate; break }
    }
    if ($null -eq $packageDirectory) { throw "Restored package not found: $packageId" }
    [xml] $spec = Get-Content -LiteralPath (Join-Path $packageDirectory ($parts[0].ToLowerInvariant() + '.nuspec')) -Raw
    $license = $spec.package.metadata.license
    $noticeFiles = @(Get-ChildItem -LiteralPath $packageDirectory -File | Where-Object {
        $_.Name -match '^(LICENSE|LICENCE|COPYING)(\..*)?$|^(THIRD[-_]PARTY[-_]NOTICES?|NOTICE)(\..*)?$'
    } | Sort-Object Name)
    if ($license.type -eq 'file') {
        $licensePath = [IO.Path]::GetFullPath((Join-Path $packageDirectory $license.InnerText))
        $packagePrefix = [IO.Path]::GetFullPath($packageDirectory).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $licensePath.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "License path escapes the package: $packageId"
        }
        if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) { throw "License text missing: $packageId" }
        $noticeFiles = @($noticeFiles + (Get-Item -LiteralPath $licensePath) | Sort-Object FullName -Unique)
    }
    if (@($noticeFiles | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING)' }).Count -eq 0 -and
        $license.type -ne 'file') { throw "No complete license text found for $packageId; review it before publishing." }
    $references = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $noticeFiles) {
        $body = [IO.File]::ReadAllText($file.FullName)
        if ([string]::IsNullOrWhiteSpace($body)) { throw "Empty license or notice: $($file.FullName)" }
        $digest = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        if (-not $textIds.ContainsKey($digest)) {
            $id = 'TEXT-' + ($texts.Count + 1).ToString('00')
            $textIds[$digest] = $id
            $texts.Add([pscustomobject]@{ Id = $id; Body = $body; Sha256 = $digest })
        }
        $references.Add($file.Name + ' => ' + $textIds[$digest])
    }
    $records.Add([pscustomobject]@{
        Package = $packageId
        Url = "https://www.nuget.org/packages/$($parts[0])/$($parts[1])"
        Repository = [string] $spec.package.metadata.repository.url
        Revision = [string] $spec.package.metadata.repository.commit
        License = [string] $license.InnerText
        Notices = $references.ToArray()
    })
}

$output = [Text.StringBuilder]::new()
$null = $output.Append("Whitehat Security Tool - Third-party licenses and notices`n")
$null = $output.Append("Generated from restored runtime dependencies by scripts/Update-ThirdPartyNotices.ps1.`n")
$null = $output.Append("Target: $TargetFramework / $RuntimeIdentifier (self-contained).`n")
$null = $output.Append("Upstream rights and full notice text are preserved below; identical files are included once.`n")
$null = $output.Append("Package-level license expressions do not replace additional component licenses in the notices.`n`n")
foreach ($record in $records) {
    $null = $output.Append("PACKAGE: $($record.Package)`nNuGet: $($record.Url)`n")
    $null = $output.Append("Source repository: $($record.Repository)`nSource revision: $($record.Revision)`n")
    $null = $output.Append("Declared license: $($record.License)`n")
    foreach ($reference in $record.Notices) { $null = $output.Append("  $reference`n") }
    $null = $output.Append("`n")
}
foreach ($text in $texts) {
    $null = $output.Append("========== BEGIN $($text.Id) ==========`n")
    $null = $output.Append("SHA-256 of upstream file bytes: $($text.Sha256)`n`n")
    $null = $output.Append($text.Body)
    if (-not $text.Body.EndsWith("`n")) { $null = $output.Append("`n") }
    $null = $output.Append("========== END $($text.Id) ==========`n`n")
}
$content = $output.ToString()
if ($Check) {
    $storedContent = if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
        [IO.File]::ReadAllText([IO.Path]::GetFullPath($OutputPath))
    } else { '' }
    if ($storedContent -cne $content) {
        $storedPackages = @([regex]::Matches($storedContent, '(?m)^PACKAGE: ([^\r\n]+)') |
            ForEach-Object { $_.Groups[1].Value })
        $storedSummary = if ($storedPackages.Count -gt 0) { $storedPackages -join ', ' } else { '(none)' }
        $restoredSummary = $records.Package -join ', '
        throw ("Third-party notices differ from the restored packages.`n" +
            "Stored packages: $storedSummary`nRestored packages: $restoredSummary`n" +
            'Regenerate and review before publishing. Matching package versions can still have different notice text.')
    }
    Write-Output "Verified notices for $($records.Count) runtime packages ($($texts.Count) complete unique texts)."
} else {
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $content, [Text.UTF8Encoding]::new($false))
    Write-Output "Updated notices for $($records.Count) runtime packages ($($texts.Count) complete unique texts)."
}
