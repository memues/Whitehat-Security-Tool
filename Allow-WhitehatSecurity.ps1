# SPDX-License-Identifier: MIT
# The legacy filename is retained for existing links. This helper now only
# verifies a release file; it does not change Defender, Smart App Control,
# the Mark of the Web, or launch the executable. Administrator rights are
# not required.
#
# Obtain the expected SHA-256 from the checksum asset on the official release:
# https://github.com/memues/Whitehat-Security-Tool/releases
#
# Usage (replace the placeholder with the published 64-character SHA-256):
#   .\Allow-WhitehatSecurity.ps1 -ExpectedSha256 '<published SHA-256>'
#   .\Allow-WhitehatSecurity.ps1 -ExpectedSha256 '<published SHA-256>' `
#       -BinaryPath '.\downloaded-release.exe'
#
# A matching checksum confirms agreement with the supplied hash. It does not
# establish the trustworthiness of the hash source or replace code signing.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedSha256,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $BinaryPath = (Join-Path $PSScriptRoot 'WhitehatSecurity.exe')
)

$ErrorActionPreference = 'Stop'

$binary = Get-Item -LiteralPath $BinaryPath -ErrorAction Stop
if ($binary -isnot [System.IO.FileInfo]) {
    throw 'BinaryPath must identify a file.'
}

$actualHash = (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash
if (-not [string]::Equals(
        $actualHash,
        $ExpectedSha256,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'SHA-256 mismatch. Do not run this file; obtain a fresh copy and checksum from the official release.'
}

Write-Output "SHA-256 verified: $($binary.FullName)"
Write-Output "SHA-256: $actualHash"
Write-Output 'Windows security settings and the downloaded file were left unchanged.'
Write-Output 'If Windows blocks this unsigned release, follow your administrator or organization policy.'
