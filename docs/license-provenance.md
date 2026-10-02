# License provenance

Whitehat Security Tool uses the [MIT License](../LICENSE). The full license file
documents the project's existing licensing; it does not replace dependency
licenses or relicense another project's code.

The original [15 February 2026 README](https://github.com/memues/Whitehat-Security-Tool/blob/5ae24007df2954795551866bfadea3d34ec4ca04/README.md#L68)
explicitly declares MIT. When the C# implementation was introduced under
`csharp/` on 10 April 2026, the
[root README still declared MIT](https://github.com/memues/Whitehat-Security-Tool/blob/440ed8ca207d9b74bf4950349d1f42adef9d9ba2/README.md#L169),
the [C# README referred to that parent repository](https://github.com/memues/Whitehat-Security-Tool/blob/440ed8ca207d9b74bf4950349d1f42adef9d9ba2/csharp/README.md#L106),
and the [C# entry point already carried an MIT SPDX header](https://github.com/memues/Whitehat-Security-Tool/blob/440ed8ca207d9b74bf4950349d1f42adef9d9ba2/csharp/Program.cs#L1).
The [subsequent move to the repository root](https://github.com/memues/Whitehat-Security-Tool/commit/260e4915ffe2d237149b81fd1a58c3a0f0294615)
left the parent-reference wording behind. The explicit root license removes that
ambiguity.

On 2 October 2026 the maintainer confirmed that the historical author aliases
`xyzwebmaster`, `garga`, and `memues` belong to the same person. The project
copyright notice therefore uses the current maintainer name, `memues`. Existing
upstream copyright and permission notices remain unchanged.

## Bundled dependencies

[THIRD-PARTY-NOTICES.txt](../THIRD-PARTY-NOTICES.txt) records each restored package,
its version, NuGet source, upstream repository revision, and license expression,
followed by the complete package-provided license and notice texts. Identical
texts are included once with references from every package that provides them.
The original upstream text is retained, including notices for components whose
licenses differ from the package's top-level MIT license.

The inventory covers packages with runtime/native assets in the selected restore
target, plus runtime packs for the frameworks the application actually uses.
Build-only tooling, unused downloaded runtime packs, and Windows components
provided by the operating system are not described as bundled dependencies.

After changing dependencies, SDK/runtime patch versions, or target frameworks,
restore the release configuration and refresh the notices before building.
The notice and Store build scripts require PowerShell 7 or later (`pwsh`):

```powershell
dotnet restore WhitehatSecurity.csproj -r win-x64 -p:Configuration=Release
pwsh -NoProfile -File scripts/Update-ThirdPartyNotices.ps1
```

To verify that the checked-in notices match the restored dependency versions and
texts without modifying the file:

```powershell
pwsh -NoProfile -File scripts/Update-ThirdPartyNotices.ps1 -Check
```

The script requires restored packages and fails when it cannot find a package's
license text. It does not download packages, assign licenses, or alter upstream
notices. Review new dependency terms when updating packages; generation of this
file alone is not an assessment of a new dependency's compatibility.

CI, GitHub release builds, and the Store EXE build script run this check after
restore. [global.json](../global.json) pins SDK 8.0.425 with roll-forward disabled;
CI and release workflows install that exact SDK from the same file. Local builds
must also use this SDK so that its self-contained runtime defaults match CI.

When upgrading the SDK, update `global.json`, install the selected SDK, restore,
and regenerate the notices with the commands above. Review the changed package
versions, source revisions, license terms, and full notice texts together before
committing the SDK and notice updates. The `-Check` gate deliberately fails if
the restored packages or their notice content differ from the checked-in file;
its diagnostic lists the stored and restored package versions without dumping
the license texts.
