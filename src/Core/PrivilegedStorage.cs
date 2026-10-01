// SPDX-License-Identifier: MIT

namespace WhitehatSecurity.Core;

/// <summary>PowerShell guards for DNS state consumed with administrator rights.</summary>
public static class PrivilegedStorage
{
    public const string DnsBackupPowerShell = """
function Assert-WhsBackupAcl {
    param([System.Security.AccessControl.FileSystemSecurity] $Acl, [switch] $AllowDirectoryCreate)
    $trusted = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM and Administrators
    $owner = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) {
        throw 'The DNS backup is not administrator-owned. Inspect its permissions before using it.'
    }
    $write = [System.Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    # Legacy ProgramData directories inherited Users:Write (create children),
    # while files inherited only read access. Accept that directory only for
    # migration, provided users cannot replace/delete children or its ACL.
    if ($AllowDirectoryCreate) {
        $write = [System.Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (($rule.FileSystemRights -band $write) -ne 0 -and $trusted -notcontains $rule.IdentityReference.Value) {
            throw 'The DNS backup is writable without administrator rights. Inspect it before restoring DNS.'
        }
    }
}

function Assert-WhsBackupPath {
    param([string] $Path, [switch] $AllowDirectoryCreate)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse points are not allowed in the DNS backup path.'
        }
        if ($ancestor -is [System.IO.DirectoryInfo]) { $ancestor = $ancestor.Parent }
        else { $ancestor = $ancestor.Directory }
    }
    if ($AllowDirectoryCreate -and $item -isnot [System.IO.DirectoryInfo]) {
        throw 'Directory migration requires a directory.'
    }
    Assert-WhsBackupAcl -Acl (Get-Acl -LiteralPath $Path -ErrorAction Stop) -AllowDirectoryCreate:$AllowDirectoryCreate
}

function Get-WhsDnsBackupPath {
    param([switch] $Create)
    $directory = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'Whitehat Security'
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    if (-not (Test-WhsPathEntry -Path $directory) -and $Create) {
        [System.IO.Directory]::CreateDirectory($directory, $security) | Out-Null
    }
    $backup = Join-Path $directory 'dns-backup.json'
    if (Test-WhsPathEntry -Path $directory) {
        Assert-WhsBackupPath -Path $directory -AllowDirectoryCreate
        # Validate existing contents before sealing inherited directory
        # permissions; changing an ACL cannot make planted data trustworthy.
        if (Test-WhsPathEntry -Path $backup) { Assert-WhsBackupPath -Path $backup }
        Set-Acl -LiteralPath $directory -AclObject $security -ErrorAction Stop
        Assert-WhsBackupPath -Path $directory
    }
    if (Test-WhsPathEntry -Path $backup) { Assert-WhsBackupPath -Path $backup }
    return $backup
}

function Test-WhsPathEntry {
    param([string] $Path)
    # Enumerate the entry itself: Test-Path can hide a dangling link, which
    # must be rejected before a later writer tries to create its target.
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($parent)) { return $false }
    $name = [System.IO.Path]::GetFileName($Path)
    return @([System.IO.Directory]::EnumerateFileSystemEntries($parent, $name)).Count -gt 0
}

""";
}
