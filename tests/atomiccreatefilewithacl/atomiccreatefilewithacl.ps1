
#
# MIT License
#
# Copyright (c) 2025 Roland Mainz <roland.mainz@nrubsig.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

#
# atomiccreatefilewithacl.ps1 - Atomically create file and add ACL at create time
#
# powershell -Command "$( < /cygdrive/l/createacltest/atomiccreatefilewithacl.ps1 )"
#

function New-FileWithAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Content,

        # Zero or more user accounts (local or domain). e.g. "alice", "GLOBAL.LOC\bob"
        [string[]]$Users = @(),

        # Zero or more group accounts (local or domain). e.g. "cygwingrp2", "GLOBAL.LOC\DevOps"
        [string[]]$Groups = @(),

        # If set, disables inheritance and removes inherited ACEs.
        [switch]$DisableInheritance,

        # If set, keeps inherited ACEs but prevents further propagation changes (uses Protect + Preserve)
        [switch]$ProtectAndPreserveInheritance
    )

    begin {
        # Validate inheritance switches
        if ($DisableInheritance -and $ProtectAndPreserveInheritance) {
            throw "Use either -DisableInheritance or -ProtectAndPreserveInheritance, not both."
        }

        # Ensure parent directory exists
        $dir = Split-Path -Path $Path -Parent
        if ([string]::IsNullOrWhiteSpace($dir)) {
            $dir = "."
        }
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        # Helper: resolve an NTAccount (string) to a SID, with clear error if not found
        function Resolve-ToSid {
            param([Parameter(Mandatory)][string]$Account)
            try {
                $nt = New-Object System.Security.Principal.NTAccount($Account)
                return $nt.Translate([System.Security.Principal.SecurityIdentifier])
            }
            catch {
                throw "Account not found or not resolvable: '$Account'. Use 'DOMAIN\name' or '.\name' for local."
            }
        }

        # Helper: create a FileSystemAccessRule (FullControl, file-only)
        function New-FullControlRule {
            param([Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$Sid)
            return New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::None,       # file only
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
    }

    process {
        # Build FileSecurity (DACL)
        $fileSec = New-Object System.Security.AccessControl.FileSecurity

        # Inheritance behavior
        if ($DisableInheritance) {
            # protect: true, preserveInheritedACL: false (remove inherited ACEs)
            $fileSec.SetAccessRuleProtection($true, $false)
        }
        elseif ($ProtectAndPreserveInheritance) {
            # protect: true, preserveInheritedACL: true (keep existing inherited ACEs)
            $fileSec.SetAccessRuleProtection($true, $true)
        }
        else {
            # protect: false -> inherit from parent
            $fileSec.SetAccessRuleProtection($false, $true)
        }

        # Add ACEs for users
        foreach ($u in $Users) {
            if ([string]::IsNullOrWhiteSpace($u)) { continue }
            $sid = Resolve-ToSid -Account $u
            $rule = New-FullControlRule -Sid $sid
            $fileSec.AddAccessRule($rule) | Out-Null
        }

        # Add ACEs for groups
        foreach ($g in $Groups) {
            if ([string]::IsNullOrWhiteSpace($g)) { continue }
            $sid = Resolve-ToSid -Account $g
            $rule = New-FullControlRule -Sid $sid
            $fileSec.AddAccessRule($rule) | Out-Null
        }

        # Create file atomically with the ACL
        $fs = $null
        $writer = $null
        try {
            $fs = [System.IO.File]::Create($Path, 4096, [System.IO.FileOptions]::None, $fileSec)
            $writer = New-Object System.IO.StreamWriter($fs)
            $writer.Write($Content)
            $writer.Flush()
        }
        finally {
            if ($writer) { $writer.Dispose() }
            if ($fs)     { $fs.Dispose() }
        }

        # Return file info and ACL
        [PSCustomObject]@{
            Path = (Resolve-Path -LiteralPath $Path).ProviderPath
            Length = (Get-Item -LiteralPath $Path).Length
            Acl = (Get-Acl -LiteralPath $Path)
        }
    }
}

# test 1
New-FileWithAcl `
  -Path "phw1.txt" `
  -Content "hello world" `
  -Users @("siegfried_wulsch", "roland_mainz") `
  -Groups @("cygwingrp2") `
  -DisableInheritance

# EOF.
