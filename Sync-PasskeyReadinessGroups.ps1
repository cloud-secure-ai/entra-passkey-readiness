<#
.SYNOPSIS
    Creates and maintains one security group per readiness bucket from a
    Get-PasskeyReadiness.ps1 CSV, ready for registration campaigns and communications.

.DESCRIPTION
    For each bucket in the report (except Ready), the script makes sure a security group
    named <GroupPrefix><Bucket> exists, adds users who are in the bucket and, with
    -RemoveStale, removes users who have moved out of it. Re-running it is safe: existing
    groups and memberships are left as they are.

    Supports -WhatIf and -Confirm.

    Companion script for the cloud-secure.ai series
    "FIDO2 enforcement when replacing SMS and voice MFA".

.PARAMETER CsvPath
    Path to a PasskeyReadiness_*.csv produced by Get-PasskeyReadiness.ps1.

.PARAMETER GroupPrefix
    Prefix for the group names. Default: MFA-Readiness-

.PARAMETER Buckets
    Buckets to create groups for. Default: every bucket except Ready.

.PARAMETER RemoveStale
    Remove members who are no longer in the bucket.

.EXAMPLE
    .\Sync-PasskeyReadinessGroups.ps1 -CsvPath .\PasskeyReadiness_20261113-1600.csv -WhatIf

    Shows what would be created and added without changing anything.

.EXAMPLE
    .\Sync-PasskeyReadinessGroups.ps1 -CsvPath .\PasskeyReadiness_20261113-1600.csv -GroupPrefix 'Contoso-MFA-' -RemoveStale

.NOTES
    Author:   Seán O'Farrell
    Website:  https://cloud-secure.ai/
    Version:  1.0
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Groups
    Graph permissions: Group.ReadWrite.All, GroupMember.ReadWrite.All
    Writes to the tenant: creates security groups and changes their membership.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,
    [string]$GroupPrefix = 'MFA-Readiness-',
    [string[]]$Buckets = @('SmsVoiceOnly', 'PasskeyOutsideAllow', 'PrivilegedNoHardwareKey', 'NoAuthenticator', 'NotMfaCapable'),
    [switch]$RemoveStale
)

$ErrorActionPreference = 'Stop'
$scopes = 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All'

try {
    $ctx = Get-MgContext
    if (-not $ctx -or ($ctx.AuthType -eq 'Delegated' -and ($scopes | Where-Object { $_ -notin $ctx.Scopes }))) {
        Write-Host "🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }
}
catch {
    Write-Host "❌ Could not connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$report = Import-Csv -Path $CsvPath
$counters = [ordered]@{ GroupsCreated = 0; GroupsExisting = 0; MembersAdded = 0; MembersRemoved = 0; Unchanged = 0; Errors = 0 }

foreach ($bucket in $Buckets) {
    $name    = "$GroupPrefix$bucket"
    $wanted  = @($report | Where-Object Readiness -eq $bucket | Select-Object -ExpandProperty UserId)
    Write-Host "`n📂 $name - $($wanted.Count) user(s) in bucket" -ForegroundColor Cyan

    try {
        $group = Get-MgGroup -Filter "displayName eq '$name'" -ConsistencyLevel eventual -CountVariable c | Select-Object -First 1
        if (-not $group) {
            if ($PSCmdlet.ShouldProcess($name, 'Create security group')) {
                $group = New-MgGroup -DisplayName $name -MailEnabled:$false -MailNickname ($name -replace '[^A-Za-z0-9]', '') `
                    -SecurityEnabled -Description "Passkey readiness bucket $bucket - maintained by Sync-PasskeyReadinessGroups.ps1"
                $counters.GroupsCreated++
                Write-Host "  ✅ Created group" -ForegroundColor Green
            }
            else { continue }
        }
        else {
            $counters.GroupsExisting++
        }

        $current = @{}
        Get-MgGroupMember -GroupId $group.Id -All | ForEach-Object { $current[$_.Id] = $true }

        foreach ($id in $wanted) {
            if ($current.ContainsKey($id)) { $counters.Unchanged++; continue }
            if ($PSCmdlet.ShouldProcess("$name <- $id", 'Add member')) {
                try {
                    New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $id
                    $counters.MembersAdded++
                }
                catch { $counters.Errors++; Write-Host "  ⚠️ Add $id failed: $($_.Exception.Message)" -ForegroundColor Yellow }
            }
        }

        if ($RemoveStale) {
            foreach ($id in $current.Keys | Where-Object { $_ -notin $wanted }) {
                if ($PSCmdlet.ShouldProcess("$name -> $id", 'Remove member')) {
                    try {
                        Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $id
                        $counters.MembersRemoved++
                    }
                    catch { $counters.Errors++; Write-Host "  ⚠️ Remove $id failed: $($_.Exception.Message)" -ForegroundColor Yellow }
                }
            }
        }
    }
    catch {
        $counters.Errors++
        Write-Host "  ❌ $name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n📊 Summary" -ForegroundColor Cyan
$counters.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-16} {1}" -f $_.Key, $_.Value) }
