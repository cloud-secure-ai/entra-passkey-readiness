<#
.SYNOPSIS
    Reports per-user readiness for the retirement of Microsoft-provided SMS and voice MFA
    and for restrictive Microsoft Entra ID passkey profiles.

.DESCRIPTION
    Reads every user's registered authentication methods from Microsoft Graph and places
    each user into one readiness bucket:

      SmsVoiceOnly          Only phone-based MFA registered. Blocked at sign-in once
                            Microsoft-provided SMS and voice is retired.
      PasskeyOutsideAllow   Has a passkey whose AAGUID is not in -AllowedAaguids, for example
                            a synced passkey. It stops working once a restrictive passkey
                            profile replaces the Default passkey profile.
      PrivilegedNoHardwareKey
                            Member of -PrivilegedGroupId without a passkey matching
                            -PrivilegedAaguids (for example a YubiKey for Tier 0).
      NoAuthenticator       Has MFA, but no Microsoft Authenticator and no allowed passkey.
      NotMfaCapable         No MFA method registered at all.
      Ready                 Microsoft Authenticator or an allowed passkey registered.

    Passkey AAGUIDs and models are read from the same Graph call as the other methods, so
    the script works without Microsoft Entra ID P1 reporting. Phone numbers are masked in
    the output. The script is read-only.

    Companion script for the cloud-secure.ai series
    "FIDO2 enforcement when replacing SMS and voice MFA".

.PARAMETER AllowedAaguids
    AAGUIDs permitted by your passkey profiles. Defaults to Microsoft Authenticator for
    Android and iOS.

.PARAMETER PrivilegedGroupId
    Object ID of the group whose members must hold a hardware key (for example Tier 0).
    Optional.

.PARAMETER PrivilegedAaguids
    AAGUIDs that satisfy the hardware key requirement for -PrivilegedGroupId members.

.PARAMETER LicensedUsersOnly
    Only report users with at least one assigned licence.

.PARAMETER EnabledUsersOnly
    Only report users whose sign-in is allowed.

.PARAMETER IncludeGuests
    Include guest accounts. Members only by default.

.PARAMETER OutputPath
    Folder for the CSV output. Defaults to the current folder.

.PARAMETER TenantId
    Tenant ID for app-only (certificate) authentication.

.PARAMETER ClientId
    Application (client) ID for app-only (certificate) authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only (certificate) authentication.

.EXAMPLE
    .\Get-PasskeyReadiness.ps1 -EnabledUsersOnly

    Interactive sign-in, Microsoft Authenticator as the only allowed passkey provider.

.EXAMPLE
    $authenticator = @(
        'de1e552d-db1d-4423-a619-566b625cdc84',   # Microsoft Authenticator for Android
        '90a3ccdf-635c-4729-a248-9b709135078f'    # Microsoft Authenticator for iOS
    )
    $yubiKey5Nfc = @(
        'fa2b99dc-9e39-4257-8f92-4a30d23c4118',   # YubiKey 5 NFC firmware 5.1
        '2fc0579f-8113-47ea-b116-bb5a8db9202a',   # YubiKey 5 NFC firmware 5.2/5.4
        'a25342c0-3cdc-4414-8e46-f4807fca511c'    # YubiKey 5 NFC firmware 5.7
    )
    .\Get-PasskeyReadiness.ps1 -AllowedAaguids ($authenticator + $yubiKey5Nfc) `
        -PrivilegedGroupId '<Tier 0 group object ID>' -PrivilegedAaguids $yubiKey5Nfc `
        -LicensedUsersOnly -EnabledUsersOnly -OutputPath C:\Reports

.EXAMPLE
    .\Get-PasskeyReadiness.ps1 -TenantId '<tenant ID>' -ClientId '<app ID>' -CertificateThumbprint '<thumbprint>'

    Unattended run with an app registration holding User.Read.All, GroupMember.Read.All and
    UserAuthenticationMethod.Read.All application permissions.

.NOTES
    Author:   Seán O'Farrell
    Website:  https://cloud-secure.ai/
    Version:  1.0
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
              Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups
    Graph permissions (delegated or application):
              User.Read.All, UserAuthenticationMethod.Read.All, GroupMember.Read.All
    Read-only: makes no changes to the tenant.
    Verify AAGUIDs against the vendor's published list before use.
#>
[CmdletBinding()]
param(
    [string[]]$AllowedAaguids = @(
        'de1e552d-db1d-4423-a619-566b625cdc84',   # Microsoft Authenticator for Android
        '90a3ccdf-635c-4729-a248-9b709135078f'    # Microsoft Authenticator for iOS
    ),
    [string]$PrivilegedGroupId,
    [string[]]$PrivilegedAaguids = @(),
    [switch]$LicensedUsersOnly,
    [switch]$EnabledUsersOnly,
    [switch]$IncludeGuests,
    [string]$OutputPath = (Get-Location).Path,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

$ErrorActionPreference = 'Stop'
$scopes = 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'GroupMember.Read.All'

#region Connect
try {
    foreach ($module in 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Groups') {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Module $module is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
        }
    }
    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Write-Host "🔐 Connecting to Microsoft Graph with certificate authentication..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    }
    else {
        $ctx = Get-MgContext
        if (-not $ctx -or ($scopes | Where-Object { $_ -notin $ctx.Scopes })) {
            Write-Host "🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $scopes -NoWelcome
        }
    }
}
catch {
    Write-Host "❌ Could not connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    return
}
#endregion

#region Lookups
$allowed    = @($AllowedAaguids    | ForEach-Object { $_.ToLower() })
$privileged = @($PrivilegedAaguids | ForEach-Object { $_.ToLower() })

$privilegedMembers = @{}
if ($PrivilegedGroupId) {
    if (-not $privileged) {
        Write-Host "⚠️ -PrivilegedGroupId was supplied without -PrivilegedAaguids; privileged check skipped." -ForegroundColor Yellow
    }
    else {
        try {
            Get-MgGroupTransitiveMember -GroupId $PrivilegedGroupId -All | ForEach-Object { $privilegedMembers[$_.Id] = $true }
            Write-Host "👥 Privileged group members: $($privilegedMembers.Count)" -ForegroundColor Cyan
        }
        catch {
            Write-Host "⚠️ Could not read privileged group $PrivilegedGroupId : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Hide-PhoneNumber([string]$Number) {
    if (-not $Number) { return '' }
    $digits = $Number -replace '\D'
    if ($digits.Length -le 4) { return '****' }
    return ('*' * ($digits.Length - 4)) + $digits.Substring($digits.Length - 4)
}
#endregion

#region Users
Write-Host "📥 Retrieving users..." -ForegroundColor Cyan
$filter = if ($IncludeGuests) { $null } else { "userType eq 'Member'" }
$userParams = @{ All = $true; Property = 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,userType' }
if ($filter) { $userParams.Filter = $filter }
$users = Get-MgUser @userParams
if ($LicensedUsersOnly) { $users = $users | Where-Object { $_.AssignedLicenses.Count -gt 0 } }
if ($EnabledUsersOnly)  { $users = $users | Where-Object { $_.AccountEnabled } }
$total = @($users).Count
Write-Host "👤 Users in scope: $total" -ForegroundColor Cyan
#endregion

#region Evaluate
$processed = 0; $failed = 0
$results = foreach ($u in $users) {
    $processed++
    Write-Progress -Activity 'Evaluating passkey readiness' -Status $u.UserPrincipalName -PercentComplete (($processed / [math]::Max($total, 1)) * 100)

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -All
    }
    catch {
        $failed++
        Write-Host "⚠️ $($u.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }

    $types = @(); $phones = @(); $passkeys = @()
    foreach ($m in $methods) {
        $type = ($m.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod$', '')
        $types += $type
        switch ($type) {
            'phone' { $phones += '{0} {1}' -f $m.AdditionalProperties['phoneType'], (Hide-PhoneNumber $m.AdditionalProperties['phoneNumber']) }
            'fido2' { $passkeys += [pscustomobject]@{ Model = $m.AdditionalProperties['model']; AaGuid = "$($m.AdditionalProperties['aaGuid'])".ToLower() } }
        }
    }
    $types = $types | Sort-Object -Unique

    $strong      = $types | Where-Object { $_ -notin 'password', 'phone', 'email', 'temporaryAccessPass' }
    $hasPhone    = $types -contains 'phone'
    $hasAuthApp  = ($types -contains 'microsoftAuthenticator') -or ($types -contains 'passwordlessMicrosoftAuthenticator')
    $allowedKeys = $passkeys | Where-Object { $_.AaGuid -in $allowed }
    $outsideKeys = $passkeys | Where-Object { $_.AaGuid -and $_.AaGuid -notin $allowed }
    $isPriv      = $privilegedMembers.ContainsKey($u.Id)
    $hasPrivKey  = [bool]($passkeys | Where-Object { $_.AaGuid -in $privileged })

    $bucket = switch ($true) {
        { -not $strong -and -not $hasPhone }      { 'NotMfaCapable'; break }
        { -not $strong -and $hasPhone }           { 'SmsVoiceOnly'; break }
        { $outsideKeys }                          { 'PasskeyOutsideAllow'; break }
        { $isPriv -and $privileged -and -not $hasPrivKey } { 'PrivilegedNoHardwareKey'; break }
        { -not $hasAuthApp -and -not $allowedKeys } { 'NoAuthenticator'; break }
        default                                   { 'Ready' }
    }

    [pscustomobject]@{
        DisplayName        = $u.DisplayName
        UserPrincipalName  = $u.UserPrincipalName
        UserId             = $u.Id
        Readiness          = $bucket
        Privileged         = $isPriv
        SignInAllowed      = $u.AccountEnabled
        Licensed           = ($u.AssignedLicenses.Count -gt 0)
        MethodsRegistered  = $types -join '; '
        Phones             = $phones -join '; '
        PasskeyModels      = ($passkeys.Model  | Where-Object { $_ }) -join '; '
        PasskeyAaguids     = ($passkeys.AaGuid | Where-Object { $_ }) -join '; '
    }
}
Write-Progress -Activity 'Evaluating passkey readiness' -Completed
#endregion

#region Output
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$file = Join-Path $OutputPath ("PasskeyReadiness_{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
$results | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8

Write-Host "`n📊 Readiness summary" -ForegroundColor Cyan
$results | Group-Object Readiness | Sort-Object Count -Descending |
    Format-Table @{ n = 'Readiness'; e = { $_.Name } }, Count -AutoSize | Out-Host

$notReady = @($results | Where-Object Readiness -ne 'Ready').Count
Write-Host "✅ Ready:      $(@($results).Count - $notReady)" -ForegroundColor Green
Write-Host "⚠️ Not ready:  $notReady" -ForegroundColor Yellow
if ($failed) { Write-Host "❌ Not read:   $failed" -ForegroundColor Red }
Write-Host "📄 Report:     $file" -ForegroundColor Cyan
#endregion
