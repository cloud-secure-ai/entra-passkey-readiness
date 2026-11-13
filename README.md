# Entra ID passkey readiness

PowerShell scripts for preparing a Microsoft Entra ID tenant for the retirement of Microsoft-provided SMS and voice MFA, and for moving users onto restrictive, AAGUID-based passkey profiles.

Companion scripts for the [cloud-secure.ai](https://cloud-secure.ai/) blog series **FIDO2 enforcement when replacing SMS and voice MFA**.

## Scripts

| Script | What it does | Changes the tenant? |
|---|---|---|
| `Get-PasskeyReadiness.ps1` | Reads every user's registered authentication methods and places each user in a readiness bucket. Exports a CSV and a console summary. | No |
| `Sync-PasskeyReadinessGroups.ps1` | Creates one security group per bucket from the CSV and keeps membership up to date. Supports `-WhatIf`. | Yes |

## Readiness buckets

| Bucket | Meaning |
|---|---|
| `SmsVoiceOnly` | Only phone-based MFA registered. Blocked at sign-in once Microsoft-provided SMS and voice is retired. |
| `PasskeyOutsideAllow` | Has a passkey whose AAGUID is not on your allow list, such as a synced passkey. It stops working when a restrictive profile replaces the Default passkey profile. |
| `PrivilegedNoHardwareKey` | Member of your privileged group without an approved hardware security key. |
| `NoAuthenticator` | Has MFA, but no Microsoft Authenticator and no allowed passkey. |
| `NotMfaCapable` | No MFA method registered. |
| `Ready` | Microsoft Authenticator or an allowed passkey registered. |

## Quick start

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser

# 1. Report (read-only)
.\Get-PasskeyReadiness.ps1 -EnabledUsersOnly -LicensedUsersOnly

# 2. Report with a hardware key requirement for a privileged group
$authenticator = 'de1e552d-db1d-4423-a619-566b625cdc84', '90a3ccdf-635c-4729-a248-9b709135078f'
$yubiKey5Nfc   = 'fa2b99dc-9e39-4257-8f92-4a30d23c4118', '2fc0579f-8113-47ea-b116-bb5a8db9202a', 'a25342c0-3cdc-4414-8e46-f4807fca511c'
.\Get-PasskeyReadiness.ps1 -AllowedAaguids ($authenticator + $yubiKey5Nfc) `
    -PrivilegedGroupId '<group object ID>' -PrivilegedAaguids $yubiKey5Nfc

# 3. Preview, then build the bucket groups
.\Sync-PasskeyReadinessGroups.ps1 -CsvPath .\PasskeyReadiness_<timestamp>.csv -WhatIf
.\Sync-PasskeyReadinessGroups.ps1 -CsvPath .\PasskeyReadiness_<timestamp>.csv -RemoveStale
```

## Permissions

| Script | Microsoft Graph permissions |
|---|---|
| `Get-PasskeyReadiness.ps1` | `User.Read.All`, `UserAuthenticationMethod.Read.All`, `GroupMember.Read.All` |
| `Sync-PasskeyReadinessGroups.ps1` | `Group.ReadWrite.All`, `GroupMember.ReadWrite.All` |

`Get-PasskeyReadiness.ps1` also supports unattended runs with certificate authentication (`-TenantId`, `-ClientId`, `-CertificateThumbprint`).

## Notes

- AAGUIDs change between hardware key models and firmware generations. Check them against the vendor's published list before use.
- Phone numbers are masked in the output; only the last four digits are kept.
- No tenant-specific values are stored in the scripts. Pass your own group IDs and AAGUIDs as parameters.

## Credit

Written by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/).

The per-user method lookup approach was informed by the AdminDroid community's [Export MFA Status Report using MS Graph](https://github.com/admindroid-community/powershell-scripts/blob/master/Export%20MFA%20Status%20Report%20using%20MS%20Graph/GetMFAStatusReport.ps1) script.

## Disclaimer

Provided as-is, without warranty. Test in a non-production tenant first.
