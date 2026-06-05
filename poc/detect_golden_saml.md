# Golden SAML Detection Guide

> **Context:** Post-exploitation technique observed in the SUNBURST campaign  
> **Actor:** NOBELIUM / UNC2452  
> **Target:** Microsoft 365 / Azure AD environments connected to on-premise ADFS

---

## What Is a Golden SAML Attack?

After gaining a foothold via the SUNBURST backdoor, NOBELIUM pivoted from on-premise networks into cloud environments using a technique known as **Golden SAML** — analogous to Kerberos Golden Ticket attacks but targeting SAML-based cloud authentication.

**The attack:**

1. Attacker accesses an ADFS (Active Directory Federation Services) server in the compromised environment
2. Extracts the **token-signing private key** (certificate private key used to sign SAML assertions)
3. Using this key, they can forge SAML assertions for **any user in the organization** — including global administrators — without knowing any passwords
4. Forged tokens grant access to any application that trusts the ADFS server: Microsoft 365, Azure, SharePoint, Teams, any SAML-enabled SaaS

**Why it's devastating:**

- Access persists even after password resets (the signing key is still valid)
- Works even if MFA is enforced (the forged token bypasses the normal auth flow)
- The legitimate ADFS server has no record of the forged token being issued
- Standard Microsoft 365 audit logs may not capture the anomalous access

---

## Detection

### Log Sources Required

| Log | Location | What to Look For |
|-----|----------|-----------------|
| ADFS Admin Log | `Event Viewer → Applications and Services → AD FS → Admin` | Event IDs 500, 501, 1007, 1021 |
| ADFS Audit Log | Windows Security log, Event ID 1202 | Token issuance for unexpected users |
| Azure AD Sign-In Logs | Azure Portal → Azure AD → Sign-ins | Sign-ins from unexpected IPs, unusual UserAgent |
| Microsoft 365 Audit Log | Compliance Center → Audit | Mail access, admin actions, app consent |

### Windows Event Log Queries

**Detect unusual SAML token issuance (ADFS server):**

```powershell
# PowerShell — Query ADFS Audit Events
Get-WinEvent -LogName "Security" -FilterXPath `
  '*[System[EventID=1202] and EventData[Data[@Name="CallerIdentity"] != "DOMAIN\svc-adfs"]]' `
  -MaxEvents 100 |
  Select-Object TimeCreated, 
    @{N="User";E={$_.Properties[0].Value}},
    @{N="IP";E={$_.Properties[3].Value}} |
  Sort-Object TimeCreated -Descending

# Look specifically for admin accounts being impersonated
Get-WinEvent -LogName "Security" -FilterXPath `
  '*[System[EventID=1202]]' |
  Where-Object { $_.Message -match "admin|global|tier0" } |
  Format-List TimeCreated, Message
```

**Detect ADFS certificate operations:**

```powershell
# Event 1007: Token Signing Certificate Change
# Event 1021: Certificate Loaded
Get-WinEvent -LogName "AD FS/Admin" |
  Where-Object { $_.Id -in @(1007, 1021, 500, 501) } |
  Sort-Object TimeCreated -Descending |
  Format-List TimeCreated, Id, Message
```

### Azure AD / Microsoft 365 Queries (KQL — Sentinel / Defender)

**Detect sign-ins from unexpected IPs using SAML tokens:**

```kql
// Azure AD Sign-In Logs — Federated auth from unexpected locations
SigninLogs
| where AuthenticationProtocol == "SAML20"
| where ResultType == 0  // successful sign-in
| where NetworkLocationDetails !contains "trustedNamedLocation"
| summarize count() by UserPrincipalName, IPAddress, AppDisplayName, bin(TimeGenerated, 1h)
| where count_ > 5
| sort by count_ desc
```

**Detect admin activity from cloud-only sessions (possible Golden SAML):**

```kql
// Audit log — Admin operations from sessions that bypassed normal auth
AuditLogs
| where LoggedByService == "Core Directory"
| where OperationName in ("Add member to role", "Reset user password", "Update application")
| where InitiatedBy.user.ipAddress !startswith "10."   // adjust for your ranges
| project TimeGenerated, OperationName, 
    User = InitiatedBy.user.userPrincipalName,
    IP = InitiatedBy.user.ipAddress,
    Target = TargetResources[0].displayName
| sort by TimeGenerated desc
```

**Detect mail access from unexpected user agents (Cobalt Strike Beacon UA):**

```kql
// Exchange Online — SUNBURST Cobalt Strike UA string
OfficeActivity
| where Operation in ("MailItemsAccessed", "FileAccessed", "Send")
| where UserAgent contains "MSIE 8.0" or UserAgent contains "Trident/4.0"
| summarize count() by UserId, ClientIP, UserAgent, bin(TimeGenerated, 1h)
| sort by TimeGenerated desc
```

### Splunk Queries

```splunk
// Detect unusual ADFS token issuance
index=windows EventCode=1202
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| stats count by time, src_user, src_ip, dest
| where count > 3
| sort - count

// Detect Azure AD sign-ins via SAML from new IPs
index=azure_signin authenticationProtocol=SAML20 resultType=0
| stats dc(ipAddress) as unique_ips, count by userPrincipalName
| where unique_ips > 5
| sort - unique_ips
```

---

## Forensic Indicators

### Signs of ADFS Certificate Theft

```powershell
# Check when the token-signing certificate was last accessed
# (anomalous access during breach period: March–December 2020)
Get-AdfsCertificate -CertificateType Token-Signing |
    Select-Object CertificateType, Thumbprint, NotAfter, IsPrimary

# Check if the certificate was exported
# Exportable private keys are a prerequisite for Golden SAML
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -match "ADFS" }
$cert | Select-Object Thumbprint, HasPrivateKey, 
    @{N="Exportable";E={$_.PrivateKey.CspKeyContainerInfo.Exportable}}
```

### Signs of Unauthorized Token Issuance

Look for ADFS Event ID 1200 (Token Issued) followed immediately by cloud service access from:
- IP addresses not in your known employee/VPN range
- Unusual geographic locations
- Unusual user-agents (especially IE 8 on XP — see WAVESHAPER.V2 note in analysis.md)
- Unusual times (outside business hours for the user's timezone)

---

## Remediation if Golden SAML Is Confirmed

1. **Revoke all existing SAML tokens** — requires rotating the ADFS token-signing certificate

   ```powershell
   # Rotate the token-signing certificate (this invalidates all existing SAML tokens)
   # WARNING: This will log out all federated users — coordinate with IT
   Update-AdfsCertificate -CertificateType Token-Signing -Urgent
   ```

2. **Audit all Azure AD / M365 admin accounts** for accounts created or modified during the breach window

   ```powershell
   # Find recently created Azure AD users (requires AzureAD module)
   Connect-AzureAD
   Get-AzureADUser -All $true | 
     Where-Object { $_.CreatedDateTime -gt (Get-Date "2020-03-01") -and 
                    $_.CreatedDateTime -lt (Get-Date "2020-12-31") } |
     Select-Object UserPrincipalName, CreatedDateTime, UserType
   ```

3. **Remove unauthorized OAuth application consent grants** — NOBELIUM was observed granting persistent app permissions

   ```powershell
   # List all OAuth app consents (review for unexpected entries)
   Connect-MgGraph
   Get-MgOauth2PermissionGrant | 
     Select-Object ClientId, ConsentType, Scope, PrincipalId |
     Sort-Object ClientId
   ```

4. **Enable Azure AD Identity Protection** and configure Conditional Access policies requiring compliant device + MFA for all privileged roles

5. **Move ADFS certificate to hardware-backed storage** (HSM or TPM) — prevents private key export

---

## References

- CyberArk — Golden SAML: Newly Discovered Attack Technique: https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
- Mandiant — Remediation and Hardening Strategies for Microsoft 365: https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452
- Microsoft — Advice for incident responders on recovery from NOBELIUM: https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/
- CISA — Alert AA21-008A: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a
