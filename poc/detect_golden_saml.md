# =============================================================================
# check_dll_hash.ps1
# SolarWinds SUNBURST — DLL Hash Verifier (Windows / PowerShell)
# CVE-2020-10148 / SUNBURST / Solorigate
#
# Verifies the SHA-256 hash of SolarWinds.Orion.Core.BusinessLayer.dll
# against all known malicious hashes from the SUNBURST campaign.
# Also scans for TEARDROP artifacts and known C2 network connections.
#
# Usage:
#   .\check_dll_hash.ps1
#   .\check_dll_hash.ps1 -DllPath "C:\custom\path\to\dll"
#   .\check_dll_hash.ps1 -ScanAll   (full system scan including network)
#
# Run as Administrator for full network connection visibility.
# For detection and educational purposes only.
# =============================================================================

param(
    [string]$DllPath = "",
    [switch]$ScanAll = $false
)

# ── Configuration ─────────────────────────────────────────────────────────────

$MaliciousHashes = @{
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77" = "Orion 2019.4 HF5"
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6" = "Orion 2020.2 (unpatched)"
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134" = "Orion 2020.2 HF1 (variant 1)"
    "ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c" = "Orion 2020.2 HF1 (variant 2)"
    "c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77" = "Orion 2020.2 HF1 (variant 3)"
}

$DefaultDllPaths = @(
    "C:\Program Files (x86)\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll",
    "C:\Program Files\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll",
    "C:\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll"
)

$TearDropArtifacts = @(
    "$env:WINDIR\SysWOW64\netsetupsvc.dll",
    "$env:PROGRAMDATA\gracious_truth.jpg",
    "$env:TEMP\gracious_truth.jpg"
)

$SunburstRatArtifacts = @(
    "$env:PROGRAMDATA\wt.exe"  # also used in the 2026 axios attack — shared indicator check
)

$C2Domains = @(
    "avsvmcloud.com",
    "databasegalore.com",
    "deftsecurity.com",
    "freescanonline.com",
    "highdatabase.com",
    "incomeupdate.com",
    "panhardware.com",
    "thedoccloud.com",
    "websitetheme.com",
    "zupertech.com"
)

# ── Output Helpers ────────────────────────────────────────────────────────────

$script:Compromised = 0
$script:Warnings = 0

function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; $script:Warnings++ }
function Write-Bad   { param($msg) Write-Host "[!!]    $msg" -ForegroundColor Red;    $script:Compromised++ }

# ── Banner ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " SolarWinds SUNBURST — DLL Hash Verifier & IOC Scanner"    -ForegroundColor White
Write-Host " CVE-2020-10148 / Solorigate / NOBELIUM"                    -ForegroundColor Gray
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"            -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

# ── 1. DLL Hash Verification ──────────────────────────────────────────────────

Write-Info "Checking SolarWinds.Orion.Core.BusinessLayer.dll hash..."

$DllsToCheck = @()

if ($DllPath -ne "") {
    $DllsToCheck += $DllPath
} else {
    foreach ($path in $DefaultDllPaths) {
        if (Test-Path $path) {
            $DllsToCheck += $path
        }
    }
}

if ($DllsToCheck.Count -eq 0) {
    Write-Info "SolarWinds Orion DLL not found at any default location"
    Write-Info "  Use -DllPath to specify a custom path"
} else {
    foreach ($dll in $DllsToCheck) {
        Write-Info "Hashing: $dll"
        try {
            $hash = (Get-FileHash $dll -Algorithm SHA256).Hash.ToLower()
            
            if ($MaliciousHashes.ContainsKey($hash)) {
                $version = $MaliciousHashes[$hash]
                Write-Bad "MALICIOUS DLL DETECTED ($version)"
                Write-Bad "  Path:   $dll"
                Write-Bad "  SHA256: $hash"
                Write-Bad "  System is COMPROMISED — isolate immediately"
            } else {
                Write-Ok "DLL hash is clean"
                Write-Info "  Path:   $dll"
                Write-Info "  SHA256: $hash"
            }
        } catch {
            Write-Warn "Could not hash file: $dll — $_"
        }
    }
}

Write-Host ""

# ── 2. TEARDROP / File Artifact Check ────────────────────────────────────────

Write-Info "Checking for TEARDROP and SUNBURST file artifacts..."

$FoundArtifact = $false

foreach ($path in $TearDropArtifacts) {
    if (Test-Path $path) {
        Write-Bad "TEARDROP artifact found: $path"
        $FoundArtifact = $true
    }
}

foreach ($path in $SunburstRatArtifacts) {
    if (Test-Path $path) {
        Write-Bad "Known RAT artifact found: $path"
        $FoundArtifact = $true
    }
}

if (-not $FoundArtifact) {
    Write-Ok "No known TEARDROP/SUNBURST file artifacts found"
}

Write-Host ""

# ── 3. Network Connections ────────────────────────────────────────────────────

if ($ScanAll) {
    Write-Info "Checking active network connections for C2 patterns..."

    try {
        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        # Check for connections on port 8000 (common in related campaigns)
        $Port8000 = $Connections | Where-Object { $_.RemotePort -eq 8000 }
        if ($Port8000) {
            foreach ($conn in $Port8000) {
                Write-Warn "Established connection on port 8000 to $($conn.RemoteAddress) — review manually"
            }
        }

        # Check for unexpected HTTPS outbound from SolarWinds process space
        $SWProcesses = Get-Process -Name "SolarWinds.BusinessLayerHost*" -ErrorAction SilentlyContinue
        if ($SWProcesses) {
            Write-Info "SolarWinds Orion host processes found — reviewing outbound connections"
            foreach ($proc in $SWProcesses) {
                $procConns = $Connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                foreach ($conn in $procConns) {
                    Write-Info "  PID $($proc.Id) → $($conn.RemoteAddress):$($conn.RemotePort)"
                }
            }
        }
    } catch {
        Write-Warn "Could not enumerate network connections (try running as Administrator): $_"
    }

    Write-Host ""

    # ── 4. DNS Cache Check ────────────────────────────────────────────────────
    Write-Info "Checking Windows DNS cache for C2 domain references..."

    try {
        $DnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        $FoundDns = $false

        foreach ($domain in $C2Domains) {
            $matches = $DnsCache | Where-Object { $_.Entry -like "*$domain*" }
            if ($matches) {
                foreach ($m in $matches) {
                    Write-Bad "C2 domain in DNS cache: $($m.Entry) → $($m.Data)"
                }
                $FoundDns = $true
            }
        }

        if (-not $FoundDns) {
            Write-Ok "No C2 domains found in Windows DNS cache"
            Write-Info "  Note: Cache is ephemeral — historical lookups require log analysis"
        }
    } catch {
        Write-Warn "Could not query DNS cache: $_"
    }

    Write-Host ""

    # ── 5. Registry Persistence Check ────────────────────────────────────────
    Write-Info "Checking registry for known SUNBURST persistence keys..."

    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($regPath in $RegPaths) {
        if (Test-Path $regPath) {
            $values = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($values) {
                Write-Info "  Registry key exists: $regPath"
                # Flag any suspicious-looking values — don't print all (could expose legit configs)
                $suspicious = $values.PSObject.Properties | 
                    Where-Object { $_.Value -match "solarwinds|orion|businesslayer" -and 
                                   $_.Name -notmatch "^PS" }
                foreach ($v in $suspicious) {
                    Write-Warn "Suspicious registry value: $regPath\$($v.Name) = $($v.Value)"
                }
            }
        }
    }

    Write-Ok "Registry persistence check complete"
    Write-Host ""
}

# ── 6. Windows Event Log Check ────────────────────────────────────────────────

if ($ScanAll) {
    Write-Info "Searching Windows event logs for SUNBURST-related events..."

    try {
        # Look for the SolarWinds service starting (Event 7036 - Service started)
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7036
            StartTime = (Get-Date).AddYears(-6)  # cover the 2020 window
        } -ErrorAction SilentlyContinue | 
            Where-Object { $_.Message -match "SolarWinds" }

        if ($Events) {
            Write-Info "Found $($Events.Count) SolarWinds service event(s) in System log"
            $Events | Select-Object -First 5 | ForEach-Object {
                Write-Info "  $($_.TimeCreated) — $($_.Message.Substring(0,[Math]::Min(80,$_.Message.Length)))"
            }
        } else {
            Write-Info "No SolarWinds service events found in System log"
        }
    } catch {
        Write-Warn "Could not query Windows event logs: $_"
    }

    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "============================================================" -ForegroundColor White
Write-Host " SCAN SUMMARY"                                               -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($script:Compromised -gt 0) {
    Write-Host " !! $($script:Compromised) CRITICAL INDICATOR(S) FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host " Immediate actions:" -ForegroundColor White
    Write-Host "   1. Disconnect this machine from the network NOW"
    Write-Host "   2. Preserve forensic evidence before any remediation"
    Write-Host "      - Memory dump: use ProcDump or WinPmem"
    Write-Host "      - Disk image: do NOT power off before imaging"
    Write-Host "   3. Rotate ALL credentials accessible from this system"
    Write-Host "      - Active Directory service accounts"
    Write-Host "      - Cloud API keys and service principals"
    Write-Host "      - ADFS token-signing certificates"
    Write-Host "   4. Audit Azure AD for rogue app registrations and admin accounts"
    Write-Host "   5. Engage incident response and notify CISA (cisa.gov/report)"
} elseif ($script:Warnings -gt 0) {
    Write-Host " ⚠  $($script:Warnings) WARNING(S) — manual review recommended" -ForegroundColor Yellow
} else {
    Write-Host " ✓  No indicators of compromise found" -ForegroundColor Green
}

Write-Host ""
Write-Host " Affected Orion versions: 2019.4 HF5, 2020.2, 2020.2 HF1" -ForegroundColor Gray
Write-Host " Safe Orion version:      2020.2.1 HF2 or later"            -ForegroundColor Gray
Write-Host " Exposure window:         March 26 – December 13, 2020"     -ForegroundColor Gray
Write-Host " Tip: Re-run with -ScanAll for network, DNS, and registry checks" -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
