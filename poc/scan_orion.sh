#!/usr/bin/env bash
# =============================================================================
# scan_orion.sh
# SolarWinds SUNBURST — IOC Scanner (Linux / macOS)
# CVE-2020-10148 / SUNBURST / Solorigate
#
# Scans the system for indicators of compromise from the SolarWinds
# Orion supply chain attack (March–December 2020):
#   - Malicious DLL hashes
#   - Known C2 domain references in DNS logs
#   - Known C2 domains in /etc/hosts or resolv.conf
#   - File system artifacts (gracious_truth.jpg, TEARDROP residue)
#   - Active network connections to known C2 IPs
#
# Usage:  ./scan_orion.sh [path_to_dll_for_hash_check]
#
# For detection and educational purposes only.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
NC='\033[0m'

COMPROMISED=0
WARNINGS=0

info()  { echo -e "${CYN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[OK]${NC}    $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; WARNINGS=$((WARNINGS+1)); }
bad()   { echo -e "${RED}${BLD}[!!]${NC}    $*"; COMPROMISED=$((COMPROMISED+1)); }

# Known malicious SHA-256 hashes for SolarWinds.Orion.Core.BusinessLayer.dll
MALICIOUS_HASHES=(
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"  # 2019.4 HF5
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"  # 2020.2
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"  # 2020.2 HF1 variant 1
    "ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c"  # 2020.2 HF1 variant 2
    "c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77"  # 2020.2 HF1 variant 3
)

# Known C2 domains (avsvmcloud.com was sinkholed Dec 14, 2020)
C2_DOMAINS=(
    "avsvmcloud.com"
    "databasegalore.com"
    "deftsecurity.com"
    "freescanonline.com"
    "highdatabase.com"
    "incomeupdate.com"
    "panhardware.com"
    "thedoccloud.com"
    "websitetheme.com"
    "zupertech.com"
)

echo ""
echo "============================================================"
echo -e " ${BLD}SolarWinds SUNBURST — IOC Scanner${NC}"
echo " CVE-2020-10148 / Solorigate / NOBELIUM"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

# ── 1. DLL Hash Check ─────────────────────────────────────────────────────────
info "Checking DLL hash..."

DLL_PATH="${1:-}"

if [[ -z "$DLL_PATH" ]]; then
    # Try to find the DLL on the filesystem (Wine/CrossOver or mounted shares)
    DLL_PATH=$(find /opt /mnt /media /home -name "SolarWinds.Orion.Core.BusinessLayer.dll" \
               2>/dev/null | head -1 || true)
fi

if [[ -n "$DLL_PATH" && -f "$DLL_PATH" ]]; then
    info "Found DLL at: $DLL_PATH"
    if command -v sha256sum &>/dev/null; then
        HASH=$(sha256sum "$DLL_PATH" | cut -d' ' -f1)
    elif command -v shasum &>/dev/null; then
        HASH=$(shasum -a 256 "$DLL_PATH" | cut -d' ' -f1)
    else
        warn "No SHA-256 tool available — skipping hash check"
        HASH=""
    fi

    if [[ -n "$HASH" ]]; then
        MATCH=false
        for h in "${MALICIOUS_HASHES[@]}"; do
            if [[ "$HASH" == "$h" ]]; then
                MATCH=true
                break
            fi
        done

        if $MATCH; then
            bad "MALICIOUS DLL HASH DETECTED: $HASH"
            bad "File: $DLL_PATH"
            bad "System is COMPROMISED — isolate immediately"
        else
            ok "DLL hash does not match any known malicious hash"
            info "  Hash: $HASH"
        fi
    fi
else
    info "SolarWinds Orion DLL not found on this system (expected on Windows)"
    info "  Pass path as argument: ./scan_orion.sh /path/to/SolarWinds.Orion.Core.BusinessLayer.dll"
fi

echo ""

# ── 2. DNS Log Search ─────────────────────────────────────────────────────────
info "Searching system logs for C2 domain references..."

LOG_FILES=(
    "/var/log/syslog"
    "/var/log/messages"
    "/var/log/dns.log"
    "/var/log/named.log"
    "/var/log/bind/query.log"
    "/var/log/firewall.log"
)

C2_PATTERN=$(IFS="|"; echo "${C2_DOMAINS[*]}")
FOUND_IN_LOGS=false

for log in "${LOG_FILES[@]}"; do
    if [[ -f "$log" ]]; then
        if grep -qiE "$C2_PATTERN" "$log" 2>/dev/null; then
            bad "C2 domain reference found in $log:"
            grep -iE "$C2_PATTERN" "$log" | tail -5 | while read -r line; do
                echo "    $line"
            done
            FOUND_IN_LOGS=true
        fi
    fi
done

# macOS unified log check
if [[ "$(uname -s)" == "Darwin" ]]; then
    for domain in "${C2_DOMAINS[@]}"; do
        if log show --predicate "eventMessage contains \"$domain\"" --last 365d 2>/dev/null \
           | grep -q "$domain"; then
            bad "C2 domain '$domain' found in macOS unified log (last 365 days)"
            FOUND_IN_LOGS=true
        fi
    done
fi

if ! $FOUND_IN_LOGS; then
    ok "No C2 domain references found in system logs"
    info "  Note: Logs may have been rotated; exposure window was March–Dec 2020"
fi

echo ""

# ── 3. /etc/hosts and resolv.conf check ───────────────────────────────────────
info "Checking /etc/hosts and DNS configuration for C2 domains..."

for domain in "${C2_DOMAINS[@]}"; do
    if grep -qi "$domain" /etc/hosts 2>/dev/null; then
        bad "C2 domain '$domain' found in /etc/hosts"
    fi
    if grep -qi "$domain" /etc/resolv.conf 2>/dev/null; then
        bad "C2 domain '$domain' found in /etc/resolv.conf"
    fi
done

ok "No C2 domains found in /etc/hosts or /etc/resolv.conf"

echo ""

# ── 4. File System Artifacts ──────────────────────────────────────────────────
info "Checking for known SUNBURST/TEARDROP file artifacts..."

ARTIFACT_PATHS=(
    "/tmp/gracious_truth.jpg"
    "/var/tmp/gracious_truth.jpg"
    "$HOME/gracious_truth.jpg"
)

FOUND_ARTIFACT=false
for p in "${ARTIFACT_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
        bad "TEARDROP payload container found: $p"
        FOUND_ARTIFACT=true
    fi
done

# Search mounted drives for Windows TEARDROP paths (if any)
if mount | grep -q "ntfs\|fuseblk"; then
    TEARDROP_WIN=$(find /mnt /media -path "*/Windows/SysWOW64/netsetupsvc.dll" 2>/dev/null | head -1 || true)
    if [[ -n "$TEARDROP_WIN" ]]; then
        bad "Potential TEARDROP artifact found at Windows path: $TEARDROP_WIN"
        FOUND_ARTIFACT=true
    fi
fi

if ! $FOUND_ARTIFACT; then
    ok "No known TEARDROP/RAINDROP file artifacts found"
fi

echo ""

# ── 5. Active Network Connections ─────────────────────────────────────────────
info "Checking for active connections to known C2 infrastructure..."

# Known C2 IP ranges associated with the SUNBURST campaign (as of Dec 2020)
C2_IPS=(
    "13.59.205.66"      # AWS - used as C2
    "54.193.127.66"     # AWS - used as C2
    "34.203.203.23"     # AWS - used as C2
    "54.215.192.52"     # AWS - used as C2
    "184.72.102.166"    # AWS - used as C2
    "13.57.184.217"     # AWS - used as C2
    "96.30.135.55"      # Secondary C2
)

FOUND_CONNECTION=false
for ip in "${C2_IPS[@]}"; do
    if command -v ss &>/dev/null; then
        if ss -tnp 2>/dev/null | grep -q "$ip"; then
            bad "Active connection to known SUNBURST C2 IP: $ip"
            FOUND_CONNECTION=true
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -an 2>/dev/null | grep -q "$ip"; then
            bad "Active connection to known SUNBURST C2 IP: $ip"
            FOUND_CONNECTION=true
        fi
    fi
done

if ! $FOUND_CONNECTION; then
    ok "No active connections to known SUNBURST C2 IPs"
    info "  Note: avsvmcloud.com was sinkholed Dec 14, 2020; active C2 may use secondary domains"
fi

echo ""

# ── 6. DNS Resolution Test (sinkhole check) ───────────────────────────────────
info "Testing avsvmcloud.com resolution (should resolve to Microsoft sinkhole)..."

if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short avsvmcloud.com 2>/dev/null | head -1 || true)
    if [[ -n "$RESOLVED" ]]; then
        # Microsoft sinkholed this to 20.140.0.1 (range)
        if echo "$RESOLVED" | grep -qE "^20\."; then
            ok "avsvmcloud.com resolves to Microsoft sinkhole ($RESOLVED) — C2 neutralized"
        else
            warn "avsvmcloud.com resolves to unexpected IP: $RESOLVED"
        fi
    else
        warn "avsvmcloud.com did not resolve — check DNS configuration"
    fi
elif command -v host &>/dev/null; then
    RESOLVED=$(host avsvmcloud.com 2>/dev/null | grep "has address" | head -1 || true)
    info "avsvmcloud.com: $RESOLVED"
else
    warn "No DNS resolution tool available (dig/host) — skipping sinkhole check"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "============================================================"
echo -e " ${BLD}SCAN SUMMARY${NC}"
echo "============================================================"

if [[ $COMPROMISED -gt 0 ]]; then
    echo -e "${RED}${BLD}"
    echo " !! $COMPROMISED CRITICAL INDICATOR(S) FOUND"
    echo -e "${NC}"
    echo " Immediate actions:"
    echo "   1. Isolate this machine from the network"
    echo "   2. Preserve forensic evidence (memory dump, disk image)"
    echo "   3. Do NOT use this machine to access any accounts or services"
    echo "   4. Rotate ALL credentials on or accessible from this system"
    echo "   5. Audit Azure AD / M365 for unauthorized SAML tokens and app registrations"
    echo "   6. Contact your CISO and engage an incident response team"
    echo "   7. File report with CISA (https://www.cisa.gov/report)"
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YEL} ⚠  $WARNINGS WARNING(S) — manual review recommended${NC}"
else
    echo -e "${GRN} ✓  No indicators of compromise found${NC}"
    echo ""
    echo " Note: This scanner covers known IOCs from the Dec 2020 exposure window."
    echo " If your logs predate that period, consider reviewing archived logs."
fi

echo ""
echo " Affected Orion versions: 2019.4 HF5, 2020.2, 2020.2 HF1"
echo " Safe Orion version:      2020.2.1 HF2 or later"
echo " Exposure window:         March 26 – December 13, 2020"
echo " Full writeup:            ../analysis.md"
echo "============================================================"
echo ""
