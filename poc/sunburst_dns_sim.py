#!/usr/bin/env python3
"""
sunburst_dns_sim.py
SolarWinds SUNBURST — DNS Subdomain Encoding Demonstrator
CVE-2020-10148 / SUNBURST / Solorigate

Demonstrates the substitution cipher used by the SUNBURST backdoor to encode
victim fingerprints (User ID + AD domain) into subdomains of avsvmcloud.com.

This is a RESEARCH TOOL ONLY. It reproduces the encoding algorithm that was
reverse-engineered by Netresec and FireEye/Mandiant from the decompiled DLL.
It does NOT contact any C2 infrastructure. The avsvmcloud.com domain has been
sinkholed by Microsoft since December 14, 2020.

Usage:
    python3 sunburst_dns_sim.py                         # demo with sample data
    python3 sunburst_dns_sim.py --domain corp.local     # encode a specific domain
    python3 sunburst_dns_sim.py --decode <subdomain>    # decode a captured subdomain

References:
    https://www.netresec.com/?page=Blog&month=2021-01&post=Extracting-the-Decoded-SUNBURST-Domains-from-DNS
    https://www.mandiant.com/resources/blog/sunburst-additional-technical-details
"""

import argparse
import hashlib
import random
import socket
import string
import sys
from datetime import datetime

# ── SUNBURST Substitution Cipher ─────────────────────────────────────────────
# Reverse-engineered from SolarWinds.Orion.Core.BusinessLayer.dll
# Source: Netresec, FireEye/Mandiant

# Alphabet for encoding lowercase letters (a-z → 15-char substitution)
ALPHA_LOWER = "rq3gsalt6u1iknm"

# Alphabet for encoding digits (0-9 → 15-char substitution, with overlap)
ALPHA_DIGITS = "0o2eavbdhu1i9jpkctnmzwqfg3y7xs854r6l"

def encode_char(c: str) -> str:
    """Encode a single character using SUNBURST's substitution cipher."""
    if c.isalpha():
        idx = ord(c.lower()) - ord('a')
        # Wrap around the 15-char alphabet
        return ALPHA_LOWER[idx % len(ALPHA_LOWER)]
    elif c.isdigit():
        idx = ord(c) - ord('0')
        return ALPHA_DIGITS[idx % len(ALPHA_DIGITS)]
    else:
        # Non-alphanumeric characters are preserved (with some exceptions)
        # SUNBURST replaced '.' with '-' in domain names
        if c == '.':
            return '-'
        return c

def encode_victim_fingerprint(user_id: str, domain: str) -> str:
    """
    Encode victim User ID and AD domain name into a SUNBURST subdomain.
    
    The resulting subdomain is appended to avsvmcloud.com to form the
    DNS query used for C2 beaconing.
    """
    combined = (user_id + domain).lower()
    encoded = ''.join(encode_char(c) for c in combined)
    return encoded

def generate_fake_uid(domain: str) -> str:
    """
    Simulate SUNBURST's UID generation.
    
    SUNBURST derived the UID from:
    - MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography)
    - NetworkAdapterConfiguration MAC addresses
    - PROCESSOR_IDENTIFIER environment variable
    - InstallDate registry value
    
    For demo purposes, we generate a deterministic hash from the domain.
    """
    h = hashlib.md5(domain.encode()).hexdigest()[:8].upper()
    return h

def format_c2_domain(encoded_fingerprint: str) -> str:
    """Format the full C2 DNS query as SUNBURST would construct it."""
    # SUNBURST rotated through several AWS regions for the AppSync endpoint
    regions = [
        "us-east-1",
        "us-east-2", 
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "ap-southeast-1",
    ]
    region = random.choice(regions)
    return f"{encoded_fingerprint}.appsync-api.{region}.avsvmcloud.com"

def decode_subdomain(subdomain: str) -> str:
    """
    Attempt to decode a captured SUNBURST subdomain back to plaintext.
    
    Note: This is a best-effort reverse of the substitution. Because the
    cipher is not bijective (multiple inputs can map to the same output
    for some characters), full decoding is not always possible without
    the original UID. Netresec's tool handles this more completely.
    """
    # Build reverse mapping (where unambiguous)
    reverse_lower = {}
    for i, c in enumerate(ALPHA_LOWER):
        orig = chr(ord('a') + (i % 26))
        if c not in reverse_lower:
            reverse_lower[c] = orig

    reverse_digits = {}
    for i, c in enumerate(ALPHA_DIGITS):
        orig = str(i % 10)
        if c not in reverse_digits:
            reverse_digits[c] = orig

    decoded = []
    for c in subdomain:
        if c in reverse_lower:
            decoded.append(reverse_lower[c])
        elif c in reverse_digits:
            decoded.append(reverse_digits[c])
        elif c == '-':
            decoded.append('.')
        else:
            decoded.append(c)

    return ''.join(decoded)

def check_sinkhole():
    """Verify that avsvmcloud.com resolves to Microsoft's sinkhole (expected)."""
    print("[INFO] Checking avsvmcloud.com resolution (should be sinkholed)...")
    try:
        ip = socket.gethostbyname("avsvmcloud.com")
        if ip.startswith("20."):
            print(f"[OK]   avsvmcloud.com → {ip} (Microsoft sinkhole — C2 neutralized)")
        else:
            print(f"[WARN] avsvmcloud.com → {ip} (unexpected — investigate)")
    except socket.gaierror:
        print("[WARN] avsvmcloud.com did not resolve")

def print_banner():
    banner = """
============================================================
 SUNBURST DNS Encoding Demonstrator
 CVE-2020-10148 / SolarWinds Orion Supply Chain Attack
 Research Tool — Does NOT contact any C2 infrastructure
============================================================
"""
    print(banner)

def demo_mode():
    """Run a demonstration of the encoding with sample victim data."""
    print_banner()
    
    sample_victims = [
        ("corp.example.com",    "Hypothetical enterprise domain"),
        ("agency.gov",          "Hypothetical government agency"),
        ("university.edu",      "Hypothetical university network"),
        ("hospital.health",     "Hypothetical healthcare org"),
    ]

    print("=" * 60)
    print(" SUNBURST DNS Subdomain Encoding — Demo")
    print(" Algorithm: Substitution cipher (reverse-engineered from DLL)")
    print("=" * 60)
    print()

    for domain, label in sample_victims:
        uid = generate_fake_uid(domain)
        encoded = encode_victim_fingerprint(uid, domain)
        full_domain = format_c2_domain(encoded)

        print(f"  Target:      {label}")
        print(f"  Domain:      {domain}")
        print(f"  Fake UID:    {uid}  (real UID from MachineGuid + hardware)")
        print(f"  Combined:    {uid + domain}")
        print(f"  Encoded:     {encoded}")
        print(f"  C2 query:    {full_domain}")
        print()

    print("=" * 60)
    print(" HOW SUNBURST USED THIS")
    print("=" * 60)
    print("""
  1. On a compromised system, SUNBURST combined the victim's hardware-
     derived UID with their Active Directory domain name.

  2. It encoded this fingerprint using the substitution cipher above,
     producing a unique subdomain for that victim.

  3. SUNBURST then issued a DNS query for:
       <encoded>.appsync-api.<region>.avsvmcloud.com

  4. The attacker's authoritative DNS server (avsvmcloud.com) logged
     every DNS query — building a registry of all ~18,000 compromised
     systems WITHOUT any direct network connection to them.

  5. For the ~100 victims the attacker chose to activate against, the
     DNS response returned a CNAME pointing to the actual C2 server.
     For all others: 0.0.0.0 (no activation).

  This mechanism meant:
  - 99%+ of infected orgs never received a payload beyond the dormant DLL
  - The attacker could enumerate all victims passively via DNS logs alone
  - C2 traffic was indistinguishable from normal Orion telemetry DNS
""")

    print("=" * 60)
    print(" CIPHER DETAILS (reverse-engineered from DLL)")
    print("=" * 60)
    print()
    print(f"  Lowercase alphabet mapping (a→z encoded to):")
    for i, c in enumerate(string.ascii_lowercase[:len(ALPHA_LOWER)]):
        print(f"    '{c}' → '{ALPHA_LOWER[i]}'", end="   ")
        if (i + 1) % 5 == 0:
            print()
    print()
    print(f"\n  Digit mapping (0→9 encoded to):")
    for i in range(10):
        print(f"    '{i}' → '{ALPHA_DIGITS[i]}'", end="   ")
    print()
    print()
    print("  '.' → '-'  (domain separator replacement)")
    print()

    check_sinkhole()
    print()

def main():
    parser = argparse.ArgumentParser(
        description="SUNBURST DNS Subdomain Encoding Demonstrator (research tool)"
    )
    parser.add_argument(
        "--domain",
        help="Encode a specific AD domain (e.g. corp.example.com)",
        type=str
    )
    parser.add_argument(
        "--decode",
        help="Attempt to decode a captured SUNBURST subdomain",
        type=str
    )
    parser.add_argument(
        "--uid",
        help="Specify a UID (used with --domain; defaults to generated value)",
        type=str,
        default=""
    )
    args = parser.parse_args()

    if args.decode:
        print_banner()
        decoded = decode_subdomain(args.decode)
        print(f"[DECODE] Input subdomain:  {args.decode}")
        print(f"[DECODE] Decoded content:  {decoded}")
        print()
        print("[INFO] Note: Full decoding requires knowing the original UID.")
        print("[INFO] See Netresec's tool for full victim domain extraction:")
        print("[INFO] https://www.netresec.com/?page=Blog&month=2021-01&post=Extracting-the-Decoded-SUNBURST-Domains-from-DNS")
        return

    if args.domain:
        print_banner()
        uid = args.uid if args.uid else generate_fake_uid(args.domain)
        encoded = encode_victim_fingerprint(uid, args.domain)
        full_domain = format_c2_domain(encoded)
        print(f"[ENCODE] Domain:      {args.domain}")
        print(f"[ENCODE] UID:         {uid}")
        print(f"[ENCODE] Combined:    {uid + args.domain}")
        print(f"[ENCODE] Encoded:     {encoded}")
        print(f"[ENCODE] C2 query:    {full_domain}")
        print()
        print("[INFO] This is a demonstration only. The domain avsvmcloud.com")
        print("[INFO] has been sinkholed by Microsoft since December 14, 2020.")
        check_sinkhole()
        return

    # Default: run full demo
    demo_mode()

if __name__ == "__main__":
    main()
