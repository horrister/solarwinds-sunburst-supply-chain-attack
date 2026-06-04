# 🔍 Vulnerability Research

A curated collection of in-depth vulnerability writeups covering real-world security incidents in the software ecosystem. Each entry includes a full technical analysis, proof-of-concept, IOC listing, and remediation guidance.

> **Purpose:** Educational reference and portfolio. All PoC code is for detection and research only.

---

## Index

| # | Vulnerability | Type | Severity | Date | Status |
|---|---------------|------|----------|------|--------|
| 002 | [SolarWinds Orion Vulnerability (CVE-2020-10148)](./../../../solarwinds-sunburst-supply-chain-attack/) | Supply Chain | 🔴 Critical | Dec 11, 2020 | 🚧 In Progress |

---

## Structure

Each entry follows a consistent format:

```
solarwinds-sunburst-supply-chain-attack/
├── README.md                     ← overview, quick detection, key facts table
├── analysis.md                   ← full writeup (8 attack stages, DLL analysis,
│                                    MITRE ATT&CK mapping, CVE-2020-10148 deep-dive,
│                                    obfuscation techniques, remediation)
├── references.md                 ← annotated sources organized by category
└── poc/
    ├── scan_orion.sh             ← Linux/macOS IOC scanner (DLL hash, DNS logs,
    │                                file artifacts, C2 connections, sinkhole check)
    ├── check_dll_hash.ps1        ← Windows PowerShell verifier (hash check,
    │                                TEARDROP artifacts, registry, event logs,
    │                                DNS cache — full scan via -ScanAll flag)
    ├── sunburst_dns_sim.py       ← Python demo of the DNS subdomain encoding
    │                                cipher (reverse-engineered from the DLL) with
    │                                encode/decode modes and full cipher visualization
    └── detect_golden_saml.md     ← Cloud pivot detection guide with KQL, PowerShell,
                                     and Splunk queries for ADFS/Azure AD forensics
```

## Methodology

The writeup covers:
- **Root cause** — what actually broke and how 
- **Attack timeline** — pre-staging, execution, discovery, remediation
- **Technical deep-dive** — deobfuscated payloads, attack chain, IOCs
- **PoC** — reproduction or detection scripts
- **Lessons learned** — systemic issues and mitigations

---

*Maintained by [@horrister](https://github.com/horrister)*
