# 🔍 Vulnerability Research

A curated collection of in-depth vulnerability writeups covering real-world security incidents in the software ecosystem. Each entry includes a full technical analysis, proof-of-concept, IOC listing, and remediation guidance.

> **Purpose:** Educational reference and portfolio. All PoC code is for detection and research only.

---

## Index

| # | Vulnerability | Type | Severity | Date | Status |
|---|---------------|------|----------|------|--------|
| 001 | [SolarWinds Orion Vulnerability (CVE-2020-10148))](./../../../solarwinds-sunburst-supply-chain-attack/) | Supply Chain | 🔴 Critical | Dec 11, 2020 | 🚧 In Progress |

---

## Structure

Each entry follows a consistent format:

```
/solarwinds-sunburst-supply-chain-attack/
├── poc/               # Detection & PoC scripts
├── README.md          # Project overview
├── analysis.md        # Full writeup
└── references.md      # Cited sources
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
