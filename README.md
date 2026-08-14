# SOC Automation Toolkit

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-45%2F45%20passing-brightgreen)](https://github.com/yourusername/soc-automation-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Automate Tier-1 SOC analyst workflows** — IOC enrichment, log triage, and phishing analysis in a single, extensible Python CLI.

Built for SOC analysts who are tired of manual pivoting between VirusTotal, AbuseIPDB, and OTX. This toolkit consolidates threat intelligence queries, parses Windows Event Logs and Apache access logs for anomalies, and extracts phishing indicators from `.eml` files — all with weighted risk scoring and structured JSON output.

---

## Why This Exists

In a modern SOC, Tier-1 analysts spend **60-70% of their time** on repetitive tasks:
- Copy-pasting IPs into 3 different threat intel portals
- Scrolling through thousands of log lines to find the needle
- Manually inspecting suspicious emails for phishing indicators

This toolkit automates all three workflows with a unified CLI, composite risk scoring, and anomaly detection — so analysts can focus on actual incident response.

---

## Features

### 1. IOC Enricher (`ioc-enrich`)
Queries **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX** simultaneously.

- Supports **IPv4/IPv6**, **MD5/SHA1/SHA256 hashes**, and **domains**
- **Weighted composite risk score**: VT (40%) + AbuseIPDB (30%) + OTX (30%)
- Automatic IOC classification with regex + `ipaddress` validation
- Graceful degradation: if one API fails, the others still contribute
- Batch enrichment from file

```bash
py -m src.cli ioc-enrich 8.8.8.8
py -m src.cli ioc-enrich malicious.com --format table
py -m src.cli ioc-enrich-batch iocs.txt -o report.json
```

### 2. Log Triage Engine (`log-triage`)
Parses **Apache/Nginx** and **Windows Event Logs** with pattern-based anomaly detection.

**Apache anomalies detected:**
- 404 spikes (potential scanning / enumeration)
- Rapid 404s from single source IP (confirmed scanning)
- Server error (5xx) spikes
- Suspicious user agents (sqlmap, nikto, nmap, curl, etc.)

**Windows Event anomalies detected:**
- Brute force attempts (Event ID 4625 clusters in time windows)
- Account lockouts (Event ID 4740)
- Privilege escalation attempts (Event ID 4673/4674)

```bash
py -m src.cli log-triage /var/log/apache2/access.log --type apache
py -m src.cli log-triage security.evtx --type windows
```

### 3. Phishing Analyzer (`phishing-analyze`)
Extracts and analyzes URLs from `.eml` files with **heuristic + API-based** detection.

**Heuristic indicators:**
- Reply-To / From header mismatch (spoofing)
- Suspicious TLDs (`.xyz`, `.tk`, `.top`, etc.)
- IP-based URLs
- URL shorteners (bit.ly, tinyurl, etc.)
- Suspicious subject keywords ("urgent", "verify", "suspend")
- HTML-only emails (no plain text alternative)

**API checks:** URLhaus + PhishTank

```bash
py -m src.cli phishing-analyze suspicious_email.eml
```

---

## Architecture

```
soc-automation-toolkit/
├── src/
│   ├── cli.py                 # Click-based CLI entrypoint
│   ├── ioc_enricher.py        # Multi-source TI enrichment
│   ├── log_triage.py          # Log parsing + anomaly engine
│   └── phishing_analyzer.py   # EML parsing + URL analysis
├── tests/
│   ├── test_ioc_enricher.py   # 16 tests
│   ├── test_log_triage.py     # 13 tests
│   └── test_phishing_analyzer.py  # 16 tests
├── sample_logs/
│   ├── apache_access.log      # Demo with scanning + sqlmap
│   ├── windows_security.log   # Demo with brute force
│   └── sample.eml             # Demo phishing email
├── config.yaml                # API keys & thresholds
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- API keys for [VirusTotal](https://www.virustotal.com/gui/join-us), [AbuseIPDB](https://www.abuseipdb.com/register), [AlienVault OTX](https://otx.alienvault.com/)

### Installation

```bash
git clone https://github.com/yourusername/soc-automation-toolkit.git
cd soc-automation-toolkit
pip install -r requirements.txt
```

### Configuration

Edit `config.yaml` with your API keys:

```yaml
apis:
  virustotal:
    api_key: "YOUR_VIRUSTOTAL_API_KEY"
  abuseipdb:
    api_key: "YOUR_ABUSEIPDB_API_KEY"
  alienvault_otx:
    api_key: "YOUR_OTX_API_KEY"
```

### Run Tests

```bash
pytest tests/ -v
```

**Result:** 45/45 tests passing

### Usage Examples

**Enrich an IP:**
```bash
py -m src.cli ioc-enrich 8.8.8.8
# Output: JSON with VT reputation, AbuseIPDB confidence, OTX pulses
```

**Analyze Apache logs:**
```bash
py -m src.cli log-triage sample_logs/apache_access.log --type apache
# Output: 4 anomalies detected (scanning, server errors, sqlmap, curl)
```

**Analyze a phishing email:**
```bash
py -m src.cli phishing-analyze sample_logs/sample.eml
# Output: SUSPICIOUS (50/100) — Reply-To mismatch, suspicious TLD, IP URL, shortener
```

---

## Risk Scoring Methodology

| Source | Weight | Metric |
|--------|--------|--------|
| VirusTotal | 40% | `(malicious + suspicious) / total_vendors * 100` |
| AbuseIPDB | 30% | `abuseConfidencePercentage` |
| AlienVault OTX | 30% | Pulse count tiered scoring (0→25→50→75→100) |

**Thresholds:**
- `0-24` → LOW
- `25-49` → MEDIUM
- `50-74` → HIGH
- `75-100` → CRITICAL

---

## Sample Output

### IOC Enrichment (8.8.8.8)
```json
{
  "ioc": "8.8.8.8",
  "ioc_type": "ip",
  "risk_score": 0.0,
  "risk_level": "low",
  "sources": {
    "virustotal": { "malicious_votes": 0, "harmless_votes": 53, "reputation": 556 },
    "abuseipdb": { "abuse_confidence_score": 0, "total_reports": 187, "isp": "Google LLC" },
    "alienvault_otx": { "pulse_count": 0 }
  }
}
```

### Log Triage (Apache)
```
Summary: 32 events, 4 anomalies detected
  [!] HIGH: Possible scanning activity from 10.0.0.50
  [!] MEDIUM: Server error spike: 11 5xx responses
  [!] HIGH: Suspicious user agent pattern 'sqlmap' detected
  [!] HIGH: Suspicious user agent pattern 'curl' detected
```

### Phishing Analysis
```
Verdict: SUSPICIOUS (Risk Score: 50.0/100)
URLs Found: 3
Indicators:
  - Reply-To mismatch
  - Suspicious TLD in URL
  - IP-based URL detected
  - URL shortener detected
  - Suspicious keyword in subject: 'urgent'
```

---

## Tech Stack

- **Python 3.10+** with type hints and dataclasses
- **Click** for CLI interface
- **PyYAML** for configuration management
- **Requests** with retry logic and timeout handling
- **pytest** + **pytest-cov** for unit testing
- **responses** for HTTP mocking in tests

---

## Roadmap

- [ ] Add MISP integration for IOC enrichment
- [ ] Support Syslog and JSON-formatted logs
- [ ] Add YARA rule scanning for file hashes
- [ ] Build Tines/Splunk SOAR connector
- [ ] Add PDF/HTML report generation
<img width="1536" height="1024" alt="Soc Automation toolkit" src="https://github.com/user-attachments/assets/43860da4-110d-4c0b-a4c1-aaf6aef5c7e1" />

---

## 👤 Alisha Sh

🎯 SOC Analyst | Detection Engineering | Threat Intelligence | NIS2 Compliance

Building defensive capabilities for the NIS2 era. Passionate about blue-team operations, detection engineering, and making security operations measurable and repeatable.

- 🐙 **GitHub:** [github.com/Alisha-sh-dev](https://github.com/Alisha-sh-dev)
- 💼 **LinkedIn:** [linkedin.com/in/alisha-sh/](https://www.linkedin.com/in/alisha-sh/)
- 🌍 **Location:** Open to SOC roles in Germany (Berlin, Frankfurt, Munich, Remote)
- 🗣️ **Languages:** English (C1) | German (B2)

---

<div align="center">

  <sub>Built with 💙 and caffeine. One log at a time.</sub>
  <br>
  <sub>⭐ If this project helped you, consider starring it!</sub>

</div>
---

## License

MIT License — see [LICENSE](LICENSE) for details.
