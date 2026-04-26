<<<<<<< HEAD
# 🛡️ WebVulnScanner

> **A production-grade, modular web application vulnerability scanner that simulates real-world penetration testing workflows — covering OWASP Web Top 10 (2021), OWASP API Security Top 10 (2023), and OWASP AI/LLM Top 10 (2025).**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org)
[![CVSS](https://img.shields.io/badge/CVSS-v3.1-orange)](https://www.first.org/cvss/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Authorized Use Only](https://img.shields.io/badge/⚠️%20Authorized-Testing%20Only-yellow)]()

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [CVSS v3.1 Scoring](#cvss-v31-scoring)
- [Attack Chain Correlation](#attack-chain-correlation)
- [Report Output](#report-output)
- [Sample Output](#sample-output)
- [Future Improvements](#future-improvements)
- [Disclaimer](#disclaimer)

---

## Overview

WebVulnScanner is a Python-based penetration testing platform built for security professionals and researchers. It goes beyond basic vulnerability checkers by implementing real CVSS v3.1 base scoring on every finding (no hardcoded values), an attack chain correlation engine that links individual vulnerabilities into multi-step attack paths, a multi-threaded scanning engine that executes all modules in parallel, and professional HTML dashboards with JSON output for CI/CD integration.

---

## Features

**Vulnerability Coverage**
- OWASP Web Application Top 10 (2021): SQL Injection, XSS, Broken Access Control, Cryptographic Failures, Security Misconfiguration, Broken Authentication, SSRF, and Information Disclosure.
- OWASP API Security Top 10 (2023): BOLA, Broken Authentication, Rate Limiting absence, BFLA, CORS misconfiguration, exposed API documentation, and shadow API version detection.
- OWASP AI Security Top 10 (2025): Prompt Injection, Insecure Output Handling, Model DoS, AI Supply Chain exposure, Sensitive Information Disclosure, Insecure Plugin Design, and Model Theft.

**Platform Capabilities**
- Form-based and cookie/token authentication with automatic session maintenance.
- Configurable crawler with depth and page limits, scope enforcement, and form extraction.
- Central EndpointManager with deduplication, tagging, and filtered retrieval.
- Thread-safe ResultCollector with CVSS auto-scoring and duplicate suppression.
- Extensible attack chain engine — add new correlation rules without modifying engine code.
- Proxy support for routing traffic through Burp Suite or OWASP ZAP.
- CI/CD-friendly exit codes (exit 1 on Critical/High findings).

---

## Architecture

```
web-vuln-scanner/
│
├── main.py                      ← Master orchestrator (CLI entry point)
│
├── core/
│   ├── target.py                ← Target metadata and scope management
│   ├── crawler.py               ← Enhanced crawler + EndpointManager integration
│   ├── endpoint_manager.py      ← Thread-safe central endpoint registry
│   ├── scanner_engine.py        ← ThreadPoolExecutor-based module runner
│   ├── result_collector.py      ← Thread-safe finding aggregator + normaliser
│   ├── attack_chain.py          ← Vulnerability correlation engine (10 built-in rules)
│   ├── cvss.py                  ← Real CVSS v3.1 base score calculator
│   ├── report.py                ← Professional HTML + JSON report generator
│   ├── auth.py                  ← Form-based / cookie / token auth handler
│   └── utils.py                 ← HTTP session factory, URL helpers, timing
│
├── modules/                     ← Scanner modules (all preserved)
│   ├── scanner_base.py
│   ├── header_auditor.py
│   ├── info_disclosure.py
│   ├── sql_injection.py
│   ├── xss_scanner.py
│   ├── broken_access_control.py
│   ├── cryptographic_failures.py
│   ├── broken_auth_scanner.py
│   ├── ssrf_scanner.py
│   ├── api_scanner.py
│   ├── ai_scanner.py
│   ├── crawler.py
│   └── false_positive_filter.py
│
├── data/
│   ├── payloads.txt             ← Categorised injection payload library
│   └── wordlist.txt             ← Directory/endpoint discovery wordlist
│
├── reporter/                    ← Legacy reporters (preserved)
├── utils/                       ← Legacy utils (preserved)
├── tests/                       ← Test suite
├── config.yaml                  ← Default configuration
└── output/                      ← Generated reports (auto-created)
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/niteshghimire0147/web-vuln-scanner.git
cd web-vuln-scanner

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

**Requirement:** Python 3.10 or higher.
=======
# Web Application Vulnerability Scanner

[![CI](https://github.com/niteshghimire/web-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/niteshghimire/web-vuln-scanner/actions)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/Top10/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> OWASP Top 10 web application scanner. Crawls a target site and tests for SQL injection, reflected XSS, security header gaps, and sensitive file exposure. Outputs professional HTML/JSON/text reports.

---

## Highlights

- **SQL Injection** — error-based (20+ database error signatures) + time-based blind
- **Reflected XSS** — 8 payload variants, checks for unescaped reflection in responses
- **Security Headers** — 6 required headers (HSTS, CSP, X-Frame-Options, etc.) + 4 leaking headers
- **Information Disclosure** — 25 sensitive paths (`.env`, `.git`, `phpinfo.php`, Spring actuators)
- **Smart Crawler** — same-origin, form extraction, URL parameter discovery
- **HTML Reports** — self-contained with severity bar chart; JSON and text also available
- **Lab Demo** — included `docker-compose.yml` spins up DVWA for safe, legal testing

---

## Quick Start

```bash
pip install -r requirements.txt

# Test against DVWA (safe demo environment)
docker run -d -p 8080:80 vulnerables/web-dvwa
python main.py --url http://localhost:8080 --cookie "security=low; PHPSESSID=test" \
  --format html -o dvwa_scan -v
```
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a

---

## Usage

```bash
<<<<<<< HEAD
# Basic scan — all modules, HTML report
python main.py --url http://target.com -v

# Targeted module scan
python main.py --url http://target.com --modules sqli,xss,bac,ssrf

# API and AI security assessment
python main.py --url http://api.target.com --modules api,ai,auth,crypto --format all

# Authenticated scan (form login)
python main.py --url http://target.com \
               --login-url http://target.com/login \
               --username admin --password admin123 --format all

# Scan with session cookie
python main.py --url http://target.com \
               --cookie "PHPSESSID=abc123; security=low" --modules all

# Route through Burp Suite
python main.py --url http://target.com --proxy http://127.0.0.1:8080 --format all -v

# High-performance scan
python main.py --url http://target.com --threads 20 --depth 3 --max-pages 100
=======
python main.py --url <TARGET> [OPTIONS]

Options:
  --url, -u         Target URL (required)
  --modules         Comma-separated: headers,sqli,xss,info (default: all)
  --depth           Crawler depth (default: 2)
  --max-pages       Max pages to crawl (default: 50)
  --timeout         HTTP timeout in seconds (default: 10)
  --delay           Delay between requests (default: 0)
  --cookie          Session cookie (e.g. "PHPSESSID=abc; security=low")
  --header          Extra header: "Name: Value" (repeatable)
  -o, --output      Output base name
  --format          html / json / text / all (default: html)
  -v, --verbose     Show progress

Exit codes: 0 = no HIGH/CRITICAL, 1 = HIGH or CRITICAL found
```

**Examples:**

```bash
# Full scan with HTML report
python main.py -u http://testapp.local -o report --format all -v

# SQLi + XSS only, authenticated
python main.py -u http://app.com --modules sqli,xss --cookie "session=abc123"

# Deep crawl with rate limiting
python main.py -u http://app.com --depth 3 --max-pages 200 --delay 0.5
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
```

---

<<<<<<< HEAD
## Modules

| Module  | OWASP Reference    | Description                                                  |
|---------|--------------------|--------------------------------------------------------------|
| headers | A05:2021           | CSP, HSTS, X-Frame-Options, X-Content-Type-Options           |
| info    | A05:2021           | .env, .git, backups, stack traces, sensitive paths           |
| sqli    | A03:2021           | Error-based and time-based blind SQL injection               |
| xss     | A03:2021           | Reflected XSS in forms and URL parameters                    |
| bac     | A01:2021           | IDOR, path traversal, forced browsing, verb tampering        |
| crypto  | A02:2021           | HTTP transmission, cookie flags, HSTS, credential leakage    |
| auth    | A07:2021           | Default credentials, account lockout, JWT misconfiguration   |
| ssrf    | A10:2021           | Cloud metadata, loopback, and header-injection SSRF          |
| api     | API Top 10 (2023)  | BOLA, broken auth, rate limiting, CORS, shadow APIs          |
| ai      | AI Top 10 (2025)   | Prompt injection, output handling, model theft, supply chain |

---

## CVSS v3.1 Scoring

Every finding is automatically scored using the full CVSS v3.1 base formula. No values are hardcoded. The engine computes the Impact Sub-Score, Exploitability Sub-Score, and final Base Score according to the FIRST specification.

```
Finding : SQL Injection (unauthenticated, network-reachable)
Vector  : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score   : 10.0 — Critical
=======
## OWASP Coverage

| Module | OWASP Category | Checks |
|--------|---------------|--------|
| `headers` | A05:2021 Security Misconfiguration | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `sqli` | A03:2021 Injection | Error-based SQLi, Time-based blind SQLi (forms + URL params) |
| `xss` | A03:2021 Injection | Reflected XSS in form inputs and URL parameters |
| `info` | A05:2021 Security Misconfiguration | Sensitive files (.env, .git, phpinfo.php, actuators), verbose errors |

---

## Tech Stack

- **Python 3.9+**
- **requests** — HTTP client
- **beautifulsoup4** — HTML parsing and form extraction
- **colorama** — Colored terminal output

---

## Safe Demo Environment

```yaml
# examples/docker-compose.yml
# Starts DVWA + WebGoat for safe, legal scanner testing
docker compose -f examples/docker-compose.yml up -d
python main.py --url http://localhost:8080 --cookie "security=low; PHPSESSID=test" -v
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
```

---

<<<<<<< HEAD
## Attack Chain Correlation

The engine correlates individual findings into multi-step attack paths using a keyword-based rule registry. Ten rules are built in, and new ones can be added by appending a `ChainRule` to `core/attack_chain.py` without modifying any engine logic.

| Chain                                     | Risk     | Trigger Conditions                               |
|-------------------------------------------|----------|--------------------------------------------------|
| Session Hijacking via XSS                 | Critical | XSS + missing HttpOnly flag                      |
| Sensitive Data Exposure via IDOR          | Critical | IDOR + broken/missing authentication             |
| Cloud Credential Exposure via SSRF        | Critical | SSRF + cloud metadata endpoint access            |
| Authentication Bypass via SQLi            | Critical | SQL injection on a login endpoint                |
| Full Account Takeover via Broken Auth     | Critical | Broken auth + weak JWT / session tokens          |
| AI Prompt Injection → Data Exfiltration   | Critical | Prompt injection + sensitive info disclosure     |
| Stored XSS → Malware Distribution        | High     | XSS + missing Content-Security-Policy            |
| Path Traversal → RCE                     | Critical | Path traversal + writable upload / log poisoning |
| API Key Leakage → Service Compromise     | High     | Exposed credential + unauthenticated API         |
| Insecure Crypto + Data Transmission Risk  | High     | HTTP transmission + missing Secure cookie flag   |

---

## Report Output

The HTML report is a self-contained, single-file dark-theme dashboard with a KPI hero row, severity distribution bar chart, collapsible attack chain explorer, filterable finding cards with full CVSS vectors, and a deduplicated recommendations section.

The JSON report provides structured output suitable for SIEM ingestion, CI/CD pipeline integration, or custom dashboard consumption. The exit code is 1 on Critical or High findings and 0 otherwise, enabling automated gate-keeping in pipelines.

---

## Sample Output

```
  ╔════════════════════════════════════════════════════════════════════╗
  ║   Web Application Vulnerability Scanner  v2.0.0                  ║
  ║   OWASP Web Top 10 · API Top 10 · AI Top 10 · CVSS v3.1         ║
  ╚════════════════════════════════════════════════════════════════════╝

[*] Target  : http://dvwa.local
[*] Modules : all (10 modules)
[*] Threads : 10

[*] Phase 1/4 — Crawling target...
[+] Discovered 23 endpoints (5 forms, 2 API, 14 with params)

[*] Phase 2/4 — Scanning (10 threads)...
[+] Scanner complete — 18 raw findings

[*] Phase 3/4 — Correlating attack chains...
[+] Identified 4 attack chain(s)

[*] Phase 4/4 — Generating reports...
[+] HTML report : output/scan_dvwa.local_20260426_143021.html
[+] JSON report : output/scan_dvwa.local_20260426_143021.json

================================================================
  Scan Complete  |  47.3s  |  18 findings  |  4 chains
================================================================
  CRITICAL        3
  HIGH            6
  MEDIUM          5
  LOW             2
  INFORMATIONAL   2
================================================================
```

---

## Future Improvements

- JavaScript-rendered SPA support via Playwright or Selenium for authenticated crawling of React/Vue applications.
- SARIF output format for native GitHub Code Scanning and Azure DevOps integration.
- YAML-defined custom scan rules without requiring Python coding.
- Continuous scanning mode with delta reporting (new findings only since last scan).
- GraphQL introspection module for schema analysis and field-level injection testing.
- Subdomain enumeration to expand scope discovery before endpoint crawling.
- Burp Suite extension for consuming scan results inside existing pentesting workflows.

---

## Disclaimer

**AUTHORIZED TESTING ONLY.** This tool is designed for use by security professionals on systems they own or have explicit written permission to test. Unauthorized use against systems you do not own or have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Author

**Nitesh Ghimire** — Security Researcher  
GitHub: [@niteshghimire0147](https://github.com/niteshghimire0147)

---

*Built for the security community. Always hack ethically.*
=======
## Legal

For authorized security testing only. See [DISCLAIMER.md](DISCLAIMER.md).
Licensed under [MIT](LICENSE).

---

## Who This Tool Is For

Penetration testers running web application assessments against DVWA, HackTheBox, or real client targets. Useful for bug bounty hunters who want automated discovery of SQLi and XSS entry points before manual exploitation. Also useful for developers running security regression tests against their own applications.

## Real-World Use Case

During a web application pentest, point this scanner at the authenticated DVWA instance (pass the session cookie with `--cookie`) to crawl all forms and URL parameters, then run SQLi and XSS modules across them. The HTML report with MITRE ATT&CK context goes into the client deliverable. The false-positive filter (`modules/false_positive_filter.py`) runs automatically to remove coincidental SQL keyword matches before findings reach the report.

## MITRE ATT&CK Mapping

| Vulnerability | Technique | Tactic |
|---------------|-----------|--------|
| SQL Injection | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access |
| XSS | [T1059.007 — JavaScript](https://attack.mitre.org/techniques/T1059/) | Execution |
| Info Disclosure | [T1592.002 — Software](https://attack.mitre.org/techniques/T1592/) | Reconnaissance |
| Path Traversal | [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | Discovery |
| Missing Headers | [T1592 — Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/) | Reconnaissance |

## Limitations

- **Error-based SQLi only** — does not detect blind/time-based injection without a baseline response comparison.
- **Crawl depth** is limited; single-page apps (React/Vue/Angular) require manual form submission.
- **XSS detection** confirms reflection but cannot execute JavaScript to confirm DOM-based sinks.
- **Authenticated scanning** requires manually passing a valid session cookie — no login automation.
- **No CSRF testing** — out of scope for this scanner.

## Interview Talking Points

**"How does your false-positive filter work?"**
> For SQLi, I require a recognisable database error signature in the response — Oracle's `ORA-` prefix, MySQL's syntax error string, PostgreSQL's `pg_query()`. If the response has a generic "internal server error" that also appears in the baseline, it's filtered out. For XSS, I check that the payload appears *unencoded* in the response — if the app HTML-encodes `<script>` to `&lt;script&gt;`, that's not exploitable, so the finding is suppressed. This cuts my false-positive rate significantly before findings reach the client report.

**"What's the difference between reflected and stored XSS, and does your scanner detect both?"**
> Reflected XSS: payload is injected in a request and immediately reflected in the response — detectable with one request/response cycle, which is what my scanner does. Stored XSS: payload is persisted server-side and rendered later to a different user — requires two steps (submit then retrieve) and is much harder to automate safely without risking persistence on production systems. My scanner detects reflected XSS only.
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
