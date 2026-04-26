# 🛡️ Web Vulnerability Scanner v2.0.0

> **A modular, CI-ready Web + API + AI Security Testing Framework built for modern penetration testing and DevSecOps pipelines.**

[![CI](https://github.com/niteshghimire0147/web-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/niteshghimire0147/web-vuln-scanner/actions)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20%7C%20API%20%7C%20AI-red)](https://owasp.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-orange)](https://attack.mitre.org)
[![Tests](https://img.shields.io/badge/Tests-65%2F65%20Passing-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-yellow)]()

---

## ⚡ Key Capabilities

| | Capability |
|---|---|
| 🔍 | Web Vulnerability Scanning — OWASP Top 10 (2021) |
| 🌐 | API Security Testing — OWASP API Top 10 (2023) |
| 🤖 | AI / LLM Security Testing — OWASP AI Top 10 (2025) |
| 🧠 | Attack Chain Correlation Engine |
| 📊 | CVSS v3.1 Severity Scoring — per finding, automatically applied |
| ⚡ | Multi-threaded Scanning Engine — ThreadPoolExecutor |
| 🧾 | HTML Report (always) + optional JSON / Markdown output |
| 🔐 | CI/CD Security Gate Support — configurable exit code threshold |

---

## Table of Contents

- [Why This Project Matters](#why-this-project-matters)
- [Attack Chain Intelligence](#-attack-chain-intelligence)
- [Security Coverage Matrix](#security-coverage-matrix)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Security Methodology](#security-methodology)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Usage](#usage)
- [CI/CD Integration](#cicd-integration)
- [Scanner Modules](#scanner-modules)
- [Payload System](#payload-system)
- [False-Positive Filtering](#false-positive-filtering)
- [Report Output](#report-output)
- [Testing](#-testing)
- [Safe Testing Environment](#safe-testing-environment)
- [Tech Stack](#tech-stack)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Key Highlights](#-key-highlights)
- [Disclaimer](#disclaimer)

---

## Why This Project Matters

### The Attacker's Perspective

Real-world intrusions rarely exploit a single vulnerability in isolation. Attackers chain discoveries: an exposed `.git/config` leaks credentials, which enables authenticated access to an admin endpoint with broken authorization, which exposes a SQL injection vector. Scanners that report individual findings without modeling these relationships underrepresent actual organizational risk.

This tool is built around **attack chain correlation** — it identifies how vulnerabilities compound, not just that they exist. Every finding is cross-referenced against adjacent findings to surface exploitable paths that a flat, line-item report would miss.

### Why CVSS v3.1 Scoring

[CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) provides a vendor-neutral, standardized severity score (0.0–10.0) derived from attack vector, complexity, privileges required, user interaction, and impact scope. Severity labels alone (High/Medium/Low) are insufficient for prioritization across heterogeneous findings. CVSS scores enable:

- Consistent severity comparison across vulnerability classes
- Risk-based remediation prioritization
- Alignment with industry-standard vulnerability databases (NVD, CVE)
- CI/CD gate logic based on numeric thresholds

### Why Attack Chains Matter

Vulnerability correlation transforms isolated findings into actionable threat models. An information disclosure finding (CVSS 5.3) combined with an authentication bypass (CVSS 7.5) may collectively enable full account takeover — a combined risk profile that neither finding expresses alone. The `core/attack_chain.py` engine models these relationships explicitly.

---

## 🔥 Attack Chain Intelligence

Traditional scanners report vulnerabilities in isolation. This framework correlates findings into **multi-step attack chains** that reflect how real adversaries operate.

### Attack Chain Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ADVERSARY ENTRY POINTS                               │
├──────────────┬──────────────────┬──────────────────┬────────────────────────┤
│  Info Leak   │   SQL Injection  │   XSS / CSRF     │   API / SSRF           │
│  A05:2021    │   A03:2021       │   A03:2021        │   A10:2021             │
└──────┬───────┴────────┬─────────┴────────┬──────────┴──────────┬────────────┘
       │                │                  │                     │
       ▼                ▼                  ▼                     ▼
┌──────────────┐ ┌─────────────┐ ┌────────────────┐ ┌───────────────────────┐
│ .git exposed │ │ DB dump /   │ │ Session cookie │ │ Cloud metadata fetch  │
│ .env leaked  │ │ auth bypass │ │ theft via JS   │ │ 169.254.169.254       │
│ stack trace  │ │ UNION SELECT│ │ DOM injection  │ │ Internal port scan    │
└──────┬───────┘ └──────┬──────┘ └───────┬────────┘ └──────────┬────────────┘
       │                │                │                      │
       └────────┬───────┘                └──────────┬───────────┘
                │                                   │
                ▼                                   ▼
     ┌──────────────────────┐           ┌───────────────────────┐
     │  CREDENTIAL ACCESS   │           │   SESSION HIJACKING   │
     │  T1110 · A07:2021    │           │   T1539 · A07:2021    │
     │  Default creds       │           │   Cookie theft        │
     │  JWT alg confusion   │           │   Token replay        │
     └──────────┬───────────┘           └──────────┬────────────┘
                │                                   │
                └──────────────┬────────────────────┘
                               │
                               ▼
                  ┌────────────────────────┐
                  │   PRIVILEGE ESCALATION │
                  │   T1078 · A01:2021     │
                  │   IDOR · Forced Browse │
                  │   Verb Tampering       │
                  └────────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
     ┌──────────────┐ ┌──────────────┐ ┌────────────────┐
     │  DATA THEFT  │ │   LATERAL    │ │  PERSISTENCE   │
     │  T1041       │ │   MOVEMENT   │ │  T1505         │
     │  PII · Keys  │ │  API abuse   │ │  Backdoor user │
     │  DB records  │ │  BOLA chain  │ │  Token plant   │
     └──────────────┘ └──────────────┘ └────────────────┘
```

### Chain Examples — Modeled by the Engine

```
[INFO DISCLOSURE]──────► [BROKEN AUTH]──────────────► [ACCOUNT TAKEOVER]
  .env exposes JWT          Weak secret cracks token      Full admin access

[SQL INJECTION]────────► [AUTH BYPASS]──────────────► [DATA EXFILTRATION]
  UNION SELECT leaks        Password hash exposed          DB dump via API

[XSS]──────────────────► [SESSION HIJACK]────────────► [PRIVILEGE ESCALATION]
  Payload reflected         Cookie stolen via JS           IDOR to admin panel

[SSRF]─────────────────► [CLOUD METADATA]────────────► [CREDENTIAL LEAKAGE]
  URL param injected        AWS IMDSv1 reached             IAM keys extracted

[API MISCONFIGURATION]─► [BOLA]──────────────────────► [UNAUTHORIZED EXFIL]
  No rate limit / auth      Object ID enumerated           All user records dumped

[PROMPT INJECTION]─────► [LLM OUTPUT ABUSE]──────────► [DATA LEAKAGE via AI]
  Instruction override      Unsafe content rendered        Sensitive data in reply
```

**MITRE ATT&CK adversary movement modeled:**
```
Reconnaissance ──► Initial Access ──► Execution ──► Privilege Escalation ──► Exfiltration
   T1592               T1190            T1059             T1078                  T1041
```

Each chain is mapped to MITRE ATT&CK tactics and OWASP categories. The `core/attack_chain.py` engine evaluates all findings against a rule registry at scan completion — a new correlation rule requires only a single `ChainRule` entry, no code changes.

---

## Security Coverage Matrix

### OWASP Web Application Top 10 (2021)

| Module | OWASP Category | Detection Technique |
|---|---|---|
| `bac` | A01: Broken Access Control | IDOR, path traversal, forced browsing, HTTP verb tampering |
| `crypto` | A02: Cryptographic Failures | HTTP usage, insecure cookies, missing HSTS, credential leakage |
| `sqli` | A03: Injection | Error-based SQLi, time-based blind SQLi, DB fingerprinting |
| `xss` | A03: Injection | Reflected XSS, payload injection, reflection validation |
| `insecure-design` | A04: Insecure Design | Business logic abuse, missing workflow validation |
| `headers` | A05: Security Misconfiguration | Missing security headers (CSP, HSTS, X-Frame-Options, XCTO) |
| `vuln-components` | A06: Vulnerable Components | Outdated libraries, exposed version fingerprints |
| `auth` | A07: Identification & Authentication Failures | Default credentials, JWT misconfiguration, weak sessions |
| `integrity` | A08: Software & Data Integrity Failures | Unsafe updates, untrusted input flows |
| `logging` | A09: Security Logging & Monitoring Failures | Missing logs, verbose error exposure |
| `ssrf` | A10: Server-Side Request Forgery | Cloud metadata abuse, loopback, URL injection |

---

### OWASP API Security Top 10 (2023)

| API Risk | Detection Technique |
|---|---|
| API1: BOLA | Object ID manipulation, unauthorized access validation |
| API2: Broken Authentication | Token bypass, session validation failure |
| API3: Broken Object Property Level Authorization | Excessive data exposure in JSON responses |
| API4: Unrestricted Resource Consumption | Rate limit bypass, request flooding |
| API5: Broken Function Level Authorization | Unauthorized endpoint method access |
| API6: Unrestricted Access to Business Flows | Workflow abuse simulation |
| API7: SSRF | Internal endpoint probing, metadata access |
| API8: Security Misconfiguration | CORS misconfig, debug exposure |
| API9: Improper Inventory Management | Shadow / deprecated API discovery |
| API10: Unsafe API Consumption | Untrusted external API usage detection |

---

### OWASP AI Security Top 10 (2025)

| AI Risk | Detection Technique |
|---|---|
| LLM01: Prompt Injection | Jailbreak attempts, instruction override payloads |
| LLM02: Insecure Output Handling | XSS/SSTI payloads in model output |
| LLM03: Training Data Poisoning | Malicious pattern injection detection |
| LLM04: Model Denial of Service | Token flooding, resource exhaustion |
| LLM05: Supply Chain Vulnerabilities | Unsafe model/API dependencies |
| LLM06: Sensitive Information Disclosure | Prompt-based data leakage attempts |
| LLM07: Insecure Plugin Design | Plugin/tool execution abuse |
| LLM08: Excessive Agency | Over-permissioned AI actions |
| LLM09: Overreliance | Lack of validation of AI output |
| LLM10: Model Theft | Extraction attempts / model probing |

---

## MITRE ATT&CK Mapping

| Vulnerability | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| SQL Injection | T1190 | Exploit Public-Facing Application | Initial Access |
| XSS | T1059.007 | JavaScript Execution | Execution |
| SSRF | T1190 | Exploit Public-Facing Application | Initial Access |
| Path Traversal | T1083 | File and Directory Discovery | Discovery |
| Information Disclosure | T1592 | Gather Victim Host Information | Reconnaissance |
| Credential Attack | T1110 | Brute Force | Credential Access |
| API Abuse | T1071 | Application Layer Protocol Abuse | Command & Control |
| Prompt Injection | T1059 | Command and Scripting Abuse | Execution |

---

## Security Methodology

### Scan Phase Architecture

```
CLI Entry Point (main.py)
        │
        ▼
Session Setup ──────── Auth handler, proxy config, custom headers
        │
        ├──────────────────────────────────┐
        ▼                                  ▼
Passive Module Execution          Active Web Crawler
(no payload injection)            (depth-limited, scope-enforced)
  headers, info, crypto,          Form extraction, URL param
  auth, api, ai                   discovery, endpoint dedup
        │                                  │
        │                                  ▼
        │                         Active Module Execution
        │                         (payload injection)
        │                         sqli, xss, bac, ssrf
        │                                  │
        └──────────────┬───────────────────┘
                       ▼
              Result Collector
              (thread-safe, deduplicated)
                       │
                       ▼
              CVSS v3.1 Scoring Engine
                       │
                       ▼
              Attack Chain Correlation
              (vulnerability relationship mapping)
                       │
                       ▼
              False-Positive Filter
              (reflection validation, error signature matching)
                       │
                       ▼
              Report Generator
              HTML | JSON | Markdown
```

### Module Interaction Model

**Passive modules** execute against the target origin directly — no form submission, no parameter injection. They inspect server responses, headers, and configuration signals. Passive results are available immediately and feed into attack chain correlation before active scanning begins.

**Active modules** consume endpoints discovered by the crawler. The `EndpointManager` deduplicates across discovery sources and exposes typed query interfaces (`with_params()`, `api_endpoints()`) so each active module receives only the endpoint subset relevant to its technique.

**Vulnerability correlation** in `attack_chain.py` operates on the aggregated finding set. It applies rule-based relationship modeling: Information Disclosure findings that expose technology version details escalate adjacent Vulnerable Component findings; Authentication failures that precede Injection findings generate compound attack chain entries with escalated severity.

### False-Positive Reduction Strategy

The scanner applies two-layer validation before finalizing findings:

1. **Signature confirmation**: SQLi findings require a recognizable database error pattern in the response body. Generic HTTP 500 responses that also appear in clean baseline requests are suppressed.
2. **Reflection validation**: XSS findings require unencoded payload presence in the response. HTML-entity-encoded reflections (`&lt;script&gt;`) are classified as non-exploitable and filtered.

Thresholds are configurable via `config.yaml` to balance sensitivity against noise for different target environments.

---

## Architecture Overview

### Data Flow

```
                         ┌──────────────────────────────┐
                         │     CLI  ·  main.py           │
                         │  URL · modules · auth · proxy │
                         └──────────────┬───────────────┘
                                        │
                         ┌──────────────▼───────────────┐
                         │        Session Setup          │
                         │  cookies · headers · proxy    │
                         └──────────────┬───────────────┘
                                        │
               ┌────────────────────────┴──────────────────────┐
               │                                               │
   ┌───────────▼────────────┐                  ┌──────────────▼──────────────┐
   │    Passive Modules      │                  │       Active Crawler         │
   │  headers  ·  info       │                  │  depth-limited · scoped      │
   │  crypto   ·  auth       │                  │  form extraction             │
   │  api      ·  ai         │                  │  URL param discovery         │
   └───────────┬─────────────┘                  └──────────────┬──────────────┘
               │                                               │
               │                                ┌──────────────▼──────────────┐
               │                                │       Active Modules         │
               │                                │  sqli · xss · bac · ssrf    │
               │                                └──────────────┬──────────────┘
               │                                               │
               └───────────────────────┬───────────────────────┘
                                       │
                         ┌─────────────▼────────────────┐
                         │       Result Collector        │
                         │  deduplicate · normalize      │
                         └─────────────┬────────────────┘
                                       │
                         ┌─────────────▼────────────────┐
                         │     CVSS v3.1 Scoring         │
                         │  0.0 – 10.0  per finding      │
                         └─────────────┬────────────────┘
                                       │
                         ┌─────────────▼────────────────┐
                         │   Attack Chain Correlation    │
                         │  model adversary paths        │
                         │  MITRE ATT&CK · OWASP refs   │
                         └─────────────┬────────────────┘
                                       │
                         ┌─────────────▼────────────────┐
                         │    False-Positive Filter      │
                         │  signature · reflection check │
                         └──────┬──────────┬────────────┘
                                │          │
              ┌─────────────────┘          └─────────────────┐
              │                                              │
   ┌──────────▼──────────┐                     ┌────────────▼────────────┐
   │      HTML Report     │                     │  JSON Report · Markdown  │
   │  visual dashboard    │                     │  SIEM · CI/CD · tickets  │
   └─────────────────────┘                     └─────────────────────────┘
```

### File Structure

```
web-vuln-scanner/
│
├── main.py                       CLI entry point and scan orchestrator
│
├── core/                         Engine layer
│   ├── target.py                 Target metadata, scope enforcement
│   ├── crawler.py                Enhanced crawler with endpoint management
│   ├── endpoint_manager.py       Thread-safe endpoint registry and deduplication
│   ├── scanner_engine.py         ThreadPoolExecutor-based module runner
│   ├── result_collector.py       Thread-safe finding aggregator with dedup and CVSS
│   ├── attack_chain.py           Vulnerability correlation and chain modeling
│   ├── cvss.py                   CVSS v3.1 base score calculator
│   ├── report.py                 HTML and JSON report generation
│   ├── auth.py                   Authentication handler (cookies, headers, proxy)
│   └── utils.py                  HTTP session factory, URL normalization, timing
│
├── modules/                      Scanner modules (one per vulnerability class)
│   ├── scanner_base.py           Abstract base class — standardizes finding schema
│   ├── header_auditor.py         A05:2021 — Security header analysis
│   ├── info_disclosure.py        A05:2021 — Sensitive path and error detection
│   ├── sql_injection.py          A03:2021 — Error-based and time-based blind SQLi
│   ├── xss_scanner.py            A03:2021 — Reflected XSS with reflection validation
│   ├── broken_access_control.py  A01:2021 — IDOR, path traversal, verb tampering
│   ├── cryptographic_failures.py A02:2021 — TLS, cookie flags, HSTS
│   ├── broken_auth_scanner.py    A07:2021 — Default credentials, lockout, JWT
│   ├── ssrf_scanner.py           A10:2021 — Cloud metadata, loopback, header injection
│   ├── api_scanner.py            API Top 10 (2023) — BOLA, rate limits, CORS
│   ├── ai_scanner.py             AI Top 10 (2025) — Prompt injection, model theft
│   ├── crawler.py                Web crawler with form and parameter extraction
│   └── false_positive_filter.py  Post-scan noise reduction
│
├── reporter/                     Output layer
│   ├── html_reporter.py          Interactive HTML dashboard with severity charts
│   ├── json_reporter.py          Machine-readable structured JSON
│   └── markdown_reporter.py      Human-readable Markdown format
│
├── utils/                        Shared infrastructure
│   ├── logger.py                 Structured, color-coded logging (all output to stderr)
│   ├── config.py                 YAML configuration loader
│   ├── mitre.py                  MITRE ATT&CK technique mapping database
│   └── payload_loader.py         OWASP-mapped payload file resolver (-w support)
│
├── data/                         OWASP-mapped payload files (auto-loaded per module)
│   ├── sqli.txt                  SQL injection payloads (error-based, time-based, union)
│   ├── xss.txt                   XSS payloads with reflection marker
│   ├── ssrf.txt                  SSRF probe targets (loopback + cloud metadata)
│   ├── bac.txt                   Forced browsing and IDOR probe paths
│   ├── auth.txt                  Default credentials and auth bypass payloads
│   └── paths.txt                 Information disclosure path list
│
├── tests/                        pytest test suite with HTTP mocking
├── examples/                     Docker Compose lab environment (DVWA)
└── config.yaml                   Default scan configuration
```

### Component Responsibilities

| Component | Responsibility |
|---|---|
| `main.py` | CLI argument parsing, session construction, scan phase orchestration, report dispatch |
| `core/target.py` | Immutable target representation, same-origin scope enforcement |
| `core/endpoint_manager.py` | Thread-safe endpoint deduplication registry with typed query interfaces |
| `core/scanner_engine.py` | Parallel module execution via ThreadPoolExecutor, module adapter pattern |
| `core/result_collector.py` | Finding normalization, deduplication by fingerprint, CVSS scoring application |
| `core/attack_chain.py` | Finding relationship modeling, severity escalation, chain entry generation |
| `core/cvss.py` | CVSS v3.1 base score calculation per finding type |
| `modules/scanner_base.py` | Standardized finding schema factory, shared logging interface |

---

## Installation

```bash
git clone https://github.com/niteshghimire0147/web-vuln-scanner.git
cd web-vuln-scanner

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Optional: development dependencies (testing, linting)
pip install -r requirements-dev.txt
```

**Requirement:** Python 3.9+

---

## Usage

```bash
python main.py --url <TARGET> [OPTIONS]

Options:
  --url, -u         Target URL (required)
  --modules         Comma-separated module list (default: all)
                    headers,info,sqli,xss,bac,crypto,auth,ssrf,api,ai
  --depth           Crawler recursion depth (default: 2)
  --max-pages       Maximum pages to crawl (default: 50)
  --timeout         HTTP request timeout in seconds (default: 10)
  --delay           Inter-request delay for rate limiting (default: 0)
  --cookie          Session cookie string ("PHPSESSID=abc; security=low")
  --header          Additional HTTP header — repeatable ("Name: Value")
  --proxy           HTTP/HTTPS proxy URL ("http://127.0.0.1:8080")
  -o, --output      Report base name saved in output/ (default: scan_<host>_<ts>)
  --json            Also save a JSON report  (output/<name>.json)
  --markdown        Also save a Markdown report (output/<name>.md)
  -w, --wordlist    Custom payload: file path, folder, or literal string
  --fail-on         Exit code 1 threshold: critical / high / medium / none (default: high)
  -v, --verbose     Enable verbose progress output

Exit codes:
  0   No findings at or above --fail-on threshold
  1   Findings detected at or above threshold (security alert, not build failure)
```

### Examples

```bash
# Full scan — HTML report auto-saved to output/scan_<host>_<ts>.html
python main.py -u http://testapp.local -v

# Full scan with named report + all formats
python main.py -u http://testapp.local -o report --json --markdown -v

# Injection-focused with authenticated session
python main.py -u http://app.com --modules sqli,xss,bac --cookie "session=abc123"

# Custom payload file override
python main.py -u http://app.com --modules sqli,xss -w custom/my_payloads.txt

# Custom payloads from a folder (loads all .txt files inside)
python main.py -u http://app.com --modules sqli -w custom/sqli-payloads/

# Rate-limited deep crawl
python main.py -u http://app.com --depth 3 --max-pages 200 --delay 0.5

# API and AI security assessment
python main.py -u http://api.target.com --modules api,ai,auth,crypto --json

# Intercept traffic through Burp Suite
python main.py -u http://target.com --proxy http://127.0.0.1:8080 -v
```

---

## CI/CD Integration

The scanner is designed as a security gate in automated pipelines. All human-readable output (banner, progress, summary) goes to **stderr**. **stdout** is silent — machine-readable data is written to files only.

### Exit Code Contract

| Code | Meaning |
|---|---|
| `0` | Scan complete — no findings at or above the configured threshold |
| `1` | Security alert — findings detected at or above threshold |

### `--fail-on` Threshold Control

```bash
# Audit-only — always exits 0, findings still reported (never blocks pipeline)
python main.py -u https://staging.app.com --json --fail-on none

# Block only on CRITICAL findings
python main.py -u https://staging.app.com --json --fail-on critical

# Block on HIGH or CRITICAL (default)
python main.py -u https://staging.app.com --json --fail-on high

# Block on MEDIUM and above
python main.py -u https://staging.app.com --json --fail-on medium
```

### Supported CI Platforms

| Platform | Integration Method |
|---|---|
| GitHub Actions | `continue-on-error: true` + `upload-artifact` — see `.github/workflows/ci.yml` |
| GitLab CI | `allow_failure: true` with JSON artifact |
| Jenkins | `catchError(buildResult: 'UNSTABLE')` block |
| Azure DevOps | `continueOnError: true` task flag |

### GitHub Actions Quick Example

```yaml
- name: Security Scan
  id: scan
  run: python main.py --url ${{ vars.STAGING_URL }} --json --fail-on critical
  continue-on-error: true

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: output/*.json

- name: Enforce Gate
  if: steps.scan.outcome == 'failure'
  run: echo "CRITICAL findings — review artifact" && exit 1
```

---

## Scanner Modules

| Module | OWASP Reference | Detection Technique |
|---|---|---|
| `headers` | A05:2021 | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `info` | A05:2021 | 25+ sensitive path probes, stack trace and verbose error detection |
| `sqli` | A03:2021 | Error-based (20+ DB signatures) + time-based blind, database fingerprinting |
| `xss` | A03:2021 | Reflected XSS, 8 payload variants, unescaped reflection validation |
| `bac` | A01:2021 | IDOR, path traversal, forced browsing, HTTP verb tampering |
| `crypto` | A02:2021 | Plaintext HTTP transmission, cookie flag analysis, absent HSTS |
| `auth` | A07:2021 | Default credential enumeration, lockout bypass, JWT algorithm confusion |
| `ssrf` | A10:2021 | Cloud metadata probing (AWS/GCP/Azure), loopback injection, header-based SSRF |
| `api` | API Top 10 (2023) | BOLA, broken auth, rate limiting absence, CORS misconfiguration, shadow APIs |
| `ai` | AI Top 10 (2025) | Prompt injection, insecure output handling, model theft, supply chain exposure |

---

## Payload System

Each injection module automatically loads payloads from a matching file in `data/` — no configuration required.

| Module | Default file | Contents |
|---|---|---|
| `sqli` | `data/sqli.txt` | Error-based, time-based blind, union-based payloads |
| `xss` | `data/xss.txt` | Reflected XSS payloads with embedded reflection marker |
| `ssrf` | `data/ssrf.txt` | Loopback, IPv6, cloud metadata probe URLs |
| `bac` | `data/bac.txt` | Admin panel paths and IDOR parameter probes |
| `auth` | `data/auth.txt` | Default credentials and auth bypass payloads |
| `info` | `data/paths.txt` | Sensitive file and debug endpoint paths |

### Custom Payloads (`-w`)

The `-w` / `--wordlist` flag overrides the default `data/` files for all active injection modules:

```bash
# Single literal payload (no file needed)
python main.py -u http://target.com --modules sqli -w "' OR 1=1--"

# Single payload file (replaces data/sqli.txt and data/xss.txt for this run)
python main.py -u http://target.com --modules sqli,xss -w custom/my_payloads.txt

# Folder — loads every .txt file inside dynamically
python main.py -u http://target.com --modules sqli -w custom/sqli-payloads/
```

**Priority:** `-w` always overrides `data/` defaults. When no `-w` is given and no `data/<module>.txt` exists, the module falls back to its built-in hardcoded payload list — nothing breaks.

---

## False-Positive Filtering

The scanner applies two-layer false-positive reduction before finalizing findings:

**Pre-scan baseline fingerprinting (per-module)**

- **Broken Access Control**: Before probing any admin/sensitive paths, the scanner fetches a guaranteed-non-existent URL and records its body hash and size. Any path that returns a response identical or near-identical (within 2% body size) to that baseline is silently discarded. This eliminates the most common false positive on SPAs and Next.js / React apps that return HTTP 200 for every route — the client-side router shows a 404 UI, but the server always responds 200.
- **Info Disclosure**: Same baseline fingerprinting — sensitive paths that return the SPA's catch-all `index.html` are suppressed. Content-type validators further confirm that flagged files actually contain the expected content (e.g., `.env` must match `KEY=VALUE` patterns, `.git/HEAD` must match `ref: refs/heads/`).

**Post-scan signature validation** (`modules/false_positive_filter.py`)

- **SQL Injection**: Requires a recognizable database error signature in the response body. HTTP 500 responses not containing DB-specific patterns are suppressed.
- **XSS**: Validates that the injected payload appears *unencoded* in the response. HTML-entity-encoded reflections are classified as non-exploitable and excluded.

Configurable thresholds in `config.yaml`:

```yaml
false_positive:
  enabled: true
  min_body_diff_bytes: 50       # Minimum response delta to flag anomalous behavior
  reflection_threshold: 0.8     # Minimum unencoded reflection match ratio for XSS
```

---

## Report Output

> **Screenshot placeholders** — add your actual screenshots to `docs/images/` and they will render here on GitHub.

### HTML Dashboard

![Scanner Dashboard](docs/images/dashboard.png)
*HTML report — severity breakdown, collapsible findings, CVSS scores, MITRE ATT&CK context*

### Report Output Example

![Report Output](docs/images/output.png)
*Sample scan report showing findings grouped by severity with evidence and remediation guidance*

---

All reports are saved to the `output/` folder automatically. **HTML is always generated.** JSON and Markdown are optional extras.

```bash
# Default — HTML only, auto-named
python main.py -u http://target.com
# output/scan_target.com_20260426_153000.html

# Named report
python main.py -u http://target.com -o myreport
# output/myreport.html

# Named report + optional formats
python main.py -u http://target.com -o myreport --json --markdown
# output/myreport.html  +  output/myreport.json  +  output/myreport.md
```

| Format | Flag | Primary Use |
|---|---|---|
| HTML | always on | Client deliverables, visual severity dashboard, collapsible findings |
| JSON | `--json` | SIEM ingestion, CI/CD pipeline integration, custom automation |
| Markdown | `--markdown` | Documentation, ticket creation, peer review |

### Sample Terminal Output

```
  +==================================================================+
  |       Web Application Vulnerability Scanner  v2.0.0             |
  |  OWASP Web Top 10 (2021) · API Top 10 (2023) · AI Top 10 (2025)|
  |  *** AUTHORIZED TESTING ONLY ***                                 |
  +==================================================================+

[1/10] Security Headers (A05:2021)...         3 findings
[2/10] Information Disclosure (A05:2021)...   1 finding
[3/10] SQL Injection (A03:2021)...            2 findings
[4/10] Cross-Site Scripting (A03:2021)...     1 finding
[5/10] Broken Access Control (A01:2021)...    2 findings
[6/10] Cryptographic Failures (A02:2021)...   1 finding
[7/10] Authentication Failures (A07:2021)...  2 findings
[8/10] SSRF (A10:2021)...                     1 finding
[9/10] API Security (API Top 10)...           3 findings
[10/10] AI Security (AI Top 10)...            2 findings

============================================================
  Scan Summary
============================================================
  Total findings : 18
  Elapsed time   : 47.3s

  CRITICAL       3
  HIGH           6
  MEDIUM         5
  LOW            2
  INFORMATIONAL  2
============================================================
```

---

## 🧪 Testing

```
65 / 65 tests passing
```

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=modules --cov-report=term-missing
```

| Test Module | Coverage |
|---|---|
| `test_sql_injection.py` | Error-based and time-based blind SQLi detection, form and URL parameter injection |
| `test_xss_scanner.py` | Reflected XSS reflection, script context detection, hidden input skipping |
| `test_header_auditor.py` | Missing header detection, server leakage, weak CSP flagging |
| `test_info_disclosure.py` | Sensitive path probing, stack trace detection, SPA false-positive suppression |
| `test_false_positive_filter.py` | SQL error signature validation, XSS reflection confirmation, baseline comparison |

All tests use HTTP response mocking (`responses` library) — no live network required.

---

## Safe Testing Environment

Use intentionally vulnerable applications for authorized lab testing:

```bash
# DVWA (Damn Vulnerable Web Application) — low security level
python main.py -u http://localhost:8080 \
  --cookie "security=low; PHPSESSID=test" \
  -v

# With all report formats
python main.py -u http://localhost:8080 \
  --cookie "security=low; PHPSESSID=test" \
  --json --markdown -v

# Full lab environment via Docker Compose (see examples/)
docker-compose -f examples/docker-compose.yml up -d
python main.py -u http://localhost:8080 --json --markdown -v
```

Recommended lab targets: [DVWA](http://dvwa.co.uk/), [WebGoat](https://owasp.org/www-project-webgoat/), [Juice Shop](https://owasp.org/www-project-juice-shop/)

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.9+ |
| HTTP Client | requests ≥ 2.31.0 |
| HTML Parsing | beautifulsoup4 ≥ 4.12.0 |
| Configuration | PyYAML ≥ 6.0 |
| Terminal Output | colorama ≥ 0.4.6 |
| Testing | pytest + responses (HTTP mocking) |
| Static Analysis | flake8 (linting), bandit (security) |
| CI/CD | GitHub Actions |

---

## Known Limitations

| Area | Limitation |
|---|---|
| SQLi | Time-based blind detection relies on response timing; susceptible to network jitter on high-latency targets |
| Crawling | Depth-limited; JavaScript-rendered SPAs (React, Vue, Angular) require supplemental tooling (Playwright/Selenium) |
| XSS | Reflection-based detection only; DOM-based and stored XSS require runtime execution or two-phase retrieval |
| Authentication | Session cookie passthrough only — no login form automation or MFA handling |
| CSRF | Out of scope; requires browser-context execution |
| Stored XSS | Excluded; two-phase submit-retrieve approach carries persistence risk on production targets |

---

## Roadmap

- [ ] JavaScript-rendered SPA support via Playwright integration
- [ ] SARIF output format for GitHub Code Scanning native integration
- [ ] YAML-defined custom scan rule engine (no Python required)
- [ ] GraphQL introspection and schema enumeration module
- [ ] Continuous scanning mode with delta-only reporting
- [ ] Stored XSS detection via sandboxed two-phase approach
- [ ] Subdomain enumeration for expanded attack surface discovery
- [ ] WebSocket security testing module

---

## 📌 Key Highlights

| | |
|---|---|
| ✔ | Modular plugin-based architecture — add a scanner by subclassing `ScannerBase`, no engine changes |
| ✔ | Real attack chain correlation — not isolated findings, but modeled adversary paths |
| ✔ | Production-ready CI/CD behavior — configurable exit codes, clean stdout/stderr separation |
| ✔ | Three security frameworks in one tool — Web + API + AI, all OWASP-aligned |
| ✔ | Extensible for enterprise workflows — SIEM-ready JSON, MITRE ATT&CK context on every finding |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, the module authoring guide, and pull request process.

## Security Policy

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

## Disclaimer

**Authorized testing only.** This tool is intended for use against systems you own or have explicit written authorization to test. Unauthorized use against third-party systems is illegal. See [DISCLAIMER.md](DISCLAIMER.md).

Licensed under [MIT](LICENSE).

---

**Author:** Nitesh Ghimire — Security Researcher
GitHub: [@niteshghimire0147](https://github.com/niteshghimire0147)
