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

---

## Usage

```bash
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
```

---

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
```

---

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
