# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - 2026-04-26

### Added
- **Broken Access Control scanner** (A01:2021) - IDOR, path traversal, forced browsing, HTTP verb tampering
- **Cryptographic Failures scanner** (A02:2021) - HTTP transmission, cookie flags, HSTS validation, credential leakage
- **Broken Authentication scanner** (A07:2021) - Default credentials, account lockout bypass, JWT misconfiguration
- **SSRF scanner** (A10:2021) - Cloud metadata endpoints, loopback injection, header-based SSRF
- **API Security scanner** (API Top 10 2023) - BOLA, broken auth, rate limiting, CORS, shadow API versioning
- **AI/LLM Security scanner** (AI Top 10 2025) - Prompt injection, insecure output handling, model theft, supply chain
- **MITRE ATT&CK mapping** for all findings with technique IDs and tactic classification
- **False-positive filter** with configurable thresholds for SQL error matching and XSS reflection validation
- **YAML configuration** (`config.yaml`) for scan parameters, module selection, and output settings
- **Structured logging** with configurable verbosity via `utils/logger.py`
- **Markdown report format** alongside existing HTML and JSON
- **SECURITY.md** responsible disclosure policy
- **GitHub Issue Templates** for bug reports and feature requests

### Changed
- Expanded module count from 4 to 10 (full OWASP coverage)
- Improved crawler with configurable depth, max pages, and delay between requests
- Enhanced CLI with `--proxy`, `--header`, `--cookie`, `--delay`, `--max-pages` options
- Upgraded HTML report with severity color coding and structured finding cards

### Fixed
- Resolved merge conflicts from v1/v2 branch integration
- Fixed Unicode character encoding issues in CLI banner

## [1.0.0] - 2025-04-15

### Added
- Web crawler with same-origin policy enforcement, form extraction, URL parameter extraction
- Header auditor: 6 required headers + 4 dangerous info-leaking headers
- SQL injection scanner: error-based (20+ DB signatures) + time-based blind
- Reflected XSS scanner with 8 payload variants and unescaped reflection detection
- Information disclosure scanner: 25 sensitive paths + verbose error detection
- HTML report with inline SVG severity bar chart
- JSON and text report formats
- GitHub Actions CI workflow
- DVWA demo environment in `examples/`
