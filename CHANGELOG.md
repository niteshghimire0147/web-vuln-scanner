# Changelog

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
- DVWA Docker Compose demo environment in `examples/`
