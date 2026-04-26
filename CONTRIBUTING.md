# Contributing to Web Vulnerability Scanner

Thank you for your interest in contributing. This project follows responsible security practices.

## Development Setup

```bash
# Clone and install
git clone https://github.com/niteshghimire0147/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

# Lint check
flake8 . --max-line-length=120 --exclude=__pycache__,.git,*.egg-info
```

## Adding a Scanner Module

1. Create `modules/your_scanner.py` inheriting from `ScannerBase`
2. Implement `scan() -> list[dict]` using `self._finding(...)` helper
3. Add your OWASP category and relevant payloads
4. Register it in `main.py`:
   - Add import at the top
   - Add module name to `ALL_MODULES` list
   - Add label to `MODULE_LABELS` dict
   - Add scan block in `run_scan()`
5. Write tests in `tests/test_your_scanner.py` using the `responses` mock library
6. Update `README.md` module table

### Finding Format

Every finding must include:

```python
{
    "title":       "SQL Injection in login form",
    "severity":    "CRITICAL",          # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    "url":         "http://target.com/login",
    "description": "The login form is vulnerable to error-based SQL injection.",
    "evidence":    "You have an error in your SQL syntax...",
    "remediation": "Use parameterized queries or prepared statements.",
    "owasp":       "A03:2021 Injection",
    "cwe":         "CWE-89",
}
```

## Payload Files

Add payloads to `data/` as plain text files (one payload per line). Reference them in your scanner module.

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-module`
3. Write tests that cover your changes
4. Ensure all tests pass: `python -m pytest tests/ -v`
5. Ensure linting passes: `flake8 . --max-line-length=120`
6. Submit a PR with a clear description

## Code Style

- PEP 8 compliant, max 120 characters per line
- Type hints on all function signatures
- Docstrings on all public functions and classes
- Descriptive variable names (no single-letter variables except loop counters)

## Security

If you discover a security vulnerability in the scanner itself, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
