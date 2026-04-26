# Contributing to Web Vulnerability Scanner

## Setup

```bash
pip install -r requirements.txt && pip install pytest pytest-cov flake8 responses
python -m pytest tests/ -v
```

## Adding a Scanner Module

1. Create `modules/your_scanner.py` inheriting from `ScannerBase`
2. Implement `scan() -> list[dict]` using `self._finding(...)` helper
3. Add your OWASP category/payloads
4. Register it in `main.py`'s module registry
5. Write tests using the `responses` mock library

## Payload Files

Add payloads to `payloads/` as plain text files (one payload per line).
Reference them in your scanner module.

## Code Style

- PEP 8, max 120 chars, type hints, docstrings
