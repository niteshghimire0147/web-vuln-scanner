"""reporter/json_reporter.py — JSON output for web vulnerability scan results."""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class JsonReporter:
    def render(self, data: dict[str, Any]) -> str:
        data.setdefault("generated_at", datetime.utcnow().isoformat())
        return json.dumps(data, indent=2, default=str)

    def save(self, data: dict[str, Any], path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render(data), encoding="utf-8")
        return out
