"""reporter/html_reporter.py — Self-contained HTML report for web vulnerability scans."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


_SEV_COLOURS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#d97706",   "LOW": "#16a34a",
    "INFORMATIONAL": "#2563eb",
}

_OWASP_LABELS = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable Components",
    "A07:2021": "Authentication Failures",
    "A08:2021": "Software Integrity Failures",
    "A09:2021": "Logging Failures",
    "A10:2021": "SSRF",
}


class HtmlReporter:
    def render(self, data: dict[str, Any]) -> str:
        target   = data.get("target", data.get("url", "Unknown"))
        findings = data.get("findings", [])
        ts       = data.get("generated_at", datetime.utcnow().isoformat())

        # ── Severity counts ───────────────────────────────────────────────
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

        total = len(findings)
        risk_label = (
            "CRITICAL" if counts.get("CRITICAL", 0) > 0 else
            "HIGH"     if counts.get("HIGH", 0)     > 0 else
            "MEDIUM"   if counts.get("MEDIUM", 0)   > 0 else
            "LOW"
        )
        risk_colour = _SEV_COLOURS.get(risk_label, "#64748b")

        # ── Summary badges ─────────────────────────────────────────────────
        badges_html = " ".join(
            f'<span class="badge" style="background:{_SEV_COLOURS[s]}">'
            f'{counts[s]} {s}</span>'
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
            if counts.get(s, 0) > 0
        )

        # ── Findings cards ─────────────────────────────────────────────────
        cards_html = []
        for i, f in enumerate(findings, 1):
            sev    = f.get("severity", "LOW")
            colour = _SEV_COLOURS.get(sev, "#64748b")
            owasp  = f.get("owasp_id", "")
            mitre_block = ""
            if f.get("mitre"):
                m = f["mitre"]
                mitre_block = (
                    f'<p><strong>MITRE ATT&amp;CK:</strong> '
                    f'<a href="{m.get("url","#")}" target="_blank">'
                    f'{m.get("technique_id","")} — {m.get("technique_name","")}'
                    f'</a> ({m.get("tactic","")})</p>'
                )
            cards_html.append(f"""
      <div class="card">
        <div class="card-header" style="border-left:5px solid {colour}">
          <span class="badge" style="background:{colour}">{sev}</span>
          <strong>[F{i:03d}] {f.get("title","")}</strong>
          <span class="owasp-tag">{owasp}</span>
        </div>
        <div class="card-body">
          <p><strong>URL:</strong> <code>{f.get("url","")}</code></p>
          <p><strong>Description:</strong> {f.get("description","")}</p>
          <p><strong>Evidence:</strong> <code class="evidence">{f.get("evidence","")}</code></p>
          <p><strong>Recommendation:</strong> {f.get("recommendation","")}</p>
          {mitre_block}
        </div>
      </div>""")

        findings_section = "".join(cards_html) if cards_html else "<p><em>No vulnerabilities found.</em></p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Web Vulnerability Scan — {target}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:system-ui,-apple-system,sans-serif;background:#f1f5f9;color:#0f172a;padding:24px}}
    .page{{max-width:1100px;margin:auto}}
    header{{background:#0f172a;color:#f8fafc;padding:28px 32px;border-radius:10px;margin-bottom:24px}}
    header h1{{font-size:1.6rem;margin-bottom:6px}}
    header .meta{{opacity:.7;font-size:.9rem}}
    .summary{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
    .stat-box{{background:#fff;border-radius:8px;padding:16px 24px;flex:1;min-width:140px;
               box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}}
    .stat-box .num{{font-size:2rem;font-weight:700}}
    .stat-box .label{{font-size:.8rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
    .badge{{display:inline-block;padding:3px 10px;border-radius:4px;color:#fff;
            font-size:.75rem;font-weight:700;text-transform:uppercase}}
    .risk-banner{{background:#fff;border-radius:8px;padding:16px;margin-bottom:24px;
                  box-shadow:0 1px 3px rgba(0,0,0,.1);
                  border-left:6px solid {risk_colour}}}
    .risk-banner h2{{color:{risk_colour};font-size:1.1rem}}
    section h2{{margin-bottom:12px;font-size:1.2rem;color:#1e293b}}
    .card{{background:#fff;border-radius:8px;margin-bottom:12px;overflow:hidden;
           box-shadow:0 1px 3px rgba(0,0,0,.08)}}
    .card-header{{padding:12px 16px;background:#f8fafc;display:flex;
                  align-items:center;gap:10px;flex-wrap:wrap}}
    .owasp-tag{{margin-left:auto;color:#64748b;font-size:.8rem;font-family:monospace}}
    .card-body{{padding:14px 16px;font-size:.92rem;line-height:1.6}}
    .card-body p{{margin-bottom:8px}}
    code{{background:#f1f5f9;padding:2px 6px;border-radius:3px;
          font-family:'Fira Code',monospace;font-size:.85em;word-break:break-all}}
    .evidence{{display:block;background:#1e293b;color:#7dd3fc;padding:8px 12px;
               border-radius:4px;white-space:pre-wrap;margin-top:4px}}
    a{{color:#2563eb}}
    footer{{margin-top:32px;color:#94a3b8;font-size:.8rem;text-align:center}}
  </style>
</head>
<body>
<div class="page">
  <header>
    <h1>Web Vulnerability Scan Report</h1>
    <div class="meta">
      Target: <strong>{target}</strong> &nbsp;·&nbsp;
      Generated: {ts} &nbsp;·&nbsp;
      Total findings: {total}
    </div>
  </header>

  <div class="summary">
    <div class="stat-box">
      <div class="num">{total}</div>
      <div class="label">Total Findings</div>
    </div>
    {"".join(f'<div class="stat-box"><div class="num" style="color:{_SEV_COLOURS[s]}">{counts.get(s,0)}</div><div class="label">{s}</div></div>' for s in ("CRITICAL","HIGH","MEDIUM","LOW"))}
  </div>

  <div class="risk-banner">
    <h2>Overall Risk: {risk_label}</h2>
    <div style="margin-top:8px">{badges_html}</div>
  </div>

  <section>
    <h2>Findings ({total})</h2>
    {findings_section}
  </section>

  <footer>
    Generated by Web Vulnerability Scanner v1.0 &nbsp;·&nbsp; Authorized testing only
  </footer>
</div>
</body>
</html>"""

    def save(self, data: dict[str, Any], path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render(data), encoding="utf-8")
        return out
