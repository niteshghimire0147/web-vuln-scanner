"""
core/report.py — Professional Report Generator

Produces two output formats:
  1. A self-contained, single-file HTML report styled like a real
     security assessment dashboard (Burp Suite / OWASP ZAP aesthetic).
  2. A structured JSON report suitable for CI/CD pipeline integration
     and programmatic consumption.
"""
import json
import os
from datetime import datetime


# ── Severity palette ──────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL":      "#dc2626",
    "HIGH":          "#ea580c",
    "MEDIUM":        "#d97706",
    "LOW":           "#16a34a",
    "INFORMATIONAL": "#2563eb",
}

SEV_BG = {
    "CRITICAL":      "#fef2f2",
    "HIGH":          "#fff7ed",
    "MEDIUM":        "#fffbeb",
    "LOW":           "#f0fdf4",
    "INFORMATIONAL": "#eff6ff",
}

RISK_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
}


# ── Main report class ─────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generates professional HTML and JSON vulnerability reports.

    Args:
        target_url:    Canonical URL of the scanned target.
        findings:      List of normalised finding dicts.
        chains:        List of attack chain dicts from AttackChainEngine.
        modules:       List of modules that were run.
        elapsed:       Scan duration in seconds.
        scanner_version: Scanner version string.
    """

    def __init__(
        self,
        target_url:      str,
        findings:        list[dict],
        chains:          list[dict],
        modules:         list[str],
        elapsed:         float,
        scanner_version: str = "2.0.0",
    ) -> None:
        self.target_url      = target_url
        self.findings        = findings
        self.chains          = chains
        self.modules         = modules
        self.elapsed         = elapsed
        self.scanner_version = scanner_version
        self.timestamp       = datetime.utcnow().isoformat() + "Z"

    # ── JSON ──────────────────────────────────────────────────────────────

    def save_json(self, path: str) -> str:
        """Write a structured JSON report and return the file path."""
        data = {
            "meta": {
                "scanner":   f"WebVulnScanner v{self.scanner_version}",
                "target":    self.target_url,
                "timestamp": self.timestamp,
                "elapsed_s": round(self.elapsed, 1),
                "modules":   self.modules,
            },
            "summary":       self._summary(),
            "findings":      self.findings,
            "attack_chains": self.chains,
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        return path

    # ── HTML ──────────────────────────────────────────────────────────────

    def save_html(self, path: str) -> str:
        """Write a self-contained HTML report and return the file path."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        html = self._build_html()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path

    # ── Internal: summary ─────────────────────────────────────────────────

    def _summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "INFORMATIONAL")
            counts[s] = counts.get(s, 0) + 1
        scores = [
            f["cvss"]["cvss_score"]
            for f in self.findings
            if "cvss" in f
        ]
        return {
            "total_findings":  len(self.findings),
            "severity_counts": counts,
            "attack_chains":   len(self.chains),
            "max_cvss":        max(scores, default=0.0),
            "avg_cvss":        round(sum(scores) / len(scores), 2) if scores else 0.0,
            "elapsed_s":       round(self.elapsed, 1),
        }

    # ── Internal: HTML builder ────────────────────────────────────────────

    def _build_html(self) -> str:
        summary    = self._summary()
        counts     = summary["severity_counts"]
        max_count  = max(counts.values(), default=1)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report — {self._esc(self.target_url)}</title>
  {self._css()}
</head>
<body>
  {self._nav()}
  <main>
    {self._hero(summary)}
    {self._severity_dashboard(counts, max_count)}
    {self._chains_section()}
    {self._findings_section()}
    {self._recommendations_section()}
  </main>
  {self._footer()}
  {self._js()}
</body>
</html>"""

    def _css(self) -> str:
        return """<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
a{color:#38bdf8;text-decoration:none}
code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.85em;word-break:break-all;font-family:'Cascadia Code','Fira Code',monospace}

/* Nav */
nav{background:#1e293b;border-bottom:1px solid #334155;padding:0 24px;display:flex;align-items:center;gap:16px;height:56px;position:sticky;top:0;z-index:100}
.nav-brand{font-size:1.1rem;font-weight:700;color:#38bdf8;white-space:nowrap}
.nav-meta{font-size:0.78rem;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nav-badge{margin-left:auto;background:#dc2626;color:#fff;padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;white-space:nowrap}

/* Hero */
.hero{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-bottom:1px solid #334155;padding:32px 24px}
.hero h1{font-size:1.6rem;font-weight:700;color:#f8fafc;margin-bottom:4px}
.hero .sub{color:#94a3b8;font-size:0.9rem;margin-bottom:20px}
.kpi-row{display:flex;flex-wrap:wrap;gap:12px}
.kpi{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:16px 20px;min-width:130px;flex:1}
.kpi-val{font-size:2rem;font-weight:800;color:#f8fafc;line-height:1}
.kpi-lbl{font-size:0.75rem;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.04em}

/* Dashboard */
main{max-width:1200px;margin:0 auto;padding:24px}
section{margin-bottom:36px}
h2{font-size:1.15rem;font-weight:700;color:#f8fafc;margin-bottom:16px;display:flex;align-items:center;gap:8px}
h2::before{content:'';display:inline-block;width:4px;height:1.1em;background:#38bdf8;border-radius:2px}

/* Severity bars */
.sev-grid{display:flex;flex-direction:column;gap:8px}
.sev-row{display:flex;align-items:center;gap:12px}
.sev-label{width:110px;font-size:0.82rem;font-weight:600;text-align:right;color:#cbd5e1}
.sev-bar-wrap{flex:1;background:#1e293b;border-radius:4px;height:22px;overflow:hidden}
.sev-bar{height:100%;border-radius:4px;transition:width .4s ease;display:flex;align-items:center;padding-left:8px;font-size:0.75rem;font-weight:700;color:#fff}
.sev-count{width:36px;text-align:right;font-size:0.85rem;font-weight:700;color:#f8fafc}

/* Chains */
.chain-card{background:#1e293b;border:1px solid #334155;border-radius:10px;margin-bottom:12px;overflow:hidden}
.chain-header{padding:14px 18px;display:flex;align-items:center;gap:12px;cursor:pointer;user-select:none}
.chain-header:hover{background:#263548}
.chain-risk{padding:3px 10px;border-radius:20px;font-size:0.72rem;font-weight:700;color:#fff}
.chain-name{font-weight:600;color:#f8fafc;flex:1}
.chain-arrow{color:#64748b;transition:transform .2s}
.chain-body{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .3s ease,padding .3s ease}
.chain-body.open{max-height:600px;padding:14px 18px}
.chain-desc{color:#94a3b8;font-size:0.88rem;line-height:1.6;margin-bottom:10px}
.chain-rec{background:#0f172a;border-left:3px solid #38bdf8;padding:10px 14px;border-radius:0 6px 6px 0;font-size:0.83rem;color:#cbd5e1}
.refs{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.ref-tag{background:#0f172a;border:1px solid #334155;border-radius:4px;padding:2px 8px;font-size:0.72rem;color:#94a3b8}

/* Findings */
.filter-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.filter-btn{border:1px solid #334155;background:#1e293b;color:#94a3b8;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:0.8rem;font-weight:500;transition:all .15s}
.filter-btn.active,.filter-btn:hover{border-color:#38bdf8;color:#38bdf8}
.finding-card{background:#1e293b;border:1px solid #334155;border-radius:10px;margin-bottom:10px;overflow:hidden;transition:border-color .15s}
.finding-card:hover{border-color:#38bdf8}
.finding-header{padding:14px 18px;display:flex;align-items:center;gap:10px;cursor:pointer}
.sev-badge{padding:3px 10px;border-radius:20px;font-size:0.72rem;font-weight:700;color:#fff;white-space:nowrap}
.finding-title{font-weight:600;color:#f8fafc;flex:1;font-size:0.92rem}
.cvss-chip{font-size:0.72rem;font-weight:700;padding:2px 8px;border-radius:4px;background:#0f172a;border:1px solid #334155;color:#94a3b8;white-space:nowrap}
.owasp-tag{font-size:0.7rem;color:#64748b;white-space:nowrap}
.finding-body{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .35s ease,padding .35s ease}
.finding-body.open{max-height:800px;padding:4px 18px 18px}
.detail-grid{display:grid;grid-template-columns:120px 1fr;gap:6px 12px;margin-bottom:10px}
.detail-key{font-size:0.78rem;color:#64748b;font-weight:600;text-transform:uppercase;padding-top:2px}
.detail-val{font-size:0.85rem;color:#cbd5e1;line-height:1.5}
.rec-box{background:#0f172a;border-left:3px solid #16a34a;padding:10px 14px;border-radius:0 6px 6px 0;font-size:0.83rem;color:#cbd5e1;line-height:1.55}

/* Recommendations */
.rec-list{counter-reset:rec}
.rec-item{display:flex;gap:14px;margin-bottom:14px;background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px}
.rec-num{counter-increment:rec;width:32px;height:32px;background:#0f172a;border:2px solid #38bdf8;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.8rem;font-weight:700;color:#38bdf8;flex-shrink:0}
.rec-num::after{content:counter(rec)}
.rec-text{flex:1}
.rec-text strong{display:block;color:#f8fafc;margin-bottom:4px;font-size:0.9rem}
.rec-text p{color:#94a3b8;font-size:0.83rem;line-height:1.55}

/* Footer */
footer{border-top:1px solid #334155;padding:20px 24px;text-align:center;color:#475569;font-size:0.78rem;margin-top:40px}

@media(max-width:640px){
  .kpi-row{flex-direction:column}
  .detail-grid{grid-template-columns:1fr}
}
</style>"""

    def _nav(self) -> str:
        crit = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        return f"""<nav>
  <span class="nav-brand">&#x1F6E1; WebVulnScanner</span>
  <span class="nav-meta">{self._esc(self.target_url)} &mdash; {self.timestamp[:10]}</span>
  {'<span class="nav-badge">&#x26A0; ' + str(crit) + ' Critical</span>' if crit else ''}
</nav>"""

    def _hero(self, summary: dict) -> str:
        counts    = summary["severity_counts"]
        crit      = counts.get("CRITICAL", 0)
        high      = counts.get("HIGH", 0)
        max_cvss  = summary["max_cvss"]
        chains    = summary["attack_chains"]
        elapsed   = summary["elapsed_s"]

        return f"""<div class="hero">
  <h1>Vulnerability Assessment Report</h1>
  <div class="sub">Target: <code>{self._esc(self.target_url)}</code> &nbsp;|&nbsp; Scanned: {self.timestamp[:19].replace("T"," ")} UTC &nbsp;|&nbsp; Duration: {elapsed}s</div>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-val">{len(self.findings)}</div><div class="kpi-lbl">Total Findings</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#dc2626">{crit}</div><div class="kpi-lbl">Critical</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#ea580c">{high}</div><div class="kpi-lbl">High</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#f59e0b">{max_cvss}</div><div class="kpi-lbl">Max CVSS</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#a78bfa">{chains}</div><div class="kpi-lbl">Attack Chains</div></div>
    <div class="kpi"><div class="kpi-val">{len(self.modules)}</div><div class="kpi-lbl">Modules Run</div></div>
  </div>
</div>"""

    def _severity_dashboard(self, counts: dict, max_count: int) -> str:
        rows = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            c     = counts.get(sev, 0)
            pct   = int((c / max_count) * 100) if max_count else 0
            color = SEV_COLORS.get(sev, "#64748b")
            rows += f"""
    <div class="sev-row">
      <span class="sev-label">{sev}</span>
      <div class="sev-bar-wrap">
        <div class="sev-bar" style="width:{pct}%;background:{color}">{c if pct > 8 else ''}</div>
      </div>
      <span class="sev-count">{c}</span>
    </div>"""
        return f"""<section id="dashboard">
  <h2>Severity Distribution</h2>
  <div class="sev-grid">{rows}
  </div>
</section>"""

    def _chains_section(self) -> str:
        if not self.chains:
            return ""
        cards = ""
        for i, chain in enumerate(self.chains):
            risk  = chain.get("risk", "High")
            color = RISK_COLORS.get(risk, "#d97706")
            refs  = "".join(
                f'<span class="ref-tag">{self._esc(r)}</span>'
                for r in chain.get("owasp_refs", []) + chain.get("mitre_refs", [])
            )
            cards += f"""
  <div class="chain-card">
    <div class="chain-header" onclick="toggle('chain-{i}')">
      <span class="chain-risk" style="background:{color}">{self._esc(risk)}</span>
      <span class="chain-name">{self._esc(chain['chain'])}</span>
      <span class="chain-arrow" id="arr-chain-{i}">&#9660;</span>
    </div>
    <div class="chain-body" id="chain-{i}">
      <p class="chain-desc">{self._esc(chain.get('description',''))}</p>
      <div class="chain-rec">{self._esc(chain.get('recommendation',''))}</div>
      <div class="refs">{refs}</div>
    </div>
  </div>"""
        return f"""<section id="chains">
  <h2>Attack Chain Correlation ({len(self.chains)})</h2>{cards}
</section>"""

    def _findings_section(self) -> str:
        if not self.findings:
            return "<section><h2>Findings</h2><p style='color:#64748b'>No vulnerabilities found.</p></section>"

        buttons = '<div class="filter-row">'
        buttons += '<button class="filter-btn active" onclick="filterSev(\'ALL\',this)">All</button>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            if any(f.get("severity") == sev for f in self.findings):
                buttons += f'<button class="filter-btn" onclick="filterSev(\'{sev}\',this)">{sev}</button>'
        buttons += "</div>"

        cards = ""
        for i, f in enumerate(self.findings):
            sev    = f.get("severity", "INFORMATIONAL")
            color  = SEV_COLORS.get(sev, "#64748b")
            score  = f.get("cvss", {}).get("cvss_score", "—")
            vec    = f.get("cvss", {}).get("vector_string", "")
            cards += f"""
  <div class="finding-card" data-sev="{sev}">
    <div class="finding-header" onclick="toggle('f-{i}')">
      <span class="sev-badge" style="background:{color}">{sev}</span>
      <span class="finding-title">{self._esc(f.get('type',''))}</span>
      <span class="cvss-chip" title="{self._esc(vec)}">CVSS {score}</span>
      <span class="owasp-tag">{self._esc(f.get('owasp_id',''))}</span>
    </div>
    <div class="finding-body" id="f-{i}">
      <div class="detail-grid">
        <span class="detail-key">Endpoint</span>
        <span class="detail-val"><code>{self._esc(str(f.get('endpoint',''))[:200])}</code></span>
        <span class="detail-key">Parameter</span>
        <span class="detail-val"><code>{self._esc(f.get('parameter','') or '—')}</code></span>
        <span class="detail-key">Payload</span>
        <span class="detail-val"><code>{self._esc(str(f.get('payload','') or '—')[:200])}</code></span>
        <span class="detail-key">Evidence</span>
        <span class="detail-val">{self._esc(str(f.get('evidence',''))[:300])}</span>
        <span class="detail-key">Confidence</span>
        <span class="detail-val">{self._esc(f.get('confidence',''))}</span>
        <span class="detail-key">CVSS Vector</span>
        <span class="detail-val"><code>{self._esc(vec)}</code></span>
        <span class="detail-key">CWE</span>
        <span class="detail-val">{self._esc(f.get('cwe_id','') or '—')}</span>
        <span class="detail-key">Module</span>
        <span class="detail-val">{self._esc(f.get('module',''))}</span>
        <span class="detail-key">Description</span>
        <span class="detail-val">{self._esc(str(f.get('description',''))[:500])}</span>
      </div>
      <div class="rec-box">{self._esc(str(f.get('recommendation',''))[:500])}</div>
    </div>
  </div>"""
        return f"""<section id="findings">
  <h2>Vulnerability Findings ({len(self.findings)})</h2>
  {buttons}
  {cards}
</section>"""

    def _recommendations_section(self) -> str:
        seen  = set()
        recs  = []
        for f in self.findings:
            rec = f.get("recommendation", "").strip()
            if rec and rec not in seen:
                seen.add(rec)
                recs.append((f.get("type", ""), rec))

        if not recs:
            return ""

        items = "".join(
            f'<li class="rec-item"><span class="rec-num"></span>'
            f'<div class="rec-text"><strong>{self._esc(t)}</strong>'
            f'<p>{self._esc(r)}</p></div></li>'
            for t, r in recs[:15]
        )
        return f"""<section id="recommendations">
  <h2>Recommendations</h2>
  <ol class="rec-list">{items}</ol>
</section>"""

    def _footer(self) -> str:
        return (
            f'<footer>Generated by <strong>WebVulnScanner v{self.scanner_version}</strong> '
            f'&mdash; {self.timestamp[:10]} &mdash; AUTHORIZED TESTING ONLY</footer>'
        )

    def _js(self) -> str:
        return """<script>
function toggle(id){
  var el=document.getElementById(id);
  var arr=document.getElementById('arr-'+id);
  el.classList.toggle('open');
  if(arr) arr.innerHTML=el.classList.contains('open')?'&#9650;':'&#9660;';
}
function filterSev(sev,btn){
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(function(c){
    c.style.display=(sev==='ALL'||c.dataset.sev===sev)?'':'none';
  });
}
</script>"""

    @staticmethod
    def _esc(text: str) -> str:
        """HTML-escape a string."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
