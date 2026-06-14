"""Generate self-contained HTML security report."""
import html
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffd700",
    "LOW": "#4dabf7",
    "INFO": "#868e96",
}

STATUS_COLORS = {
    "FAIL": "#ff4444",
    "WARN": "#ffd700",
    "PASS": "#51cf66",
    "INFO": "#868e96",
    "ERROR": "#cc5de8",
}


def _severity_score(findings):
    """Calculate a 0-100 security score."""
    if not findings:
        return 100
    deductions = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2}
    score = 100
    for f in findings:
        sev = f.get("severity", "INFO")
        status = f.get("status", "INFO")
        if status in ("FAIL", "WARN"):
            score -= deductions.get(sev, 0)
    return max(0, score)


def _score_color(score):
    if score >= 80:
        return "#51cf66"
    elif score >= 60:
        return "#ffd700"
    else:
        return "#ff4444"


def generate(url, findings, output_path):
    score = _severity_score(findings)
    score_color = _score_color(score)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_url = html.escape(str(url))

    by_check = {}
    for f in findings:
        check = f.get("check", "other")
        by_check.setdefault(check, []).append(f)

    stats = {"FAIL": 0, "WARN": 0, "PASS": 0}
    for f in findings:
        s = f.get("status", "INFO")
        if s in stats:
            stats[s] += 1

    findings_html = ""
    for check_name, check_findings in by_check.items():
        findings_html += f'<div class="check-section"><h3>{html.escape(check_name.replace("_", " ").title())}</h3>'
        for f in check_findings:
            status = f.get("status", "INFO")
            severity = f.get("severity", "INFO")
            scolor = STATUS_COLORS.get(status, "#868e96")
            detail = f.get("detail", "")
            recommendation = f.get("recommendation", "")
            extra_rows = ""
            for k, v in f.items():
                if k in ("check", "status", "severity", "detail", "recommendation"):
                    continue
                if isinstance(v, list):
                    v = ", ".join(str(i) for i in v[:10])
                extra_rows += (
                    f'<tr><td class="key">{html.escape(str(k).replace("_"," ").capitalize())}</td>'
                    f'<td>{html.escape(str(v))}</td></tr>'
                )

            findings_html += f"""
<div class="finding" style="border-left: 4px solid {scolor};">
  <div class="finding-header">
    <span class="badge" style="background:{scolor}">{html.escape(str(status))}</span>
    <span class="sev-badge" style="background:{SEVERITY_COLORS.get(severity,'#868e96')}">{html.escape(str(severity))}</span>
    <span class="finding-detail">{html.escape(str(detail))}</span>
  </div>
  {"<div class='recommendation'>💡 " + html.escape(str(recommendation)) + "</div>" if recommendation else ""}
  {f"<table class='meta'>{extra_rows}</table>" if extra_rows else ""}
</div>"""
        findings_html += "</div>"

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebAudit Report — {safe_url}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 2rem; }}
  header {{ text-align: center; padding: 2rem 0; border-bottom: 1px solid #30363d; margin-bottom: 2rem; }}
  h1 {{ font-size: 2rem; color: #58a6ff; margin-bottom: 0.5rem; }}
  .url {{ color: #8b949e; font-size: 0.9rem; }}
  .meta {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.5rem; }}
  .score-ring {{ display: inline-block; font-size: 3rem; font-weight: bold; color: {score_color}; margin: 1rem 0; }}
  .stats {{ display: flex; gap: 1rem; justify-content: center; margin: 1rem 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 2rem; text-align: center; }}
  .stat-num {{ font-size: 1.8rem; font-weight: bold; }}
  .stat-label {{ font-size: 0.8rem; color: #8b949e; }}
  .check-section {{ margin-bottom: 2rem; }}
  .check-section h3 {{ color: #58a6ff; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #30363d; }}
  .finding {{ background: #161b22; border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
  .badge, .sev-badge {{ font-size: 0.75rem; font-weight: bold; padding: 2px 8px; border-radius: 4px; color: #000; }}
  .finding-detail {{ flex: 1; color: #c9d1d9; }}
  .recommendation {{ margin-top: 0.5rem; color: #8b949e; font-size: 0.9rem; padding: 0.5rem; background: #0d1117; border-radius: 4px; }}
  table.meta {{ margin-top: 0.75rem; width: 100%; font-size: 0.85rem; border-collapse: collapse; }}
  table.meta td {{ padding: 3px 8px; }}
  table.meta td.key {{ color: #8b949e; width: 160px; }}
  footer {{ text-align: center; color: #8b949e; font-size: 0.85rem; padding: 2rem 0; border-top: 1px solid #30363d; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>WebAudit Security Report</h1>
    <div class="url">{safe_url}</div>
    <div class="meta">Generated: {now}</div>
    <div class="score-ring">{score}/100</div>
    <div class="stats">
      <div class="stat"><div class="stat-num" style="color:#ff4444">{stats['FAIL']}</div><div class="stat-label">FAIL</div></div>
      <div class="stat"><div class="stat-num" style="color:#ffd700">{stats['WARN']}</div><div class="stat-label">WARN</div></div>
      <div class="stat"><div class="stat-num" style="color:#51cf66">{stats['PASS']}</div><div class="stat-label">PASS</div></div>
    </div>
  </header>
  {findings_html}
  <footer>WebAudit v1.0 — Use responsibly. Only test systems you own or have permission to test.</footer>
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(document)
