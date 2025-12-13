# slowql/src/slowql/reporters/json_reporter.py
"""
JSON reporter for SlowQL.

Outputs the full analysis result as a structured JSON object.
Useful for CI/CD integration and machine consumption.
"""

from __future__ import annotations

import json
import csv
from html import escape
from typing import Any

from slowql.core.models import AnalysisResult, Issue
from slowql.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """
    Renders analysis results as JSON.
    """

    def report(self, result: AnalysisResult) -> None:
        """
        Convert result to JSON and write to output.
        """
        data = result.to_dict()
        
        json_output = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str  # Handle datetimes etc.
        )
        
        if self.output_file:
            self.output_file.write(json_output)
        else:
            print(json_output)


def _normalize_fix_text(fix_obj: Any) -> str:
    """
    Normalize the `fix` field into a human-readable string.

    Supports:
      - None
      - str
      - structured Fix objects with .description / .replacement
    """
    if fix_obj is None:
        return ""

    if isinstance(fix_obj, str):
        txt = fix_obj.strip()
        return "" if txt.lower() == "none" else txt

    desc = getattr(fix_obj, "description", None)
    repl = getattr(fix_obj, "replacement", None)

    parts: list[str] = []
    if desc:
        parts.append(str(desc).strip())
    if repl:
        parts.append(str(repl).strip())

    txt = " ".join(parts).strip()
    return "" if txt.lower() == "none" else txt


class HTMLReporter(BaseReporter):
    """
    Renders analysis results as a standalone HTML report.

    One row per Issue, with:
      - Severity
      - Rule ID
      - Dimension
      - Message
      - Impact
      - Fix (normalized text)
      - Location (if available)
    """

    def report(self, result: AnalysisResult) -> None:
        rows: list[dict[str, str]] = []

        for issue in result.issues:
            sev = getattr(issue.severity, "name", str(issue.severity))
            rule_id = issue.rule_id or ""
            dim = getattr(issue.dimension, "name", "") if getattr(issue, "dimension", None) else ""
            msg = issue.message or ""
            impact = issue.impact or ""
            fix_txt = _normalize_fix_text(getattr(issue, "fix", None))
            loc = f"{getattr(issue, 'location', '') or ''}"

            rows.append(
                {
                    "severity": sev,
                    "rule_id": rule_id,
                    "dimension": dim,
                    "message": msg,
                    "impact": impact,
                    "fix": fix_txt,
                    "location": loc,
                }
            )

        # Build HTML table body
        html_rows: list[str] = []
        for r in rows:
            html_rows.append(
                f"""
        <tr>
          <td class="sev sev-{escape(r['severity'].lower())}">{escape(r['severity'])}</td>
          <td>{escape(r['rule_id'])}</td>
          <td>{escape(r['dimension'])}</td>
          <td>{escape(r['message'])}</td>
          <td>{escape(r['impact'])}</td>
          <td>{escape(r['fix'])}</td>
          <td>{escape(r['location'])}</td>
        </tr>"""
            )

        # Safe meta values
        total_issues = getattr(result.statistics, "total_issues", len(result.issues))
        score_val = getattr(result, "score", None) or getattr(result, "health_score", None)
        if score_val is not None:
            health_html = f"<div>Health score: {score_val}/100</div>"
        else:
            health_html = ""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SlowQL Analysis Report</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0b1120;
      color: #e5e7eb;
      padding: 24px;
    }}
    h1 {{
      color: #f97316;
      text-align: center;
      margin-bottom: 0.25rem;
    }}
    h2 {{
      color: #a855f7;
      margin-top: 1.5rem;
    }}
    .meta {{
      font-size: 13px;
      color: #9ca3af;
      margin-bottom: 1rem;
      text-align: center;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      font-size: 13px;
    }}
    th, td {{
      padding: 8px 10px;
      border-bottom: 1px solid #1f2937;
      vertical-align: top;
    }}
    th {{
      background: #020617;
      color: #f9fafb;
      text-align: left;
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    tr:nth-child(even) td {{
      background: #020617;
    }}
    .sev-critical {{ color: #f97373; font-weight: 600; }}
    .sev-high     {{ color: #fb923c; font-weight: 600; }}
    .sev-medium   {{ color: #22c55e; }}
    .sev-low      {{ color: #38bdf8; }}
    .sev-info     {{ color: #9ca3af; }}
    code {{
      font-family: "JetBrains Mono", "Fira Code", monospace;
    }}
  </style>
</head>
<body>
  <h1>SlowQL Analysis Report</h1>
  <div class="meta">
    <div>Total issues: {total_issues}</div>
    {health_html}
  </div>

  <h2>Detected Issues</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule ID</th>
        <th>Dimension</th>
        <th>Message</th>
        <th>Impact</th>
        <th>Fix</th>
        <th>Location</th>
      </tr>
    </thead>
    <tbody>
      {''.join(html_rows)}
    </tbody>
  </table>
</body>
</html>
"""
        if self.output_file:
            self.output_file.write(html)
        else:
            print(html)

class CSVReporter(BaseReporter):
    """
    Renders analysis results as CSV.

    Columns:
      severity, rule_id, dimension, message, impact, fix, location
    """

    def report(self, result: AnalysisResult) -> None:
        writer = csv.writer(self.output_file or sys.stdout)  # type: ignore[arg-type]

        # Header
        writer.writerow(
            [
                "severity",
                "rule_id",
                "dimension",
                "message",
                "impact",
                "fix",
                "location",
            ]
        )

        for issue in result.issues:
            sev = getattr(issue.severity, "name", str(issue.severity))
            rule_id = issue.rule_id or ""
            dim = getattr(issue.dimension, "name", "") if getattr(issue, "dimension", None) else ""
            msg = issue.message or ""
            impact = issue.impact or ""
            fix_txt = _normalize_fix_text(getattr(issue, "fix", None))
            loc = f"{getattr(issue, 'location', '') or ''}"

            writer.writerow([sev, rule_id, dim, msg, impact, fix_txt, loc])