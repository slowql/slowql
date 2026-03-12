# slowql/src/slowql/reporters/sarif_reporter.py
"""
SARIF reporter for SlowQL.

Outputs the full analysis result as a structured SARIF 2.1.0 JSON object.
Useful for integrating with code scanning and security tooling.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from slowql.core.models import Severity
from slowql.reporters.base import BaseReporter

if TYPE_CHECKING:
    from slowql.core.models import AnalysisResult


class SARIFReporter(BaseReporter):
    """
    Renders analysis results as SARIF 2.1.0 JSON.
    """

    def _map_severity(self, severity: Severity) -> str:
        """Map SlowQL severity to SARIF level."""
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        if severity in (Severity.LOW, Severity.INFO):
            return "note"
        return "none"

    def report(self, result: AnalysisResult) -> None:
        """
        Convert result to SARIF and write to output.
        """
        rules_dict: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for issue in result.issues:
            rule_id = issue.rule_id

            # Build rule metadata if not already present
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("-", ""),
                    "shortDescription": {"text": getattr(issue, "message", "Rule violation")},
                    "properties": {
                        "category": issue.dimension.name if hasattr(issue, "dimension") and hasattr(issue.dimension, "name") else str(getattr(issue, "dimension", ""))
                    }
                }

            level = self._map_severity(issue.severity)

            sarif_result: dict[str, Any] = {
                "ruleId": rule_id,
                "message": {"text": issue.message},
                "level": level,
            }

            # Map locations if available
            if issue.location:
                loc = issue.location
                file_path = loc.file if loc.file else "unknown"

                physical_loc: dict[str, Any] = {
                    "artifactLocation": {"uri": file_path}
                }

                region: dict[str, int] = {}
                if loc.line:
                    region["startLine"] = loc.line
                if loc.end_line:
                    region["endLine"] = loc.end_line
                if loc.column:
                    region["startColumn"] = loc.column
                if loc.end_column:
                    region["endColumn"] = loc.end_column

                if region:
                    physical_loc["region"] = region

                sarif_result["locations"] = [{"physicalLocation": physical_loc}]

            sarif_results.append(sarif_result)

        sarif_log = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SlowQL",
                            "informationUri": "https://github.com/slowql/slowql",
                            "version": result.version,
                            "rules": list(rules_dict.values())
                        }
                    },
                    "results": sarif_results
                }
            ]
        }

        sarif_output = json.dumps(
            sarif_log,
            indent=2,
            ensure_ascii=False,
        )

        if self.output_file:
            self.output_file.write(sarif_output)
        else:
            print(sarif_output)
