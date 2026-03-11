"""
GitHub Actions reporter for SlowQL.

Emits workflow commands to create annotations in GitHub Actions UI.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TextIO

from slowql.core.models import Severity
from slowql.reporters.base import BaseReporter

if TYPE_CHECKING:
    from slowql.core.models import AnalysisResult, Issue


class GithubActionsReporter(BaseReporter):
    """
    Reporter that emits GitHub Actions workflow commands.

    Maps SlowQL severities to GitHub Actions annotation levels:
    - critical/high -> error
    - medium/low -> warning
    - info -> notice

    Format:
    ::[level] file={file},line={line},col={col}::{rule_id} {message}
    """

    def __init__(self, output_file: TextIO | None = None) -> None:
        """Initialize the reporter."""
        # Default to stdout, but we allow overriding for testing
        super().__init__(output_file or sys.stdout)

    def _escape_data(self, value: str) -> str:
        """
        Escape string for use as data in GitHub Actions commands.
        See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#escaping-data
        """
        return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def _escape_property(self, value: str) -> str:
        """
        Escape string for use as a property value in GitHub Actions commands.
        See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#escaping-property-values
        """
        return (
            value.replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
            .replace(":", "%3A")
            .replace(",", "%2C")
        )

    def _get_level(self, severity: Severity) -> str:
        """Map severity to GitHub Actions level."""
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity in (Severity.MEDIUM, Severity.LOW):
            return "warning"
        return "notice"

    def _format_issue(self, issue: Issue) -> str:
        """Format a single issue as a workflow command."""
        level = self._get_level(issue.severity)

        properties = []
        if issue.location.file:
            properties.append(f"file={self._escape_property(issue.location.file)}")

        if issue.location.line:
            properties.append(f"line={issue.location.line}")

        if issue.location.column:
            properties.append(f"col={issue.location.column}")

        if issue.location.end_line:
            properties.append(f"endLine={issue.location.end_line}")

        if issue.location.end_column:
            properties.append(f"endColumn={issue.location.end_column}")

        props_str = ",".join(properties)

        message = self._escape_data(f"{issue.rule_id} {issue.message}")

        if props_str:
            return f"::{level} {props_str}::{message}"
        return f"::{level}::{message}"

    def report(self, result: AnalysisResult) -> None:
        """
        Output issues as GitHub Actions annotations.

        Args:
            result: The analysis result to report on.
        """
        for issue in result.issues:
            print(self._format_issue(issue), file=self.output_file)
