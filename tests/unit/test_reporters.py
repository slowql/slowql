# tests/unit/test_reporters.py
"""
Test reporter classes.
"""

from slowql.reporters.base import BaseReporter
from slowql.reporters.console import ConsoleReporter
from slowql.reporters.json_reporter import JSONReporter
from slowql.core.models import AnalysisResult, Issue, Severity, Dimension, Location


class TestBaseReporter:
    def test_base_reporter_is_abstract(self):
        # BaseReporter is abstract and cannot be instantiated directly
        try:
            BaseReporter()
            assert False, "Should not be able to instantiate abstract class"
        except TypeError:
            pass


class TestConsoleReporter:
    def test_console_reporter_creation(self):
        reporter = ConsoleReporter()
        assert reporter is not None

    def test_console_reporter_report(self):
        reporter = ConsoleReporter()
        result = AnalysisResult()

        # Should not crash
        reporter.report(result)

    def test_console_reporter_with_issues(self):
        reporter = ConsoleReporter()
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test issue",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="SELECT *"
        )
        result = AnalysisResult()
        result.add_issue(issue)

        # Should not crash
        reporter.report(result)


class TestJSONReporter:
    def test_json_reporter_creation(self):
        reporter = JSONReporter()
        assert reporter is not None

    def test_json_reporter_report(self):
        reporter = JSONReporter()
        result = AnalysisResult()

        # Should not crash
        reporter.report(result)

    def test_json_reporter_with_issues(self):
        reporter = JSONReporter()
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test issue",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="SELECT *"
        )
        result = AnalysisResult()
        result.add_issue(issue)

        # Should not crash
        reporter.report(result)

    def test_json_reporter_with_complex_result(self):
        reporter = JSONReporter()
        loc = Location(line=1, column=1, file="test.sql")

        # Add multiple issues with different severities
        issues = [
            Issue(rule_id="SEC-001", message="Security issue", severity=Severity.CRITICAL,
                  dimension=Dimension.SECURITY, location=loc, snippet="SELECT *"),
            Issue(rule_id="PERF-001", message="Performance issue", severity=Severity.HIGH,
                  dimension=Dimension.PERFORMANCE, location=loc, snippet="SELECT *"),
            Issue(rule_id="QUAL-001", message="Quality issue", severity=Severity.MEDIUM,
                  dimension=Dimension.QUALITY, location=loc, snippet="SELECT *"),
        ]

        result = AnalysisResult()
        for issue in issues:
            result.add_issue(issue)

        # Should handle complex results
        reporter.report(result)

    def test_json_reporter_empty_result(self):
        reporter = JSONReporter()
        result = AnalysisResult()

        # Should handle empty results
        reporter.report(result)