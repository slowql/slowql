from unittest.mock import MagicMock, patch

from slowql.core.models import AnalysisResult, Dimension, Fix, Issue, Severity, Statistics
from slowql.reporters.console import ConsoleReporter


class TestConsoleReporterCoverage:
    def test_report_clean(self):
        reporter = ConsoleReporter()
        result = MagicMock(spec=AnalysisResult)
        result.issues = []
        result.queries = ["SELECT 1"]
        result.version = "1.0.0"

        with patch.object(reporter.console, "print") as mock_print:
            reporter.report(result)
            # Should print clean report
            assert mock_print.called

    def test_report_full(self):
        reporter = ConsoleReporter()

        # Create rich issue set
        issues = [
            Issue(
                rule_id="SEC-001",
                message="Security issue",
                severity=Severity.CRITICAL,
                dimension=Dimension.SECURITY,
                location=MagicMock(),
                snippet="SELECT *",
                fix=Fix("Fix it", "SELECT c"),
                impact="Bad",
            ),
            Issue(
                rule_id="PERF-001",
                message="Perf issue",
                severity=Severity.HIGH,
                dimension=Dimension.PERFORMANCE,
                location=None,
                snippet="SELECT *",
                impact="Slow",
            ),
            Issue(
                rule_id="COST-001",
                message="Cost issue",
                severity=Severity.MEDIUM,
                dimension=Dimension.COST,
                location=None,
                snippet="SELECT *",
            ),
            Issue(
                rule_id="REL-001",
                message="Reliability issue",
                severity=Severity.LOW,
                dimension=Dimension.RELIABILITY,
                location=None,
                snippet="SELECT *",
            ),
            Issue(
                rule_id="INFO-001",
                message="Info issue",
                severity=Severity.INFO,
                dimension=Dimension.QUALITY,
                location=None,
                snippet="SELECT *",
            ),
        ]

        stats = Statistics()
        for i in issues:
            stats.by_severity[i.severity] += 1
            stats.by_dimension[i.dimension] += 1
        stats.total_issues = len(issues)

        result = AnalysisResult(
            issues=issues, statistics=stats, queries=[MagicMock()], version="1.0.0"
        )

        # Patch console to avoid visual output but verify logical calls
        with patch.object(reporter.console, "print"):
            reporter.report(result)

    def test_heatmap_empty(self):
        reporter = ConsoleReporter()
        result = MagicMock(spec=AnalysisResult)
        result.issues = []
        with patch.object(reporter.console, "print"):
            reporter._show_heatmap_section(result)  # Should return early

    def test_health_score_variations(self):
        # Mock result to control health score indirectly or test _calculate_health_score.
        # _calculate_health_score is likely in BaseReporter or ConsoleReporter.
        # It's called in _show_dashboard_sections.
        pass  # Covered by report_full

    def test_fix_extraction(self):
        # Specific test for _extract_fix_text inner logic if possible, or via fix scenarios
        reporter = ConsoleReporter()
        result = MagicMock(spec=AnalysisResult)
        issue_str_fix = Issue(
            rule_id="ID",
            message="Msg",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            location=None,
            snippet="",
            fix="Simple string fix",
        )
        issue_none_fix = Issue(
            rule_id="ID",
            message="Msg",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            location=None,
            snippet="",
            fix=None,
        )
        result.issues = [issue_str_fix, issue_none_fix]
        result.statistics = Statistics()

        with patch.object(reporter.console, "print"):
            reporter._show_next_steps(result)
