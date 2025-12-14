
import pytest
from unittest.mock import MagicMock, patch
from slowql.reporters.console import ConsoleReporter
from slowql.core.models import AnalysisResult, Issue, Severity, Dimension, Location, Fix, Query

QUERY_LOC = Location(line=1, column=1)

def create_issue(rule_id="TEST-001", message="Test", severity=Severity.LOW, dimension=Dimension.QUALITY, fix=None):
    return Issue(
        rule_id=rule_id,
        message=message,
        severity=severity,
        dimension=dimension,
        location=QUERY_LOC,
        snippet="SELECT *",
        fix=fix
    )

class TestConsoleReporterDetails:
    
    @pytest.fixture
    def reporter(self):
        with patch("slowql.reporters.console.Console") as mock_console_cls:
            mock_console = mock_console_cls.return_value
            mock_console.width = 100
            rep = ConsoleReporter()
            # We want to keep the mock to check calls, but the class sets self.console
            return rep

    def test_show_clean_report(self, reporter):
        # We need to mock _show_clean_report calls or just call report with empty result
        # Note: _show_clean_report is not defined in the provided snippet of console.py but used in line 81.
        # It might be inherited or defined later. Let's assume it exists or I missed it in view.
        # Actually I missed viewing the end of the file.
        # But let's test report() with empty result.
        
        result = AnalysisResult()
        reporter.report(result)
        # Should likely print something about no issues.
        assert reporter.console.print.called

    def test_show_dashboard_calculates_health(self, reporter):
        result = AnalysisResult()
        # Add diverse issues
        result.add_issue(create_issue(severity=Severity.CRITICAL))
        result.add_issue(create_issue(severity=Severity.HIGH))
        
        with patch.object(reporter, "_create_health_panel") as mock_health:
             with patch.object(reporter, "_create_severity_panel") as mock_sev:
                 with patch.object(reporter, "_create_dimension_panel") as mock_dim:
                      reporter._show_dashboard_sections(result)
                      mock_health.assert_called_once()
                      mock_sev.assert_called_once()
                      mock_dim.assert_called_once()

    def test_create_health_panel_logic(self, reporter):
        # Test score logic indirectly via panel creation
        result = AnalysisResult() # 100 score
        p = reporter._create_health_panel(100, result)
        # Just check it returns a panel
        from rich.panel import Panel
        assert isinstance(p, Panel)
        assert "HEALTH" in p.title
        
        # Low score
        p = reporter._create_health_panel(30, result)
        # Assuming FAILURE IMMINENT logic

    def test_create_dimension_panel_all_types(self, reporter):
        result = AnalysisResult()
        for dim in Dimension:
            result.add_issue(create_issue(dimension=dim, rule_id=f"R-{dim.value}"))
            
        p = reporter._create_dimension_panel(result)
        # Should run without error
        assert p

    def test_heatmap_section(self, reporter):
        result = AnalysisResult()
        result.add_issue(create_issue(dimension=Dimension.SECURITY, severity=Severity.CRITICAL))
        
        reporter._show_heatmap_section(result)
        # Should print table
        assert reporter.console.print.called

    def test_issue_frequency_spectrum(self, reporter):
        result = AnalysisResult()
        result.add_issue(create_issue(rule_id="R1"))
        result.add_issue(create_issue(rule_id="R1"))
        result.add_issue(create_issue(rule_id="R2"))
        
        reporter._show_issue_frequency_spectrum(result)
        assert reporter.console.print.called

    def test_issues_table_v2(self, reporter):
        result = AnalysisResult()
        fix = Fix(description="Fix it", replacement="SELECT 1")
        result.add_issue(create_issue(fix=fix))
        result.add_issue(create_issue(fix=None)) # Cover branch with no fix
        
        reporter._show_issues_table_v2(result)
        assert reporter.console.print.called

    def test_detection_verification(self, reporter):
        result = AnalysisResult()
        reporter._show_detection_verification(result)
        assert reporter.console.print.called

    def test_show_next_steps(self, reporter):
        result = AnalysisResult()
        # Add critical issue to trigger priority alpha
        result.add_issue(create_issue(severity=Severity.CRITICAL, rule_id="C1"))
        # Add high issue to trigger priority beta
        result.add_issue(create_issue(severity=Severity.HIGH, rule_id="H1"))
        # Add issue with fix
        result.add_issue(create_issue(fix=Fix(description="Desc", replacement="Repl"), rule_id="F1"))
        
        reporter._show_next_steps(result)
        assert reporter.console.print.called
        
    def test_show_main_title(self, reporter):
        result = AnalysisResult()
        reporter._show_main_title(result)
        assert reporter.console.print.called

    def test_calculate_health_score(self, reporter):
         # Need to verify _calculate_health_score logic if accessible or add test for it if public/protected
         # It is called in _show_dashboard_sections.
         # Assuming it's protected.
         result = AnalysisResult()
         score = reporter._calculate_health_score(result)
         assert score == 100
         
         result.add_issue(create_issue(severity=Severity.CRITICAL))
         score_crit = reporter._calculate_health_score(result)
         assert score_crit < 100
