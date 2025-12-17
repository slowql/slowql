
import pytest
import io
import json
from unittest.mock import MagicMock, patch
from slowql.reporters.json_reporter import JSONReporter, HTMLReporter, CSVReporter, _normalize_fix_text
from slowql.core.models import AnalysisResult, Statistics, Issue, Severity, Dimension, Fix, Location

class TestReportersCoverage:
    def test_normalize_fix_text(self):
        assert _normalize_fix_text(None) == ""
        assert _normalize_fix_text("  simple  ") == "simple"
        assert _normalize_fix_text("none") == ""
        assert _normalize_fix_text("NONE") == ""
        
        fix_obj = Fix("Desc", "Repl")
        assert "Desc" in _normalize_fix_text(fix_obj)
        assert "Repl" in _normalize_fix_text(fix_obj)
        
        fix_desc_only = Fix("Desc", "")
        assert "Desc" in _normalize_fix_text(fix_desc_only)

    def test_json_reporter(self):
        result = MagicMock(spec=AnalysisResult)
        result.to_dict.return_value = {"key": "val"}
        
        # Test output to file
        with io.StringIO() as buf:
            reporter = JSONReporter()
            reporter.output_file = buf
            reporter.report(result)
            assert json.loads(buf.getvalue()) == {"key": "val"}
            
        # Test output to stdout
        with patch("builtins.print") as mock_print:
            reporter = JSONReporter()
            reporter.report(result)
            assert mock_print.called

    def test_html_reporter(self):
        issues = [
            Issue(
                rule_id="RULE-1", message="Msg", severity=Severity.HIGH, 
                dimension=Dimension.SECURITY, location=Location(1,1), snippet="SELECT 1",
                impact="Bad", fix=Fix("Fix it", "Code")
            )
        ]
        result = AnalysisResult(
            issues=issues,
            statistics=Statistics(total_issues=1),
            version="1.0"
        )
        
        # Test file output
        with io.StringIO() as buf:
            reporter = HTMLReporter()
            with patch.object(reporter, "_calculate_health_score", return_value=85):
                reporter.output_file = buf
                reporter.report(result)
                out = buf.getvalue()
                assert "RULE-1" in out
                assert "Health Score: <span" in out
                assert ">85</span>/100" in out
            
        # Test stdout
        with patch("builtins.print") as mock_print:
            reporter = HTMLReporter()
            reporter.report(result)
            assert mock_print.called

    def test_csv_reporter(self):
        issues = [
             Issue(
                rule_id="RULE-1", message="Msg", severity=Severity.HIGH, 
                dimension=Dimension.SECURITY, location=Location(1,1), snippet="SELECT 1",
                impact="Bad", fix="FixStr"
            )
        ]
        result = AnalysisResult(issues=issues)
        
        with io.StringIO() as buf:
            reporter = CSVReporter()
            reporter.output_file = buf
            reporter.report(result)
            out = buf.getvalue()
            assert "RULE-1" in out
            assert "FixStr" in out
            assert "severity,rule_id" in out # Header
