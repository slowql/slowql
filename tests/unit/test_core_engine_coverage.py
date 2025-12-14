
import pytest
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path
from slowql.core.engine import SlowQL
from slowql.core.config import Config, AnalysisConfig
from slowql.core.models import AnalysisResult, Issue, Severity, Dimension, Query, Location
from slowql.core.exceptions import ParseError, SlowQLError, FileNotFoundError

class TestSlowQLEngineCoverage:
    
    @pytest.fixture
    def mock_config(self):
        config = MagicMock(spec=Config)
        config.analysis = MagicMock(spec=AnalysisConfig)
        config.analysis.dialect = "postgres"
        config.analysis.max_query_length = 1000
        config.analysis.enabled_dimensions = [d.value for d in Dimension]
        config.analysis.enabled_rules = None
        config.analysis.disabled_rules = []
        return config

    def test_init_and_properties(self, mock_config):
        with patch("slowql.core.config.Config.find_and_load", return_value=mock_config):
            engine = SlowQL(auto_discover=False)
            assert engine.config == mock_config
            
            # Test parser lazy load
            with patch("slowql.parser.universal.UniversalParser") as mock_parser_cls:
                parser = engine.parser
                assert parser is not None
                mock_parser_cls.assert_called_once()
                assert engine.parser is parser # Cached

            # Test analyzers lazy load
            with patch("slowql.analyzers.registry.get_registry") as mock_get_reg:
                mock_reg = mock_get_reg.return_value
                mock_reg.get_all.return_value = []
                analyzers = engine.analyzers
                assert isinstance(analyzers, list)
                mock_reg.discover.assert_not_called() # auto_discover=False

    def test_load_analyzers_auto_discover(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=True)
        with patch("slowql.analyzers.registry.get_registry") as mock_get_reg:
            mock_reg = mock_get_reg.return_value
            mock_reg.get_all.return_value = [MagicMock(dimension=Dimension.SECURITY)]
            
            analyzers = engine.analyzers
            mock_reg.discover.assert_called_once()
            assert len(analyzers) == 1

    def test_analyze_file_not_found(self, mock_config):
        engine = SlowQL(config=mock_config)
        with pytest.raises(FileNotFoundError):
            engine.analyze_file("nonexistent.sql")

    def test_analyze_files_exception_handling(self, mock_config):
        engine = SlowQL(config=mock_config)
        
        # specific SlowQLError re-raise
        with patch.object(engine, "analyze_file", side_effect=SlowQLError("Slow error")):
             with pytest.raises(SlowQLError):
                 engine.analyze_files(["a.sql"])

        # generic Exception wrapping
        with patch.object(engine, "analyze_file", side_effect=ValueError("Generic error")):
             with pytest.raises(ParseError) as exc:
                 engine.analyze_files(["a.sql"])
             assert "Failed to analyze file" in str(exc.value)

    def test_parse_sql_limit(self, mock_config):
        mock_config.analysis.max_query_length = 5
        engine = SlowQL(config=mock_config)
        
        with pytest.raises(ParseError) as exc:
            engine._parse_sql("123456")
        assert "exceeds maximum length" in str(exc.value)

    def test_should_report_issue_whitelist(self, mock_config):
        # enabled_rules is NOT None
        mock_config.analysis.enabled_rules = ["SEC-001", "PERF"]
        engine = SlowQL(config=mock_config)
        
        # Allowed exact
        issue1 = MagicMock(rule_id="SEC-001")
        assert engine._should_report_issue(issue1) is True
        
        # Allowed prefix
        issue2 = MagicMock(rule_id="PERF-SCAN-001")
        # prefix calculation: "-".join(issue.rule_id.split("-")[:2]) -> PERF-SCAN
        # Wait, splitting PERF-SCAN-001 by "-" gives ["PERF", "SCAN", "001"]. [:2] is ["PERF", "SCAN"]. Join -> "PERF-SCAN".
        # So "PERF" (in config) != "PERF-SCAN".
        # The logic in code is `prefix = "-".join(issue.rule_id.split("-")[:2])`.
        # If I want to whitelist by generic "PERF", the code expects specific format.
        # Let's test what the code does:
        # If rule is PERF-SCAN-001, prefix is PERF-SCAN.
        # If config has PERF-SCAN, it returns True.
        
        mock_config.analysis.enabled_rules = ["SEC-001", "PERF-SCAN"]
        assert engine._should_report_issue(issue2) is True

        # Not allowed
        issue3 = MagicMock(rule_id="REL-001")
        assert engine._should_report_issue(issue3) is False

    def test_should_report_issue_blacklist(self, mock_config):
        mock_config.analysis.enabled_rules = None
        mock_config.analysis.disabled_rules = ["SEC-001", "PERF-SCAN"]
        engine = SlowQL(config=mock_config)
        
        # Blocked exact
        issue1 = MagicMock(rule_id="SEC-001")
        assert engine._should_report_issue(issue1) is False
        
        # Blocked prefix
        issue2 = MagicMock(rule_id="PERF-SCAN-001") # prefix PERF-SCAN
        assert engine._should_report_issue(issue2) is False
        
        # Allowed
        issue3 = MagicMock(rule_id="REL-001")
        assert engine._should_report_issue(issue3) is True

    def test_get_rule_info_and_list(self, mock_config):
        engine = SlowQL(config=mock_config)
        
        # Mock analyzers/rules
        rule = MagicMock()
        rule.id = "TEST-001"
        rule.name = "Test Rule"
        rule.dimension = Dimension.QUALITY
        
        analyzer = MagicMock()
        analyzer.rules = [rule]
        
        with patch.object(engine, "_analyzers", [analyzer]):
            # Force load state
            engine._analyzers_loaded = True
            
            # get_rule_info
            info = engine.get_rule_info("TEST-001")
            assert info["id"] == "TEST-001"
            assert info["name"] == "Test Rule"
            
            assert engine.get_rule_info("NONEXISTENT") is None
            
            # list_rules
            rules = engine.list_rules()
            assert len(rules) == 1
            assert rules[0]["id"] == "TEST-001"

    def test_should_run_analyzer(self, mock_config):
        mock_config.analysis.enabled_dimensions = ["security"]
        engine = SlowQL(config=mock_config)
        
        analyzer_sec = MagicMock()
        analyzer_sec.dimension = Dimension.SECURITY # value "security"
        assert engine._should_run_analyzer(analyzer_sec) is True
        
        analyzer_perf = MagicMock()
        analyzer_perf.dimension = Dimension.PERFORMANCE # value "performance"
        assert engine._should_run_analyzer(analyzer_perf) is False

    def test_analyze_integration_mock(self, mock_config):
        # Test full analyze flow with mocks
        engine = SlowQL(config=mock_config)
        
        with patch.object(engine, "_parse_sql", return_value=[MagicMock()]), \
             patch.object(engine, "_run_analyzers", return_value=[create_issue()]):
             
             result = engine.analyze("SELECT 1")
             assert isinstance(result, AnalysisResult)
             assert len(result.issues) == 1
             assert result.statistics.analysis_time_ms > 0

def create_issue():
    return Issue(rule_id="TEST", message="Msg", severity=Severity.LOW, dimension=Dimension.QUALITY, location=Location(1,1), snippet="")
