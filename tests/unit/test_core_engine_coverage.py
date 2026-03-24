from unittest.mock import MagicMock, patch

import pytest

from slowql.core.config import AnalysisConfig, Config
from slowql.core.engine import SlowQL
from slowql.core.exceptions import FileNotFoundError, ParseError, SlowQLError
from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity
from slowql.schema.models import Schema


class TestSlowQLEngineCoverage:
    @pytest.fixture
    def mock_config(self):
        config = MagicMock(spec=Config)
        config.analysis = MagicMock(spec=AnalysisConfig)
        config.analysis.dialect = "postgres"
        config.analysis.max_query_length = 1000
        config.analysis.enabled_rules = None
        config.analysis.disabled_rules = []
        config.analysis.enabled_dimensions = {
            "security",
            "performance",
            "reliability",
            "compliance",
            "cost",
            "quality",
        }
        config.analysis.parallel = False
        config.analysis.max_workers = 1
        config.schema_config = MagicMock()
        config.schema_config.path = None
        config.cache_config = MagicMock()
        config.cache_config.enabled = False
        config.plugins = MagicMock()
        config.plugins.directories = []
        config.plugins.modules = []
        return config

    def test_init_and_properties(self, mock_config):
        with patch("slowql.core.config.Config.find_and_load", return_value=mock_config):
            engine = SlowQL(auto_discover=False)
            assert engine.config == mock_config

            # Test parser lazy load
            with patch("slowql.core.engine.UniversalParser") as mock_parser_cls:
                parser = engine.parser
                assert parser is not None
                mock_parser_cls.assert_called_once_with(dialect="postgres")
                assert engine.parser is parser  # Cached

            # Test analyzers lazy load
            with patch("slowql.analyzers.registry.get_registry") as mock_get_reg:
                mock_reg = mock_get_reg.return_value
                mock_reg.get_all.return_value = []
                analyzers = engine.analyzers
                assert isinstance(analyzers, list)
                mock_reg.discover.assert_not_called()  # auto_discover=False

    def test_load_analyzers_auto_discover(self, mock_config):
        with patch("slowql.core.engine.get_registry") as mock_get_reg:
            mock_reg = MagicMock()
            mock_reg.get_all.return_value = [MagicMock(dimension=Dimension.SECURITY)]
            mock_get_reg.return_value = mock_reg

            # Create engine AFTER setting up the mock
            engine = SlowQL(config=mock_config, auto_discover=True)

            # Access the analyzers property to trigger loading
            analyzers = engine.analyzers

            # Verify discover was called
            mock_reg.discover.assert_called_once()
            assert len(analyzers) == 1

    def test_analyze_file_not_found(self, mock_config):
        engine = SlowQL(config=mock_config)
        with pytest.raises(FileNotFoundError):
            engine.analyze_file("nonexistent.sql")

    def test_analyze_files_exception_handling(self, mock_config):
        engine = SlowQL(config=mock_config)

        # SlowQLError is skipped silently — does not raise
        with patch.object(engine, "analyze_file", side_effect=SlowQLError("Slow error")):
            result = engine.analyze_files(["a.sql"])
            assert result is not None

        # Generic Exception is wrapped and raised as ParseError
        with (
            patch.object(engine, "analyze_file", side_effect=ValueError("Generic error")),
            pytest.raises(ParseError),
        ):
            engine.analyze_files(["a.sql"])

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
        # The prefix for "PERF-SCAN-001" is calculated as "PERF-SCAN".
        # This is because `issue.rule_id.split("-")[:2]` results in ["PERF", "SCAN"].
        # So, a config entry of "PERF" would not match. The code expects "PERF-SCAN".
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
        issue2 = MagicMock(rule_id="PERF-SCAN-001")  # prefix PERF-SCAN
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
        analyzer_sec.dimension = Dimension.SECURITY  # value "security"
        assert engine._should_run_analyzer(analyzer_sec) is True

        analyzer_perf = MagicMock()
        analyzer_perf.dimension = Dimension.PERFORMANCE  # value "performance"
        assert engine._should_run_analyzer(analyzer_perf) is False

    def test_analyze_integration_mock(self, mock_config):
        # Test full analyze flow with mocks
        engine = SlowQL(config=mock_config)
        mock_p = MagicMock()
        mock_p.parse.return_value = [MagicMock()]
        engine._parser = mock_p

        with patch.object(engine, "_run_analyzers", return_value=[create_issue()]):
            result = engine.analyze("SELECT 1")
            assert isinstance(result, AnalysisResult)
            assert len(result.issues) == 1
            assert result.statistics.analysis_time_ms > 0

    def test_parse_sql_delegation(self, mock_config):
        engine = SlowQL(config=mock_config)
        mock_p = MagicMock()
        engine._parser = mock_p
        engine._parse_sql("SELECT 1")
        mock_p.parse.assert_called_once()

    def test_run_schema_rules_filters_issues(self, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)
        engine.schema = MagicMock(spec=Schema)

        issue = create_issue(rule_id="SCHEMA-FILTERED-001")
        mock_rule = MagicMock()
        mock_rule.check.return_value = [issue]

        monkeypatch.setattr("slowql.rules.schema.TableExistsRule", lambda _s: mock_rule)
        monkeypatch.setattr("slowql.rules.schema.ColumnExistsRule", lambda _s: MagicMock())
        monkeypatch.setattr("slowql.rules.schema.MissingIndexRule", lambda _s: MagicMock())

        # Mock _should_report_issue to return False
        with patch.object(engine, "_should_report_issue", return_value=False):
            issues = engine._run_schema_rules([MagicMock()])
            assert len(issues) == 0

    def test_schema_property_setter(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)
        mock_schema = MagicMock(spec=Schema)
        engine.schema = mock_schema
        assert engine.schema == mock_schema
        assert engine._schema == mock_schema

    def test_with_schema_path_loads_schema(self, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)
        mock_schema = MagicMock(spec=Schema)

        def mock_load(_path):
            assert _path == "mock.sql"
            return mock_schema

        monkeypatch.setattr(engine, "_load_schema", mock_load)
        returned_engine = engine.with_schema(schema_path="mock.sql")

        assert returned_engine is engine
        assert engine.schema == mock_schema

    def test_analyze_file_reads_file_and_delegates(self, tmp_path, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)
        sql_file = tmp_path / "test.sql"
        sql_content = "SELECT 1;"
        sql_file.write_text(sql_content)

        def mock_analyze(_sql, file_path=None, **_kwargs):
            assert _sql == sql_content
            assert file_path == str(sql_file)
            return AnalysisResult(dialect="postgres")

        monkeypatch.setattr(engine, "analyze", mock_analyze)
        result = engine.analyze_file(sql_file)
        assert isinstance(result, AnalysisResult)

    def test_analyze_files_aggregates_multiple_results(self, tmp_path, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)

        def mock_analyze_file(_path, **_kwargs):
            res = AnalysisResult(dialect="postgres")
            res.queries = [MagicMock()]
            res.add_issue(create_issue())
            res.statistics.parse_time_ms = 10.0
            return res

        monkeypatch.setattr(engine, "analyze_file", mock_analyze_file)

        result = engine.analyze_files(["f1.sql", "f2.sql"])
        assert len(result.queries) == 2
        assert len(result.issues) == 2
        assert result.statistics.parse_time_ms == 20.0

    def test_analyze_files_wraps_unexpected_exception(self, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)

        def mock_analyze_file(_path, **_kwargs):
            raise ValueError("boom")

        monkeypatch.setattr(engine, "analyze_file", mock_analyze_file)

        with pytest.raises(ParseError) as exc:
            engine.analyze_files(["f1.sql"])
        assert "Failed to analyze file: f1.sql" in str(exc.value)
        assert "boom" in str(exc.value.details)

    def test_should_report_issue_with_enabled_rules_prefix_match(self, mock_config):
        mock_config.analysis.enabled_rules = ["SCHEMA-COL"]
        engine = SlowQL(config=mock_config)

        issue = MagicMock(rule_id="SCHEMA-COL-001")
        assert engine._should_report_issue(issue) is True

    def test_should_report_issue_with_disabled_rules_prefix_match(self, mock_config):
        mock_config.analysis.enabled_rules = None
        mock_config.analysis.disabled_rules = ["SCHEMA-COL"]
        engine = SlowQL(config=mock_config)

        issue = MagicMock(rule_id="SCHEMA-COL-001")
        assert engine._should_report_issue(issue) is False

    def test_run_schema_rules_logs_warning_when_rule_fails(self, mock_config, monkeypatch, caplog):
        engine = SlowQL(config=mock_config, auto_discover=False)
        engine.schema = MagicMock(spec=Schema)

        mock_rule = MagicMock()
        mock_rule.id = "FAIL-RULE"
        mock_rule.check.side_effect = Exception("rule failure")

        # Mock the rule classes inside _run_schema_rules
        monkeypatch.setattr("slowql.rules.schema.TableExistsRule", lambda _s: mock_rule)
        monkeypatch.setattr("slowql.rules.schema.ColumnExistsRule", lambda _s: MagicMock())
        monkeypatch.setattr("slowql.rules.schema.MissingIndexRule", lambda _s: MagicMock())

        with caplog.at_level("WARNING"):
            issues = engine._run_schema_rules([MagicMock()])

        assert "Schema rule FAIL-RULE failed: rule failure" in caplog.text
        assert isinstance(issues, list)

    def test_get_rule_info_returns_none_for_unknown_rule(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)
        assert engine.get_rule_info("UNKNOWN-999") is None

    def test_list_rules_returns_rule_metadata(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)

        rule = MagicMock()
        rule.id = "RULE-1"
        rule.name = "Rule One"
        rule.dimension = Dimension.QUALITY

        analyzer = MagicMock()
        analyzer.rules = [rule]

        with patch.object(engine, "_analyzers", [analyzer]):
            engine._analyzers_loaded = True
            rules = engine.list_rules()
            assert len(rules) == 1
            assert rules[0]["id"] == "RULE-1"
            assert rules[0]["name"] == "Rule One"
            assert rules[0]["dimension"] == Dimension.QUALITY

    def test_init_with_schema_arg(self, mock_config):
        mock_schema = MagicMock(spec=Schema)
        engine = SlowQL(config=mock_config, schema=mock_schema)
        assert engine.schema == mock_schema

    def test_init_with_schema_path_arg(self, mock_config, monkeypatch):
        mock_schema = MagicMock(spec=Schema)
        monkeypatch.setattr(SlowQL, "_load_schema", lambda _s, _p: mock_schema)
        engine = SlowQL(config=mock_config, schema_path="path/to/schema.sql")
        assert engine.schema == mock_schema

    def test_init_with_config_schema_fallback(self, mock_config, monkeypatch):
        mock_schema = MagicMock(spec=Schema)
        monkeypatch.setattr(SlowQL, "_load_schema", lambda _s, _p: mock_schema)

        # Mock config with schema.path
        mock_config.schema_config = MagicMock()
        mock_config.schema_config.path = "config/schema.sql"

        # 1. Fallback to config when no explicit args
        engine = SlowQL(config=mock_config)
        assert engine.schema == mock_schema

        # 2. Explicit schema_path overrides config
        mock_schema_explicit = MagicMock(spec=Schema)

        def mock_load_multi(_instance, path):
            if path == "explicit.sql":
                return mock_schema_explicit
            return mock_schema

        monkeypatch.setattr(SlowQL, "_load_schema", mock_load_multi)

        engine2 = SlowQL(config=mock_config, schema_path="explicit.sql")
        assert engine2.schema == mock_schema_explicit

        # 3. Explicit schema object overrides both
        mock_schema_obj = MagicMock(spec=Schema)
        engine3 = SlowQL(config=mock_config, schema=mock_schema_obj, schema_path="ignored.sql")
        assert engine3.schema == mock_schema_obj

    def test_load_schema_delegation(self, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config)
        with patch("slowql.schema.inspector.SchemaInspector.from_ddl_file") as mock_from_ddl:
            mock_from_ddl.return_value = MagicMock(spec=Schema)
            engine._load_schema("path.sql")
            mock_from_ddl.assert_called_once()

    def test_with_schema_null_case(self, mock_config):
        engine = SlowQL(config=mock_config)
        engine.with_schema(schema=None)
        assert engine.schema is None

    def test_run_analyzers_with_real_loop(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)
        analyzer = MagicMock()
        analyzer.dimension = Dimension.QUALITY
        issue = create_issue()
        analyzer.analyze.return_value = [issue]

        with patch.object(engine, "_analyzers", [analyzer]):
            engine._analyzers_loaded = True
            # Exercise _run_analyzers through analyze
            with patch.object(engine, "_parse_sql", return_value=[MagicMock()]):
                result = engine.analyze("SELECT 1")
                assert len(result.issues) == 1

    def test_run_schema_rules_no_schema_returns_empty(self, mock_config):
        engine = SlowQL(config=mock_config)
        # _schema is None by default
        assert engine._run_schema_rules([MagicMock()]) == []

    def test_run_schema_rules_with_reported_issue(self, mock_config, monkeypatch):
        engine = SlowQL(config=mock_config, auto_discover=False)
        engine.schema = MagicMock(spec=Schema)

        issue = create_issue(rule_id="SCHEMA-TEST-001")

        mock_rule = MagicMock()
        mock_rule.id = "SCHEMA-TEST"
        mock_rule.check.return_value = [issue]

        monkeypatch.setattr("slowql.rules.schema.TableExistsRule", lambda _s: mock_rule)
        monkeypatch.setattr("slowql.rules.schema.ColumnExistsRule", lambda _s: MagicMock())
        monkeypatch.setattr("slowql.rules.schema.MissingIndexRule", lambda _s: MagicMock())

        # Ensure it should be reported
        mock_config.analysis.enabled_rules = ["SCHEMA-TEST"]

        issues = engine._run_schema_rules([MagicMock()])
        assert len(issues) == 1
        assert issues[0] == issue

    def test_parser_property_lazy_load(self, mock_config):
        engine = SlowQL(config=mock_config)
        # First access
        with patch("slowql.core.engine.UniversalParser") as mock_parser:
            p1 = engine.parser
            mock_parser.assert_called_once()
            # Second access (cached)
            p2 = engine.parser
            assert p1 is p2
            assert mock_parser.call_count == 1

    def test_with_schema_direct(self, mock_config):
        engine = SlowQL(config=mock_config)
        mock_schema = MagicMock(spec=Schema)
        engine.with_schema(schema=mock_schema)
        assert engine.schema == mock_schema

    def test_run_analyzers_skips_disabled(self, mock_config):
        mock_config.analysis.enabled_dimensions = ["security"]
        engine = SlowQL(config=mock_config, auto_discover=False)
        analyzer = MagicMock()
        analyzer.dimension = Dimension.QUALITY # Should be skipped

        with patch.object(engine, "_analyzers", [analyzer]):
            engine._analyzers_loaded = True
            issues = engine._run_analyzers([MagicMock()])
            assert len(issues) == 0
            analyzer.analyze.assert_not_called()

    def test_run_analyzers_triggers_schema_rules(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)
        engine.schema = MagicMock(spec=Schema)

        with patch.object(engine, "_run_schema_rules", return_value=[create_issue()]) as mock_schema_rules:
            issues = engine._run_analyzers([MagicMock()])
            assert len(issues) == 1
            mock_schema_rules.assert_called_once()

    def test_run_analyzers_filters_issues(self, mock_config):
        engine = SlowQL(config=mock_config, auto_discover=False)
        analyzer = MagicMock()
        analyzer.dimension = Dimension.QUALITY
        issue = create_issue(rule_id="FILTERED")
        analyzer.analyze.return_value = [issue]

        # Mock _should_report_issue to return False
        with (
            patch.object(engine, "_should_report_issue", return_value=False),
            patch.object(engine, "_analyzers", [analyzer]),
        ):
            engine._analyzers_loaded = True
            issues = engine._run_analyzers([MagicMock()])
            assert len(issues) == 0


def create_issue(rule_id="TEST"):
    return Issue(
        rule_id=rule_id,
        message="Msg",
        severity=Severity.LOW,
        dimension=Dimension.QUALITY,
        location=Location(1, 1),
        snippet="",
    )
