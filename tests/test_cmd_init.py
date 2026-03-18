"""Tests for slowql init command."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from slowql.cli.app import _cmd_init


class TestCmdInit:
    def test_creates_config_file(self, tmp_path, monkeypatch):
        """Init creates slowql.yaml in current directory."""
        monkeypatch.chdir(tmp_path)
        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "2"]
            result = _cmd_init()

        assert result == 0
        assert (tmp_path / "slowql.yaml").exists()

    def test_config_has_valid_yaml(self, tmp_path, monkeypatch):
        """Generated config is valid YAML."""
        import yaml
        monkeypatch.chdir(tmp_path)
        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["1", "2"]
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert "severity" in config
        assert "analysis" in config
        assert config["severity"]["fail_on"] == "high"
        assert config["analysis"]["dialect"] == "postgresql"

    def test_auto_detect_dialect(self, tmp_path, monkeypatch):
        """Selecting auto-detect omits dialect from config."""
        import yaml
        monkeypatch.chdir(tmp_path)
        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "2"]
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert "dialect" not in config.get("analysis", {})

    def test_overwrite_aborted(self, tmp_path, monkeypatch):
        """Init aborts when user declines overwrite."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "slowql.yaml").write_text("existing: true")

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["n"]
            result = _cmd_init()

        assert result == 1
        assert (tmp_path / "slowql.yaml").read_text() == "existing: true"

    def test_overwrite_accepted(self, tmp_path, monkeypatch):
        """Init overwrites when user confirms."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "slowql.yaml").write_text("existing: true")

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["y", "15", "2"]
            result = _cmd_init()

        assert result == 0
        assert (tmp_path / "slowql.yaml").read_text() != "existing: true"

    def test_detects_sql_files(self, tmp_path, monkeypatch):
        """Init detects .sql files in directory."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "queries.sql").write_text("SELECT 1;")
        (tmp_path / "migrations.sql").write_text("CREATE TABLE t (id INT);")

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "2"]
            result = _cmd_init()

        assert result == 0

    def test_detects_schema_file(self, tmp_path, monkeypatch):
        """Init detects schema.sql and adds to config."""
        import yaml
        monkeypatch.chdir(tmp_path)
        (tmp_path / "schema.sql").write_text("CREATE TABLE users (id INT);")

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "2"]
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert "schema" in config
        assert config["schema"]["path"] == "schema.sql"

    def test_threshold_selection(self, tmp_path, monkeypatch):
        """Init respects threshold selection."""
        import yaml
        monkeypatch.chdir(tmp_path)

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "1"]  # critical threshold
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert config["severity"]["fail_on"] == "critical"

    def test_mysql_dialect_selection(self, tmp_path, monkeypatch):
        """Init sets MySQL dialect correctly."""
        import yaml
        monkeypatch.chdir(tmp_path)

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["2", "2"]  # MySQL, high
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert config["analysis"]["dialect"] == "mysql"

    def test_output_format_is_text(self, tmp_path, monkeypatch):
        """Generated config uses valid format value."""
        import yaml
        monkeypatch.chdir(tmp_path)

        with patch("slowql.cli.app.HAVE_READCHAR", False), patch("slowql.cli.app.Prompt") as mock_prompt:
            mock_prompt.ask.side_effect = ["15", "2"]
            _cmd_init()

        config = yaml.safe_load((tmp_path / "slowql.yaml").read_text())
        assert config["output"]["format"] == "text"


class TestCmdListRulesFilters:
    """Additional filter tests for list-rules."""

    def test_filter_by_dialect_postgresql(self) -> None:
        from slowql.cli.app import _cmd_list_rules
        assert _cmd_list_rules(dialect="postgresql") == 0

    def test_filter_by_dialect_tsql(self) -> None:
        from slowql.cli.app import _cmd_list_rules
        assert _cmd_list_rules(dialect="tsql") == 0

    def test_filter_dimension_and_dialect(self) -> None:
        from slowql.cli.app import _cmd_list_rules
        assert _cmd_list_rules(dimension="security", dialect="tsql") == 0

    def test_no_results_filter(self) -> None:
        from slowql.cli.app import _cmd_list_rules
        # sqlite has no compliance rules
        assert _cmd_list_rules(dimension="compliance", dialect="sqlite") == 0


class TestCmdExplainMore:
    """Additional explain tests."""

    def test_explain_dialect_rule(self) -> None:
        from slowql.cli.app import _cmd_explain
        assert _cmd_explain("SEC-MYSQL-001") == 0

    def test_explain_with_impact(self) -> None:
        from slowql.cli.app import _cmd_explain
        assert _cmd_explain("REL-DATA-001") == 0

    def test_explain_unknown_prefix(self) -> None:
        from slowql.cli.app import _cmd_explain
        assert _cmd_explain("ZZZZZ-001") == 1


class TestUtilityFunctions:
    """Test utility functions in app.py."""

    def test_session_manager_init(self) -> None:
        from slowql.cli.app import SessionManager
        s = SessionManager()
        assert s.queries_analyzed == 0
        assert s.total_issues == 0

    def test_session_manager_duration(self) -> None:
        from slowql.cli.app import SessionManager
        s = SessionManager()
        d = s.get_session_duration()
        assert "s" in d

    def test_query_cache(self) -> None:
        from slowql.cli.app import QueryCache
        c = QueryCache()
        assert c.get("SELECT 1") is None
        c.clear()

    def test_safe_path(self) -> None:
        from slowql.cli.app import safe_path
        p = safe_path(None)
        assert isinstance(p, Path)

    def test_safe_path_with_value(self) -> None:
        from slowql.cli.app import safe_path
        p = safe_path(Path("/tmp/reports"))
        assert isinstance(p, Path)

    def test_ensure_reports_dir(self, tmp_path) -> None:
        from slowql.cli.app import ensure_reports_dir
        d = tmp_path / "new_reports"
        result = ensure_reports_dir(d)
        assert result.exists()

    def test_is_machine_readable_format(self) -> None:
        from slowql.cli.app import _is_machine_readable_format
        assert _is_machine_readable_format("sarif") is True
        assert _is_machine_readable_format("github-actions") is True
        assert _is_machine_readable_format("console") is False

    def test_init_cli(self) -> None:
        from slowql.cli.app import init_cli
        init_cli(machine_readable=True)
        init_cli(machine_readable=False)

    def test_compute_fail_exit_code(self) -> None:
        from slowql.cli.app import _compute_fail_exit_code
        from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity

        result = AnalysisResult()
        assert _compute_fail_exit_code(result, None) == 0
        assert _compute_fail_exit_code(result, "never") == 0

        result.add_issue(Issue(
            rule_id="TEST-001",
            message="test",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            location=Location(line=1, column=1),
            snippet="test",
        ))
        assert _compute_fail_exit_code(result, "high") == 2
        assert _compute_fail_exit_code(result, "critical") == 0

    def test_session_manager_add_analysis(self) -> None:
        from slowql.cli.app import SessionManager
        from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity

        s = SessionManager()
        result = AnalysisResult()
        result.add_issue(Issue(
            rule_id="TEST-001",
            message="test",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            location=Location(line=1, column=1),
            snippet="test",
        ))
        s.add_analysis(result)
        assert s.total_issues == 1
        assert s.severity_breakdown["high"] == 1

    def test_session_manager_export(self, tmp_path) -> None:
        from slowql.cli.app import SessionManager
        s = SessionManager()
        path = s.export_session(tmp_path / "session.json")
        assert path.exists()

    def test_query_cache_set_and_get(self) -> None:
        from slowql.cli.app import QueryCache
        from slowql.core.models import AnalysisResult

        c = QueryCache()
        result = AnalysisResult()
        c.set("SELECT 1", result)
        assert c.get("SELECT 1") is not None
        assert c.get("SELECT 2") is None
