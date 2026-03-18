from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from slowql.cli import app
from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Query, Severity


def _issue(rule_id: str = "TEST-001", severity: Severity = Severity.HIGH) -> Issue:
    return Issue(
        rule_id=rule_id,
        message="test issue",
        severity=severity,
        dimension=Dimension.SECURITY,
        location=Location(line=1, column=1),
        snippet="SELECT 1",
    )


def _result(with_issue: bool = False) -> AnalysisResult:
    r = AnalysisResult()
    if with_issue:
        r.add_issue(_issue())
    return r


def _query(sql: str = "SELECT 1") -> Query:
    return Query(
        raw=sql,
        normalized=sql,
        dialect="postgresql",
        location=Location(line=1, column=1),
        query_type="SELECT",
    )


class TestPromptDialect:
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_prompt_dialect_numeric_selects_postgresql(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "1"
        assert app.prompt_dialect() == "postgresql"

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_prompt_dialect_numeric_selects_universal(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "15"
        assert app.prompt_dialect() is None

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_prompt_dialect_name_match(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "mysql"
        assert app.prompt_dialect() == "mysql"

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_prompt_dialect_invalid_returns_none(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "garbage"
        assert app.prompt_dialect() is None


class TestRunAnalysis:
    @patch("slowql.cli.app.console")
    def test_run_analysis_cache_hit_non_machine_readable(self, mock_console):
        cache = app.QueryCache()
        cached = _result(with_issue=True)
        cache.set("SELECT 1", cached)
        engine = MagicMock()
        out = app._run_analysis("SELECT 1", engine, cache, fast=True, machine_readable=False)
        assert out is cached
        mock_console.print.assert_called()

    def test_run_analysis_machine_readable_no_cache(self):
        engine = MagicMock()
        result = _result(with_issue=True)
        engine.analyze.return_value = result
        out = app._run_analysis("SELECT 1", engine, None, fast=True, machine_readable=True)
        assert out is result
        engine.analyze.assert_called_once_with("SELECT 1")

    @patch("slowql.cli.app.AnimatedAnalyzer")
    @patch("slowql.cli.app.Progress")
    def test_run_analysis_non_machine_readable_runs_engine(self, mock_progress, _mock_anim):
        engine = MagicMock()
        result = _result(with_issue=True)
        engine.analyze.return_value = result
        progress_cm = MagicMock()
        progress_cm.__enter__.return_value = progress_cm
        progress_cm.__exit__.return_value = None
        progress_cm.add_task.return_value = 1
        mock_progress.return_value = progress_cm

        out = app._run_analysis("SELECT 1", engine, None, fast=True, machine_readable=False)
        assert out is result
        engine.analyze.assert_called_once_with("SELECT 1")


class TestShowIntro:
    @patch("slowql.cli.app.console")
    def test_show_intro_machine_readable_returns_none(self, _mock_console):
        assert app._show_intro(False, True, False, 0.1, machine_readable=True) is None

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    def test_show_intro_with_intro_disabled_returns_none(self, _mock_rain, mock_console):
        out = app._show_intro(False, True, False, 0.1, machine_readable=False)
        assert out is None
        mock_console.print.assert_called()

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    def test_show_intro_with_intro_enabled(self, mock_rain, mock_console):
        rain = MagicMock()

        def _run(*_args, **_kwargs):
            rain._selected_dialect = "postgresql"

        rain.run.side_effect = _run
        mock_rain.return_value = rain

        out = app._show_intro(True, False, True, 0.1, machine_readable=False)

        assert out == "postgresql"
        rain.run.assert_called_once()
        mock_console.print.assert_called()


class TestHandleSqlInput:
    @patch("slowql.cli.app.console")
    def test_handle_sql_input_dir_no_files(self, mock_console, tmp_path):
        d = tmp_path / "sqls"
        d.mkdir()
        payload, cont = app._handle_sql_input(
            first_run=True,
            input_files=[d],
            non_interactive=False,
            mode="auto",
            is_tty=False,
            engine=MagicMock(),
            enable_comparison=False,
        )
        assert payload is None
        assert cont is True
        mock_console.print.assert_called()

    @patch("slowql.cli.app.console")
    def test_handle_sql_input_dir_empty_files(self, mock_console, tmp_path):
        d = tmp_path / "sqls"
        d.mkdir()
        (d / "a.sql").write_text("\n  \n", encoding="utf-8")
        payload, cont = app._handle_sql_input(
            first_run=True,
            input_files=[d],
            non_interactive=False,
            mode="auto",
            is_tty=False,
            engine=MagicMock(),
            enable_comparison=False,
        )
        assert payload is None
        assert cont is True
        mock_console.print.assert_called()

    @patch("slowql.cli.app.console")
    def test_handle_sql_input_dir_multiple_files_joins_statements(self, _mock_console, tmp_path):
        d = tmp_path / "sqls"
        d.mkdir()
        (d / "a.sql").write_text("SELECT 1", encoding="utf-8")
        (d / "b.sql").write_text("SELECT 2;", encoding="utf-8")
        payload, cont = app._handle_sql_input(
            first_run=True,
            input_files=[d],
            non_interactive=False,
            mode="auto",
            is_tty=False,
            engine=MagicMock(),
            enable_comparison=False,
        )
        assert cont is False
        assert payload is not None
        assert "SELECT 1;" in payload
        assert "SELECT 2;" in payload

    def test_handle_sql_input_non_interactive_no_files_breaks(self):
        payload, cont = app._handle_sql_input(
            first_run=False,
            input_files=None,
            non_interactive=True,
            mode="auto",
            is_tty=False,
            engine=MagicMock(),
            enable_comparison=False,
        )
        assert payload is None
        assert cont is False


class TestLoopEnd:
    @patch("slowql.cli.app.console")
    def test_handle_loop_end_non_interactive_exports_session(self, mock_console, tmp_path):
        session = app.SessionManager()
        session._machine_readable = False
        result = app._handle_loop_end(
            non_interactive=True,
            result=_result(with_issue=True),
            out_dir=tmp_path,
            session=session,
            export_session_history=True,
        )
        assert result is False
        mock_console.print.assert_called()

    @patch("slowql.cli.app.show_quick_actions_menu", return_value=False)
    def test_handle_loop_end_interactive_exit(self, _mock_menu, tmp_path):
        session = app.SessionManager()
        result = app._handle_loop_end(
            non_interactive=False,
            result=_result(with_issue=True),
            out_dir=tmp_path,
            session=session,
            export_session_history=False,
        )
        assert result is False


class TestInteractiveMenus:
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.HAVE_READCHAR", False)
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_fallback_export(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "1"
        with patch("slowql.cli.app.export_interactive") as mock_export:
            out = app.show_quick_actions_menu(_result(with_issue=True), None, Path("reports"))
            assert out is True
            mock_export.assert_called_once()

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.HAVE_READCHAR", False)
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_fallback_continue(self, mock_prompt, _mock_console):
        mock_prompt.ask.return_value = "2"
        out = app.show_quick_actions_menu(_result(with_issue=True), None, Path("reports"))
        assert out is True

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.HAVE_READCHAR", False)
    @patch("slowql.cli.app.Prompt")
    def test_export_interactive_fallback(self, mock_prompt, _mock_console, tmp_path):
        mock_prompt.ask.return_value = "1"
        with patch("slowql.cli.app._run_exports") as mock_exports:
            app.export_interactive(_result(with_issue=True), tmp_path)
            mock_exports.assert_called_once()


class TestRuleCommands:
    @patch("slowql.cli.app.console")
    def test_cmd_list_rules_no_match(self, mock_console):
        code = app._cmd_list_rules(dimension="security", dialect="sqlite")
        assert code == 0
        mock_console.print.assert_called()

    @patch("slowql.cli.app.console")
    def test_cmd_explain_unknown_with_prefix_suggestions(self, mock_console):
        code = app._cmd_explain("PERF-DOES-NOT-EXIST")
        assert code == 1
        mock_console.print.assert_called()

    @patch("slowql.cli.app.console")
    def test_cmd_explain_rule_with_tags_branch(self, mock_console):
        code = app._cmd_explain("PERF-SCAN-001")
        assert code == 0
        mock_console.print.assert_called()


class TestMainNewBranches:
    @patch("slowql.cli.app._cmd_list_rules", return_value=0)
    @patch("slowql.cli.app.build_argparser")
    def test_main_list_rules_branch(self, mock_build, mock_cmd):
        parser = MagicMock()
        args = MagicMock()
        args.list_rules = True
        args.explain = None
        args.init = False
        args.filter_dimension = "security"
        args.filter_dialect = None
        parser.parse_args.return_value = args
        mock_build.return_value = parser
        assert app.main([]) == 0
        mock_cmd.assert_called_once_with(dimension="security", dialect=None)

    @patch("slowql.cli.app._cmd_explain", return_value=0)
    @patch("slowql.cli.app.build_argparser")
    def test_main_explain_branch(self, mock_build, mock_cmd):
        parser = MagicMock()
        args = MagicMock()
        args.list_rules = False
        args.explain = "PERF-SCAN-001"
        args.init = False
        parser.parse_args.return_value = args
        mock_build.return_value = parser
        assert app.main([]) == 0
        mock_cmd.assert_called_once_with("PERF-SCAN-001")

    @patch("slowql.cli.app._cmd_init", return_value=0)
    @patch("slowql.cli.app.build_argparser")
    def test_main_init_branch(self, mock_build, mock_cmd):
        parser = MagicMock()
        args = MagicMock()
        args.list_rules = False
        args.explain = None
        args.init = True
        parser.parse_args.return_value = args
        mock_build.return_value = parser
        assert app.main([]) == 0
        mock_cmd.assert_called_once()

    @patch("slowql.cli.app.build_argparser")
    def test_main_fix_missing_file_errors(self, mock_build):
        parser = MagicMock()
        args = MagicMock()
        args.list_rules = False
        args.explain = None
        args.init = False
        args.input_file = None
        args.file = None
        args.extra_files = []
        args.no_intro = False
        args.duration = 3.0
        args.mode = "auto"
        args.export = None
        args.out = Path("reports")
        args.fast = False
        args.verbose = False
        args.non_interactive = False
        args.no_cache = False
        args.compare = False
        args.schema = None
        args.dialect = None
        args.diff = False
        args.fix = True
        args.export_session = False
        args.format = "console"
        args.fail_on = None
        args.fix_report = None
        parser.parse_args.return_value = args
        mock_build.return_value = parser
        parser.error.side_effect = RuntimeError("parser-error")
        with pytest.raises(RuntimeError):
            app.main([])
        parser.error.assert_called()
