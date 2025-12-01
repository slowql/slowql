# tests/unit/test_analyzer.py
import pytest
import pandas as pd
from slowql.core.analyzer import QueryAnalyzer
from slowql.core.detector import DetectedIssue

class TestAnalyzer:
    # -------------------------------
    # Initialization & Basics
    # -------------------------------
    def test_initialization(self):
        analyzer = QueryAnalyzer(verbose=False)
        assert analyzer.verbose is False
        assert analyzer._issue_stats == {}

    def test_analyze_single_query_dataframe(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        assert isinstance(results, pd.DataFrame)
        assert not results.empty
        assert "issue" in results.columns

    def test_analyze_clean_query(self, analyzer):
        results = analyzer.analyze("SELECT id FROM users WHERE id = 1")
        assert results.empty

    def test_analyze_list_of_queries(self, analyzer):
        queries = ["SELECT * FROM users", "DELETE FROM orders"]
        results = analyzer.analyze(queries)
        assert len(results) >= 2

    def test_return_list_format(self, analyzer):
        issues = analyzer.analyze("SELECT * FROM users", return_dataframe=False)
        assert isinstance(issues, list)
        assert all(isinstance(i, DetectedIssue) for i in issues)

    def test_verbose_output(self, capsys):
        analyzer = QueryAnalyzer(verbose=True)
        analyzer.analyze("SELECT * FROM users")
        captured = capsys.readouterr()
        assert "Analyzing SQL queries" in captured.out

    # -------------------------------
    # Stats & Summary
    # -------------------------------
    def test_stats_tracking(self, analyzer):
        analyzer.analyze("SELECT * FROM users")
        stats = analyzer.get_summary_stats()
        assert stats["total_issues_detected"] > 0
        assert "SELECT * Usage" in stats["issue_breakdown"]

    def test_summary_stats_empty(self, analyzer):
        stats = analyzer.get_summary_stats()
        assert isinstance(stats, dict)
        assert "total_issues_detected" in stats

    # -------------------------------
    # Parallel Analysis
    # -------------------------------
    def test_analyze_parallel(self, analyzer):
        queries = ["SELECT * FROM users", "DELETE FROM orders"]
        results = analyzer.analyze_parallel(queries, return_dataframe=True)
        assert isinstance(results, pd.DataFrame)
        assert not results.empty

    def test_analyze_parallel_list(self, analyzer):
        queries = ["SELECT * FROM users", "DELETE FROM orders"]
        issues = analyzer.analyze_parallel(queries, return_dataframe=False)
        assert isinstance(issues, list)
        assert all(isinstance(i, DetectedIssue) for i in issues)

    # -------------------------------
    # DataFrame Conversion
    # -------------------------------
    def test_multiple_identical_issues(self, analyzer):
        queries = ["SELECT * FROM users"] * 5
        results = analyzer.analyze(queries)
        assert results["count"].iloc[0] == 5

    def test_to_dataframe_empty(self, analyzer):
        df = analyzer._to_dataframe([])
        assert df.empty

    # -------------------------------
    # Reporting
    # -------------------------------
    def test_print_report_empty(self, analyzer, capsys):
        empty_df = pd.DataFrame()
        analyzer.print_report(empty_df)
        captured = capsys.readouterr()
        assert "No SQL issues detected" in captured.out

    def test_print_report_with_issues(self, analyzer, capsys):
        results = analyzer.analyze("DELETE FROM users")
        analyzer.print_report(results)
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_print_report_multiple_occurrences(self, analyzer, capsys):
        queries = ["DELETE FROM users"] * 3
        results = analyzer.analyze(queries)
        analyzer.print_report(results)
        captured = capsys.readouterr()
        assert "Occurrences: 3" in captured.out


    # -------------------------------
    # Export
    # -------------------------------
    def test_export_json(self, analyzer, tmp_path):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, "json", str(tmp_path / "test.json"))
        assert filepath.endswith(".json")

    def test_export_csv(self, analyzer, tmp_path):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, "csv", str(tmp_path / "test.csv"))
        assert filepath.endswith(".csv")

    def test_export_html(self, analyzer, tmp_path):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, "html", str(tmp_path / "test.html"))
        assert filepath.endswith(".html")

    def test_export_invalid_format(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        with pytest.raises(ValueError):
            analyzer.export_report(results, "invalid")

    def test_export_auto_filename(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, "json")  # No filename
        assert "sql_analysis_" in filepath

    # -------------------------------
    # Index Suggestions
    # -------------------------------
    def test_suggest_indexes(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users WHERE UPPER(email) = 'TEST'")
        suggestions = analyzer.suggest_indexes(results)
        assert any("Functional index" in s or "CREATE INDEX" in s for s in suggestions)

    def test_suggest_indexes_empty(self, analyzer):
        empty_df = pd.DataFrame()
        suggestions = analyzer.suggest_indexes(empty_df)
        assert suggestions == []

    def test_suggest_indexes_no_where_clause(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        suggestions = analyzer.suggest_indexes(results)
        assert any("No WHERE clause" in s for s in suggestions)

    @pytest.mark.parametrize("query,expected", [
    ("SELECT * FROM users", "No WHERE clause"),
    ("SELECT * FROM users WHERE UPPER(email) = 'x'", "Functional index"),
    ("SELECT * FROM users WHERE id = 1 JOIN orders ON users.id = orders.user_id", "JOIN operations"),
    ("SELECT * FROM users WHERE id = 1 ORDER BY name", "ORDER BY clause"),
    ("SELECT * FROM users WHERE id = 1 GROUP BY name", "GROUP BY clause"),
    ])
    def test_suggest_indexes_branches(self, analyzer, query, expected):
        results = analyzer.analyze(query)
        suggestions = analyzer.suggest_indexes(results)
        assert any(expected in s for s in suggestions)




    # -------------------------------
    # Query Comparison
    # -------------------------------
    def test_compare_queries_improvement(self, analyzer):
        comparison = analyzer.compare_queries(
            "SELECT * FROM users",
            "SELECT id, name FROM users"
        )
        assert comparison["improvement_percentage"] > 0

    def test_compare_queries_no_improvement(self, analyzer):
        comparison = analyzer.compare_queries(
            "SELECT id FROM users",
            "SELECT id FROM users"
        )
        assert comparison["improvement_percentage"] == 0

    def test_compare_queries_negative_improvement(self, analyzer):
        comparison = analyzer.compare_queries(
            "SELECT id FROM users",
            "SELECT * FROM users"
        )
        assert comparison["improvement_percentage"] <= 0
        assert "SELECT * Usage" in comparison["remaining_issues"]
