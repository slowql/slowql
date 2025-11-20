# tests/unit/test_analyzer.py
import pytest
import pandas as pd
from slowql.core.analyzer import QueryAnalyzer
from slowql.core.detector import IssueSeverity, DetectedIssue

class TestAnalyzer:
    def test_initialization(self):
        analyzer = QueryAnalyzer(verbose=False)
        assert analyzer.verbose == False
        assert analyzer._issue_stats == {}
        
    def test_analyze_single_query(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        assert isinstance(results, pd.DataFrame)
        assert not results.empty
        assert 'issue' in results.columns
        
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
        
    def test_stats_tracking(self, analyzer):
        analyzer.analyze("SELECT * FROM users")
        stats = analyzer.get_summary_stats()
        assert stats['total_issues_detected'] > 0
        assert 'SELECT * Usage' in stats['issue_breakdown']
        
    def test_empty_query_handling(self, analyzer):
        results = analyzer.analyze("")
        assert results.empty
        
    def test_multiple_identical_issues(self, analyzer):
        queries = ["SELECT * FROM users"] * 5
        results = analyzer.analyze(queries)
        assert results['count'].iloc[0] == 5
        
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
        
    def test_export_json(self, analyzer, tmp_path):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, 'json', str(tmp_path / "test.json"))
        assert filepath.endswith('.json')
        
    def test_export_csv(self, analyzer, tmp_path):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, 'csv', str(tmp_path / "test.csv"))
        assert filepath.endswith('.csv')
        
    def test_export_invalid_format(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        with pytest.raises(ValueError):
            analyzer.export_report(results, 'invalid')
            
    def test_suggest_indexes(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users WHERE UPPER(email) = 'TEST'")
        suggestions = analyzer.suggest_indexes(results)
        assert len(suggestions) > 0
        
    def test_compare_queries(self, analyzer):
        comparison = analyzer.compare_queries(
            "SELECT * FROM users",
            "SELECT id, name FROM users"
        )
        assert comparison['improvement_percentage'] > 0
        
    def test_severity_sorting(self, analyzer):
        # Create query that triggers multiple severities
        queries = [
            "DELETE FROM users",  # CRITICAL
            "SELECT * FROM users"  # MEDIUM
        ]
        results = analyzer.analyze(queries)
        # Critical should be listed first in reports
        assert results.iloc[0]['severity'] in ['critical', 'high']

    def test_export_auto_filename(self, analyzer):
        results = analyzer.analyze("SELECT * FROM users")
        filepath = analyzer.export_report(results, 'json')  # No filename!
        assert 'sql_analysis_' in filepath

    def test_suggest_indexes_empty(self, analyzer):
        empty_df = pd.DataFrame()
        suggestions = analyzer.suggest_indexes(empty_df)
        assert suggestions == []

    def test_compare_identical_queries(self, analyzer):
        result = analyzer.compare_queries("SELECT id FROM users", "SELECT id FROM users")
        assert result['improvement_percentage'] == 0
