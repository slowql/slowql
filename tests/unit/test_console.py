import pandas as pd
import pytest
from slowql.formatters.console import ConsoleFormatter

@pytest.fixture
def formatter():
    return ConsoleFormatter()

@pytest.fixture
def sample_results():
    return pd.DataFrame([
        {
            "severity": "critical",
            "issue": "SELECT * Usage",
            "query": "SELECT * FROM users",
            "fix": "Use explicit column names",
            "impact": "Slower queries, harder to optimize",
            "count": 3
        },
        {
            "severity": "high",
            "issue": "Missing WHERE in DELETE",
            "query": "DELETE FROM users",
            "fix": "Add WHERE clause",
            "impact": "Risk of full table deletion",
            "count": 2
        },
        {
            "severity": "medium",
            "issue": "Non-SARGable WHERE",
            "query": "SELECT * FROM users WHERE YEAR(created_at)=2023",
            "fix": "Rewrite WHERE clause for index use",
            "impact": "Query cannot use index",
            "count": 1
        },
        {
            "severity": "low",
            "issue": "LIKE without Wildcards",
            "query": "SELECT * FROM users WHERE name LIKE 'John'",
            "fix": "Use wildcards in LIKE",
            "impact": "May miss partial matches",
            "count": 1
        }
    ])

def test_format_analysis_full(formatter, sample_results):
    formatter.format_analysis(sample_results)

def test_format_analysis_empty(formatter):
    empty_df = pd.DataFrame(columns=["severity", "issue", "query", "fix", "impact", "count"])
    formatter.format_analysis(empty_df)

def test_format_comparison(formatter):
    formatter.format_comparison(before_count=10, after_count=4)

def test_export_html_report(formatter, sample_results, tmp_path):
    path = tmp_path / "report.html"
    output = formatter.export_html_report(sample_results, str(path))
    assert output.endswith(".html")
    assert path.exists()

def test_show_health_gauge(formatter, sample_results):
    score = formatter._calculate_health_score(sample_results)
    formatter._show_health_gauge(score, sample_results)

def test_show_severity_distribution(formatter, sample_results):
    formatter._show_severity_distribution(sample_results)

def test_show_issues_table_v2(formatter, sample_results):
    formatter._show_issues_table_v2(sample_results)

def test_show_summary_stats(formatter, sample_results):
    formatter._show_summary_stats(sample_results)

def test_show_next_steps(formatter, sample_results):
    formatter._show_next_steps(sample_results)

def test_show_clean_report(formatter):
    formatter._show_clean_report()

def test_create_stats_panel(formatter, sample_results):
    panel = formatter._create_stats_panel(sample_results)
    assert panel is not None

def test_show_issues_table_future(formatter, sample_results):
    formatter._show_issues_table_future(sample_results)

def test_show_frequency_viz(formatter, sample_results):
    formatter._show_frequency_viz(sample_results)

def test_show_recommendations_panel(formatter, sample_results):
    formatter._show_recommendations_panel(sample_results)

def test_show_issues_table_legacy(formatter, sample_results):
    formatter._show_issues_table(sample_results)

def test_show_recommendations_panel(formatter, sample_results):
    formatter._show_recommendations_panel(sample_results)

def test_show_frequency_viz_empty(formatter):
    empty_df = pd.DataFrame(columns=["issue", "count"])
    formatter._show_frequency_viz(empty_df)

def test_show_issues_table_truncation(formatter):
    long_query = "SELECT * FROM users WHERE " + "x = 1 AND " * 20
    results = pd.DataFrame([{
        "severity": "high",
        "issue": "Long Query Test",
        "query": long_query,
        "fix": "Shorten query",
        "impact": "Hard to read",
        "count": 1
    }])
    formatter._show_issues_table(results)

def test_show_issues_table_future_truncation(formatter):
    long_impact = "This impact description is extremely long and should be truncated for display..." * 3
    results = pd.DataFrame([{
        "severity": "high",
        "issue": "Impact Truncation",
        "query": "SELECT * FROM users",
        "fix": "Fix it",
        "impact": long_impact,
        "count": 1
    }])
    formatter._show_issues_table_future(results)
