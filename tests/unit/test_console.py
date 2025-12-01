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
    results = pd.DataFrame([{
        "severity": "high",
        "issue": "Impact Truncation",
        "query": "SELECT * FROM users",
        "fix": "Fix it",
        "impact": "This impact description is extremely long and should be truncated for display..." * 3,
        "count": 1
    }])
    formatter._show_issues_table_future(results)

def test_show_progress(formatter):
    progress = formatter.show_progress("Analyzing queries")
    assert progress is not None

def test_print_analysis_function(sample_results):
    from slowql.formatters.console import print_analysis
    print_analysis(sample_results)

def test_show_single_issue(formatter):
    from slowql.core.detector import DetectedIssue, IssueSeverity
    issue = DetectedIssue(
        issue_type="SELECT * Usage",
        query="SELECT * FROM users",
        description="Using SELECT * is inefficient",
        fix="Specify columns explicitly",
        impact="Slower queries and harder to optimize",
        severity=IssueSeverity.CRITICAL
    )
    formatter.show_single_issue(issue)

def test_show_next_steps_fallback(formatter):
    df = pd.DataFrame([{
        "severity": "low",
        "issue": "Minor Formatting",
        "query": "SELECT * FROM users",
        "fix": "Use consistent casing",
        "impact": "Minor readability issue",
        "count": 1
    }])
    formatter._show_next_steps(df)

def test_show_health_gauge_red_zone(formatter):
    df = pd.DataFrame([{
        "severity": "critical",
        "issue": "Massive IN List",
        "query": "SELECT * FROM users WHERE id IN (...)",
        "fix": "Use JOIN instead",
        "impact": "Memory overload",
        "count": 10
    }])
    score = formatter._calculate_health_score(df)
    assert score < 40
    formatter._show_health_gauge(score, df)


def test_show_recommendations_panel_fallback(formatter):
    df = pd.DataFrame([{
        "severity": "low",
        "issue": "Minor Formatting",
        "query": "SELECT * FROM users",
        "fix": "Use consistent casing",
        "impact": "Minor readability issue",
        "count": 1
    }])
    formatter._show_recommendations_panel(df)
