# tests/unit/test_cli_components.py
"""
Test CLI components.
"""

from slowql.cli import app
from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.models import AnalysisResult, Issue, Severity, Dimension, Location


def test_cli_app_structure():
    """Test that CLI app has expected structure."""
    assert hasattr(app, 'main')
    assert callable(app.main)


def test_config_loading():
    """Test config loading in CLI context."""
    config = Config()
    assert config is not None
    assert config.analysis is not None
    assert config.output is not None


def test_engine_creation():
    """Test engine creation with config."""
    config = Config()
    engine = SlowQL(config=config)
    assert engine is not None
    assert engine.config is config


def test_result_formatting():
    """Test result formatting components."""
    # Create a result with issues
    loc = Location(line=1, column=1, file="test.sql")
    issue = Issue(
        rule_id="TEST-001",
        message="Test issue",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=loc,
        snippet="SELECT *"
    )
    result = AnalysisResult()
    result.add_issue(issue)

    # Test that result has expected properties
    assert len(result.issues) == 1
    assert result.statistics.total_issues == 1
    assert result.exit_code == 1  # LOW/MEDIUM issues


def test_severity_formatting():
    """Test severity display formatting."""
    severity = Severity.CRITICAL
    assert severity.emoji == "💀"
    assert severity.color == "bold red"

    severity = Severity.HIGH
    assert severity.emoji == "🔥"
    assert severity.color == "red"


def test_dimension_formatting():
    """Test dimension display formatting."""
    dimension = Dimension.SECURITY
    assert dimension.emoji == "🔒"
    assert dimension.color == "red"

    dimension = Dimension.PERFORMANCE
    assert dimension.emoji == "⚡"
    assert dimension.color == "yellow"


def test_location_formatting():
    """Test location string formatting."""
    loc = Location(line=1, column=5, file="test.sql")
    assert str(loc) == "test.sql:1:5"

    loc_no_file = Location(line=1, column=5)
    assert str(loc_no_file) == "1:5"

    loc_with_end = Location(line=1, column=5, end_line=1, end_column=10)
    assert str(loc_with_end) == "1:5-1:10"


def test_issue_formatting():
    """Test issue display formatting."""
    loc = Location(line=1, column=1)
    issue = Issue(
        rule_id="TEST-001",
        message="Test issue",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=loc,
        snippet="SELECT *"
    )

    assert issue.rule_id == "TEST-001"
    assert issue.message == "Test issue"
    assert issue.severity == Severity.MEDIUM
    assert issue.dimension == Dimension.QUALITY
    assert str(issue.location) == "1:1"
    assert issue.snippet == "SELECT *"


def test_statistics_calculation():
    """Test statistics calculation."""
    result = AnalysisResult()

    # Add issues of different severities
    loc = Location(line=1, column=1)
    issues = [
        Issue(rule_id="CRIT-001", message="Critical", severity=Severity.CRITICAL,
              dimension=Dimension.SECURITY, location=loc, snippet="code"),
        Issue(rule_id="HIGH-001", message="High", severity=Severity.HIGH,
              dimension=Dimension.SECURITY, location=loc, snippet="code"),
        Issue(rule_id="MED-001", message="Medium", severity=Severity.MEDIUM,
              dimension=Dimension.PERFORMANCE, location=loc, snippet="code"),
    ]

    for issue in issues:
        result.add_issue(issue)

    assert result.statistics.total_issues == 3
    assert result.statistics.by_severity[Severity.CRITICAL] == 1
    assert result.statistics.by_severity[Severity.HIGH] == 1
    assert result.statistics.by_severity[Severity.MEDIUM] == 1
    assert result.statistics.by_dimension[Dimension.SECURITY] == 2
    assert result.statistics.by_dimension[Dimension.PERFORMANCE] == 1

    # Test exit codes
    assert result.exit_code == 3  # Has CRITICAL issues


def test_result_filtering():
    """Test result filtering methods."""
    loc = Location(line=1, column=1)
    issues = [
        Issue(rule_id="SEC-001", message="Security", severity=Severity.HIGH,
              dimension=Dimension.SECURITY, location=loc, snippet="code"),
        Issue(rule_id="PERF-001", message="Performance", severity=Severity.MEDIUM,
              dimension=Dimension.PERFORMANCE, location=loc, snippet="code"),
        Issue(rule_id="QUAL-001", message="Quality", severity=Severity.LOW,
              dimension=Dimension.QUALITY, location=loc, snippet="code"),
    ]

    result = AnalysisResult()
    for issue in issues:
        result.add_issue(issue)

    # Filter by severity
    high_issues = result.filter_by_severity(Severity.HIGH)
    assert len(high_issues) == 1
    assert high_issues[0].severity == Severity.HIGH

    # Filter by dimension
    security_issues = result.filter_by_dimension(Dimension.SECURITY)
    assert len(security_issues) == 1
    assert security_issues[0].dimension == Dimension.SECURITY


def test_result_grouping():
    """Test result grouping methods."""
    loc1 = Location(line=1, column=1, file="file1.sql")
    loc2 = Location(line=1, column=1, file="file2.sql")
    loc3 = Location(line=1, column=1)  # No file

    issues = [
        Issue(rule_id="TEST-001", message="Issue 1", severity=Severity.MEDIUM,
              dimension=Dimension.QUALITY, location=loc1, snippet="code"),
        Issue(rule_id="TEST-002", message="Issue 2", severity=Severity.MEDIUM,
              dimension=Dimension.SECURITY, location=loc2, snippet="code"),
        Issue(rule_id="TEST-003", message="Issue 3", severity=Severity.MEDIUM,
              dimension=Dimension.PERFORMANCE, location=loc3, snippet="code"),
    ]

    result = AnalysisResult()
    for issue in issues:
        result.add_issue(issue)

    # Group by dimension
    grouped_by_dim = result.grouped_by_dimension()
    assert len(grouped_by_dim[Dimension.QUALITY]) == 1
    assert len(grouped_by_dim[Dimension.SECURITY]) == 1
    assert len(grouped_by_dim[Dimension.PERFORMANCE]) == 1

    # Group by file
    grouped_by_file = result.grouped_by_file()
    assert len(grouped_by_file["file1.sql"]) == 1
    assert len(grouped_by_file["file2.sql"]) == 1
    assert len(grouped_by_file["<stdin>"]) == 1


def test_result_serialization():
    """Test result serialization."""
    result = AnalysisResult(dialect="mysql", version="1.0.0")

    data = result.to_dict()
    assert data["dialect"] == "mysql"
    assert data["version"] == "1.0.0"
    assert "issues" in data
    assert "statistics" in data
    assert "timestamp" in data
    assert "config_hash" in data