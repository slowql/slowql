import json
from datetime import UTC, datetime
from io import StringIO

from slowql.core.models import (
    AnalysisResult,
    Dimension,
    Issue,
    Location,
    Severity,
    Statistics,
)
from slowql.reporters.sarif_reporter import SARIFReporter


def _create_mock_result() -> AnalysisResult:
    issues = [
        Issue(
            rule_id="SEC-INJ-001",
            message="Critical SQL injection found",
            severity=Severity.CRITICAL,
            dimension=Dimension.SECURITY,
            location=Location(line=10, column=5, end_line=10, end_column=20, file="main.sql"),
            snippet="SELECT *",
        ),
        Issue(
            rule_id="QUAL-STYLE-002",
            message="Medium styling issue",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=Location(line=15, column=2, file="main.sql"),
            snippet="SELECT a",
        ),
        Issue(
            rule_id="PERF-INDEX-003",
            message="Low performance note",
            severity=Severity.LOW,
            dimension=Dimension.PERFORMANCE,
            location=Location(line=20, column=0),
            snippet="SELECT b",
        )
    ]
    result = AnalysisResult(
        issues=issues,
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    return result

def test_sarif_reporter_structure_and_mapping() -> None:
    result = _create_mock_result()
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    json_output = output.getvalue()
    data = json.loads(json_output)

    assert data["version"] == "2.1.0"
    assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "SlowQL"
    assert run["tool"]["driver"]["version"] == "2.1.0"

    # Check rules metadata collection
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 3
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"SEC-INJ-001", "QUAL-STYLE-002", "PERF-INDEX-003"}

    # Check issue mappings
    results = run["results"]
    assert len(results) == 3

    # Critical mapped to error
    assert results[0]["ruleId"] == "SEC-INJ-001"
    assert results[0]["level"] == "error"
    loc1 = results[0]["locations"][0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == "main.sql"
    assert loc1["region"]["startLine"] == 10
    assert loc1["region"]["endLine"] == 10
    assert loc1["region"]["startColumn"] == 5
    assert loc1["region"]["endColumn"] == 20

    # Medium mapped to warning
    assert results[1]["ruleId"] == "QUAL-STYLE-002"
    assert results[1]["level"] == "warning"
    loc2 = results[1]["locations"][0]["physicalLocation"]
    assert "endLine" not in loc2["region"]
    assert loc2["region"]["startColumn"] == 2

    # Low mapped to note
    assert results[2]["ruleId"] == "PERF-INDEX-003"
    assert results[2]["level"] == "note"
    loc3 = results[2]["locations"][0]["physicalLocation"]
    assert loc3["artifactLocation"]["uri"] == "unknown"


def test_map_severity_unknown_fallback() -> None:
    reporter = SARIFReporter()
    # Using a fake/unsupported severity-like object to trigger fallback
    assert reporter._map_severity("unsupported") == "none"  # type: ignore


def test_report_deduplicates_rule_metadata_for_same_rule_id() -> None:
    issues = [
        Issue(
            rule_id="RULE-001",
            message="First issue",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            location=Location(line=1, column=1, file="test.sql"),
            snippet="SELECT *",
        ),
        Issue(
            rule_id="RULE-001",
            message="Second issue",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            location=Location(line=10, column=1, file="test.sql"),
            snippet="SELECT *",
        ),
    ]
    result = AnalysisResult(
        issues=issues,
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    data = json.loads(output.getvalue())
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "RULE-001"
    assert len(data["runs"][0]["results"]) == 2


def test_report_issue_without_location_has_no_locations() -> None:
    # issue.location is required in Issue dataclass usually, but sarif_reporter.py
    # checks `if issue.location:`. We can pass None if we bypass type checks or
    # if it's optional. Models.py says `location: Location`.
    # However, sarif_reporter.py has `if issue.location:`.
    # Let's see if we can trick it for coverage.
    issue = Issue(
        rule_id="RULE-001",
        message="No location issue",
        severity=Severity.HIGH,
        dimension=Dimension.SECURITY,
        location=None,  # type: ignore
        snippet="SELECT *",
    )
    result = AnalysisResult(
        issues=[issue],
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    data = json.loads(output.getvalue())
    assert "locations" not in data["runs"][0]["results"][0]


def test_report_location_with_only_start_line() -> None:
    issue = Issue(
        rule_id="RULE-001",
        message="Line only",
        severity=Severity.HIGH,
        dimension=Dimension.SECURITY,
        location=Location(line=5, column=0),
        snippet="SELECT *",
    )
    result = AnalysisResult(
        issues=[issue],
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    data = json.loads(output.getvalue())
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    # Column 0 is falsy, so it should be omitted in SARIF region
    assert region == {"startLine": 5}


def test_report_location_with_end_line_and_columns() -> None:
    issue = Issue(
        rule_id="RULE-001",
        message="Fully detailed location",
        severity=Severity.HIGH,
        dimension=Dimension.SECURITY,
        location=Location(line=1, column=3, end_line=2, end_column=4),
        snippet="SELECT *",
    )
    result = AnalysisResult(
        issues=[issue],
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    data = json.loads(output.getvalue())
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {
        "startLine": 1,
        "endLine": 2,
        "startColumn": 3,
        "endColumn": 4,
    }


def test_report_writes_to_stdout_when_no_output_file(capsys) -> None:
    issue = Issue(
        rule_id="STDOUT-001",
        message="Stdout test",
        severity=Severity.INFO,
        dimension=Dimension.QUALITY,
        location=Location(line=1, column=1),
        snippet="SELECT *",
    )
    result = AnalysisResult(
        issues=[issue],
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    reporter = SARIFReporter(output_file=None)
    reporter.report(result)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["runs"][0]["results"][0]["ruleId"] == "STDOUT-001"


def test_report_location_with_empty_region() -> None:
    issue = Issue(
        rule_id="RULE-001",
        message="Empty location",
        severity=Severity.HIGH,
        dimension=Dimension.SECURITY,
        location=Location(line=0, column=0),
        snippet="SELECT *",
    )
    result = AnalysisResult(
        issues=[issue],
        statistics=Statistics(),
        timestamp=datetime.now(UTC),
        version="2.1.0",
    )
    output = StringIO()
    reporter = SARIFReporter(output_file=output)
    reporter.report(result)

    data = json.loads(output.getvalue())
    physical_loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in physical_loc
