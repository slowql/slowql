import io

from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity
from slowql.reporters.github_actions_reporter import GithubActionsReporter


def test_github_actions_reporter_severity_mapping() -> None:
    out = io.StringIO()
    reporter = GithubActionsReporter(output_file=out)

    result = AnalysisResult()
    result.add_issue(Issue(
        rule_id="RULE-1",
        message="Critical issue",
        severity=Severity.CRITICAL,
        dimension=Dimension.QUALITY,
        location=Location(line=1, column=1, file="test.sql"),
        snippet="SELECT *"
    ))
    result.add_issue(Issue(
        rule_id="RULE-2",
        message="Medium issue",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=Location(line=2, column=2, end_line=2, end_column=10, file="test.sql"),
        snippet="SELECT *"
    ))
    result.add_issue(Issue(
        rule_id="RULE-3",
        message="Info issue",
        severity=Severity.INFO,
        dimension=Dimension.QUALITY,
        location=Location(line=3, column=3, file="test.sql"),
        snippet="SELECT *"
    ))

    reporter.report(result)

    output = out.getvalue().splitlines()
    assert len(output) == 3
    assert output[0] == "::error file=test.sql,line=1,col=1::RULE-1 Critical issue"
    assert output[1] == "::warning file=test.sql,line=2,col=2,endLine=2,endColumn=10::RULE-2 Medium issue"
    assert output[2] == "::notice file=test.sql,line=3,col=3::RULE-3 Info issue"

def test_github_actions_reporter_escaping() -> None:
    out = io.StringIO()
    reporter = GithubActionsReporter(output_file=out)

    result = AnalysisResult()
    # Test escaping in file name and message
    result.add_issue(Issue(
        rule_id="RULE-ESC",
        message="Message with \n \r %",
        severity=Severity.HIGH,
        dimension=Dimension.QUALITY,
        location=Location(line=1, column=1, file="file with,colon:and%.sql"),
        snippet="SELECT *"
    ))

    reporter.report(result)

    output = out.getvalue().splitlines()
    assert len(output) == 1
    # File name should escape , : % \r \n
    expected_file = "file with%2Ccolon%3Aand%25.sql"
    expected_msg = "RULE-ESC Message with %0A %0D %25"
    assert output[0] == f"::error file={expected_file},line=1,col=1::{expected_msg}"

def test_github_actions_reporter_no_location() -> None:
    out = io.StringIO()
    reporter = GithubActionsReporter(output_file=out)

    result = AnalysisResult()
    result.add_issue(Issue(
        rule_id="RULE-NOLOC",
        message="No location issue",
        severity=Severity.LOW,
        dimension=Dimension.QUALITY,
        location=Location(line=0, column=0),
        snippet=""
    ))

    reporter.report(result)

    output = out.getvalue().splitlines()
    assert len(output) == 1
    # Location line and col are 0, so should they be omitted if 0?
    # Actually Location requires line and col. The test above uses 0.
    # The reporter uses if issue.location.line. In python `if 0` is false, so it won't be included.
    # Let's verify our reporter implementation handles this correctly.
    assert output[0] == "::warning::RULE-NOLOC No location issue"
