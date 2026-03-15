from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity


def _issue(severity: Severity) -> Issue:
    return Issue(
        rule_id="TEST-001",
        message="test",
        severity=severity,
        dimension=Dimension.QUALITY,
        location=Location(line=1, column=1),
        snippet="SELECT 1",
    )

def _result(*severities: Severity) -> AnalysisResult:
    r = AnalysisResult()
    for s in severities:
        r.add_issue(_issue(s))
    return r

def test_no_issues_returns_0():
    assert AnalysisResult().exit_code == 0

def test_info_only_returns_0():
    assert _result(Severity.INFO).exit_code == 0

def test_multiple_info_returns_0():
    assert _result(Severity.INFO, Severity.INFO).exit_code == 0

def test_low_returns_1():
    assert _result(Severity.LOW).exit_code == 1

def test_medium_returns_1():
    assert _result(Severity.MEDIUM).exit_code == 1

def test_low_and_info_returns_1():
    assert _result(Severity.LOW, Severity.INFO).exit_code == 1

def test_high_returns_2():
    assert _result(Severity.HIGH).exit_code == 2

def test_high_and_medium_returns_2():
    assert _result(Severity.HIGH, Severity.MEDIUM).exit_code == 2

def test_critical_returns_3():
    assert _result(Severity.CRITICAL).exit_code == 3

def test_critical_and_high_returns_3():
    assert _result(Severity.CRITICAL, Severity.HIGH).exit_code == 3

def test_critical_and_low_returns_3():
    assert _result(Severity.CRITICAL, Severity.LOW).exit_code == 3

def test_mixed_all_severities_returns_3():
    assert _result(
        Severity.INFO, Severity.LOW, Severity.MEDIUM,
        Severity.HIGH, Severity.CRITICAL
    ).exit_code == 3

def test_exit_code_is_int():
    assert isinstance(AnalysisResult().exit_code, int)
