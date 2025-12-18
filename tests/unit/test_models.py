# tests/unit/test_models.py
import pytest

from slowql.core.models import (
    AnalysisResult,
    Dimension,
    Fix,
    Issue,
    Location,
    Query,
    Severity,
    Statistics,
)


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_emoji(self):
        assert Severity.CRITICAL.emoji == "💀"
        assert Severity.HIGH.emoji == "🔥"
        assert Severity.MEDIUM.emoji == "⚡"
        assert Severity.LOW.emoji == "💫"
        assert Severity.INFO.emoji == "💡"

    def test_severity_color(self):
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.HIGH.color == "red"
        assert Severity.MEDIUM.color == "yellow"
        assert Severity.LOW.color == "cyan"
        assert Severity.INFO.color == "dim"

    def test_severity_weight(self):
        assert Severity.CRITICAL.weight == 5
        assert Severity.HIGH.weight == 4
        assert Severity.MEDIUM.weight == 3
        assert Severity.LOW.weight == 2
        assert Severity.INFO.weight == 1

    def test_severity_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.MEDIUM


class TestDimension:
    def test_dimension_values(self):
        assert Dimension.SECURITY.value == "security"
        assert Dimension.PERFORMANCE.value == "performance"
        assert Dimension.RELIABILITY.value == "reliability"
        assert Dimension.COMPLIANCE.value == "compliance"
        assert Dimension.COST.value == "cost"
        assert Dimension.QUALITY.value == "quality"
        assert Dimension.SCHEMA.value == "schema"
        assert Dimension.DATA.value == "data"
        assert Dimension.MIGRATION.value == "migration"
        assert Dimension.OPERATIONAL.value == "operational"
        assert Dimension.BUSINESS.value == "business"

    def test_dimension_emoji(self):
        assert Dimension.SECURITY.emoji == "🔒"
        assert Dimension.PERFORMANCE.emoji == "⚡"
        assert Dimension.RELIABILITY.emoji == "🛡️"
        assert Dimension.COMPLIANCE.emoji == "📋"
        assert Dimension.COST.emoji == "💰"
        assert Dimension.QUALITY.emoji == "📝"
        assert Dimension.SCHEMA.emoji == "🏛️"
        assert Dimension.DATA.emoji == "📊"
        assert Dimension.MIGRATION.emoji == "🔄"
        assert Dimension.OPERATIONAL.emoji == "⚙️"
        assert Dimension.BUSINESS.emoji == "🧠"

    def test_dimension_description(self):
        assert "Security" in Dimension.SECURITY.description
        assert "Performance" in Dimension.PERFORMANCE.description
        assert "reliability" in Dimension.RELIABILITY.description.lower()


class TestLocation:
    def test_location_creation(self):
        loc = Location(line=1, column=5, end_line=1, end_column=10, file="test.sql")
        assert loc.line == 1
        assert loc.column == 5
        assert loc.end_line == 1
        assert loc.end_column == 10
        assert loc.file == "test.sql"
        assert loc.query_index is None

    def test_location_str(self):
        loc = Location(line=1, column=5, file="test.sql")
        assert str(loc) == "test.sql:1:5"

        loc_no_file = Location(line=1, column=5)
        assert str(loc_no_file) == "1:5"

        loc_with_end = Location(line=1, column=5, end_line=1, end_column=10)
        assert str(loc_with_end) == "1:5-1:10"

    def test_location_to_dict(self):
        loc = Location(line=1, column=5, file="test.sql", query_index=0)
        data = loc.to_dict()
        assert data["line"] == 1
        assert data["column"] == 5
        assert data["file"] == "test.sql"
        assert data["query_index"] == 0


class TestFix:
    def test_fix_creation(self):
        fix = Fix(
            description="Add index",
            replacement="CREATE INDEX idx_name ON table(col)",
            is_safe=True,
            confidence=0.9,
        )
        assert fix.description == "Add index"
        assert fix.replacement == "CREATE INDEX idx_name ON table(col)"
        assert fix.is_safe is True
        assert fix.confidence == 0.9

    def test_fix_to_dict(self):
        fix = Fix(description="Fix", replacement="code")
        data = fix.to_dict()
        assert data["description"] == "Fix"
        assert data["replacement"] == "code"
        assert data["is_safe"] is False
        assert data["confidence"] == 1.0


class TestIssue:
    def test_issue_creation(self):
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test issue",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="SELECT *",
        )
        assert issue.rule_id == "TEST-001"
        assert issue.message == "Test issue"
        assert issue.severity == Severity.MEDIUM
        assert issue.dimension == Dimension.QUALITY
        assert issue.location == loc
        assert issue.snippet == "SELECT *"
        assert issue.fix is None
        assert issue.impact is None

    def test_issue_validation(self):
        loc = Location(line=1, column=1)
        with pytest.raises(ValueError):
            Issue(
                rule_id="",
                message="Test",
                severity=Severity.MEDIUM,
                dimension=Dimension.QUALITY,
                location=loc,
                snippet="code",
            )

        with pytest.raises(ValueError):
            Issue(
                rule_id="TEST-001",
                message="",
                severity=Severity.MEDIUM,
                dimension=Dimension.QUALITY,
                location=loc,
                snippet="code",
            )

    def test_issue_properties(self):
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        assert issue.code == "TEST-001"

    def test_issue_to_dict(self):
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
            impact="Performance impact",
            tags=("tag1", "tag2"),
            metadata={"key": "value"},
        )
        data = issue.to_dict()
        assert data["rule_id"] == "TEST-001"
        assert data["message"] == "Test"
        assert data["severity"] == "medium"
        assert data["dimension"] == "quality"
        assert data["location"]["line"] == 1
        assert data["snippet"] == "code"
        assert data["impact"] == "Performance impact"
        assert data["tags"] == ["tag1", "tag2"]
        assert data["metadata"] == {"key": "value"}


class TestQuery:
    def test_query_creation(self):
        loc = Location(line=1, column=1)
        query = Query(
            raw="SELECT * FROM users",
            normalized="SELECT * FROM users",
            dialect="mysql",
            location=loc,
            tables=("users",),
            columns=("id", "name"),
            query_type="SELECT",
        )
        assert query.raw == "SELECT * FROM users"
        assert query.normalized == "SELECT * FROM users"
        assert query.dialect == "mysql"
        assert query.location == loc
        assert query.tables == ("users",)
        assert query.columns == ("id", "name")
        assert query.query_type == "SELECT"
        assert query.ast is None

    def test_query_properties(self):
        loc = Location(line=1, column=1)
        query = Query(
            raw="SELECT * FROM users",
            normalized="SELECT * FROM users",
            dialect="mysql",
            location=loc,
            query_type="SELECT",
        )
        assert query.is_select is True
        assert query.is_insert is False
        assert query.is_update is False
        assert query.is_delete is False

        query.query_type = "INSERT"
        assert query.is_select is False
        assert query.is_insert is True

    def test_query_hash(self):
        loc = Location(line=1, column=1)
        query1 = Query(raw="SELECT *", normalized="SELECT *", dialect="mysql", location=loc)
        query2 = Query(raw="SELECT *", normalized="SELECT *", dialect="mysql", location=loc)
        assert hash(query1) == hash(query2)


class TestStatistics:
    def test_statistics_creation(self):
        stats = Statistics()
        assert stats.total_queries == 0
        assert stats.total_issues == 0
        assert Severity.CRITICAL in stats.by_severity
        assert Dimension.SECURITY in stats.by_dimension

    def test_statistics_to_dict(self):
        stats = Statistics(total_queries=5, total_issues=3)
        stats.by_severity[Severity.HIGH] = 2
        stats.by_dimension[Dimension.SECURITY] = 1

        data = stats.to_dict()
        assert data["total_queries"] == 5
        assert data["total_issues"] == 3
        assert data["by_severity"]["high"] == 2
        assert data["by_dimension"]["security"] == 1


class TestAnalysisResult:
    def test_analysis_result_creation(self):
        result = AnalysisResult()
        assert len(result.issues) == 0
        assert len(result.queries) == 0
        assert result.statistics.total_queries == 0
        assert result.statistics.total_issues == 0

    def test_analysis_result_add_issue(self):
        loc = Location(line=1, column=1)
        issue = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        result = AnalysisResult()
        result.add_issue(issue)

        assert len(result.issues) == 1
        assert result.statistics.total_issues == 1
        assert result.statistics.by_severity[Severity.MEDIUM] == 1
        assert result.statistics.by_dimension[Dimension.QUALITY] == 1

    def test_analysis_result_filter_by_severity(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            location=loc,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)

        high_issues = result.filter_by_severity(Severity.HIGH)
        assert len(high_issues) == 1
        assert high_issues[0].severity == Severity.HIGH

    def test_analysis_result_filter_by_dimension(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.SECURITY,
            location=loc,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)

        security_issues = result.filter_by_dimension(Dimension.SECURITY)
        assert len(security_issues) == 1
        assert security_issues[0].dimension == Dimension.SECURITY

    def test_analysis_result_properties(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.CRITICAL,
            dimension=Dimension.SECURITY,
            location=loc,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.HIGH,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)

        assert result.has_critical is True
        assert result.has_high is True

    def test_analysis_result_exit_code(self):
        loc = Location(line=1, column=1)
        result = AnalysisResult()

        # No issues
        assert result.exit_code == 0

        # Only INFO issues
        issue_info = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.INFO,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        result.add_issue(issue_info)
        assert result.exit_code == 0

        # LOW/MEDIUM issues
        issue_low = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        result.add_issue(issue_low)
        assert result.exit_code == 1

        # HIGH issues
        issue_high = Issue(
            rule_id="TEST-003",
            message="Test",
            severity=Severity.HIGH,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        result.add_issue(issue_high)
        assert result.exit_code == 2

        # CRITICAL issues
        issue_critical = Issue(
            rule_id="TEST-004",
            message="Test",
            severity=Severity.CRITICAL,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        result.add_issue(issue_critical)
        assert result.exit_code == 3

    def test_analysis_result_sorted_by_severity(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.CRITICAL,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)

        sorted_issues = result.sorted_by_severity()
        assert sorted_issues[0].severity == Severity.CRITICAL
        assert sorted_issues[1].severity == Severity.LOW

    def test_analysis_result_grouped_by_dimension(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.SECURITY,
            location=loc,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.SECURITY,
            location=loc,
            snippet="code",
        )
        issue3 = Issue(
            rule_id="TEST-003",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)
        result.add_issue(issue3)

        grouped = result.grouped_by_dimension()
        assert len(grouped[Dimension.SECURITY]) == 2
        assert len(grouped[Dimension.QUALITY]) == 1

    def test_analysis_result_grouped_by_file(self):
        loc1 = Location(line=1, column=1, file="file1.sql")
        loc2 = Location(line=1, column=1, file="file2.sql")
        loc3 = Location(line=1, column=1)  # No file

        issue1 = Issue(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc1,
            snippet="code",
        )
        issue2 = Issue(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc2,
            snippet="code",
        )
        issue3 = Issue(
            rule_id="TEST-003",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.QUALITY,
            location=loc3,
            snippet="code",
        )

        result = AnalysisResult()
        result.add_issue(issue1)
        result.add_issue(issue2)
        result.add_issue(issue3)

        grouped = result.grouped_by_file()
        assert len(grouped["file1.sql"]) == 1
        assert len(grouped["file2.sql"]) == 1
        assert len(grouped["<stdin>"]) == 1

    def test_analysis_result_to_dict(self):
        result = AnalysisResult(dialect="mysql", version="1.0.0")
        data = result.to_dict()
        assert data["dialect"] == "mysql"
        assert data["version"] == "1.0.0"
        assert "issues" in data
        assert "statistics" in data
