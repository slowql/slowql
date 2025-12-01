# tests/unit/test_detector.py
import pytest
from slowql.core.detector import QueryDetector, IssueSeverity

@pytest.fixture
def detector():
    return QueryDetector()

# -------------------------------
# Parametrized coverage for all detectors
# -------------------------------
@pytest.mark.parametrize("query,expected,severity", [
    # SELECT *
    ("SELECT * FROM users", "SELECT * Usage", IssueSeverity.MEDIUM),
    # Missing WHERE
    ("DELETE FROM users", "Missing WHERE in UPDATE/DELETE", IssueSeverity.CRITICAL),
    # Non-SARGable
    ("SELECT * FROM users WHERE YEAR(created_at)=2023", "Non-SARGable WHERE", IssueSeverity.HIGH),
    # Implicit conversion
    ("SELECT * FROM users WHERE email = 123", "Implicit Type Conversion", IssueSeverity.HIGH),
    # Cartesian product
    ("SELECT * FROM a, b", "Cartesian Product", IssueSeverity.CRITICAL),
    # N+1 pattern
    ("SELECT * FROM users WHERE user_id = ?", "Potential N+1 Pattern", IssueSeverity.HIGH),
    # Correlated subquery
    ("SELECT *, (SELECT COUNT(*) FROM orders WHERE orders.user_id=users.id) FROM users", "Correlated Subquery", IssueSeverity.HIGH),
    # OR prevents index
    ("SELECT * FROM users WHERE id=1 OR name='x'", "OR Prevents Index", IssueSeverity.MEDIUM),
    # OFFSET pagination
    ("SELECT * FROM users OFFSET 5000", "Large OFFSET Pagination", IssueSeverity.HIGH),
    # DISTINCT unnecessary
    ("SELECT DISTINCT id FROM users", "Unnecessary DISTINCT", IssueSeverity.LOW),
    # Huge IN list
    ("SELECT * FROM users WHERE id IN (" + ",".join(map(str, range(100))) + ")", "Massive IN List", IssueSeverity.HIGH),
    # Leading wildcard
    ("SELECT * FROM users WHERE name LIKE '%john%'", "Leading Wildcard", IssueSeverity.HIGH),
    # COUNT(*) exists
    ("SELECT COUNT(*) FROM users WHERE id > 0 HAVING COUNT(*) > 0", "COUNT(*) for Existence", IssueSeverity.MEDIUM),
    # NOT IN nullable
    ("SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM orders)", "NOT IN with NULLable", IssueSeverity.HIGH),
    # EXISTS without LIMIT
    ("SELECT * FROM users WHERE EXISTS (SELECT * FROM orders)", "EXISTS without LIMIT", IssueSeverity.LOW),
    # Floating point equality
    ("SELECT * FROM users WHERE price = 19.99", "Floating Point Equality", IssueSeverity.MEDIUM),
    # NULL comparison
    ("SELECT * FROM users WHERE status = NULL", "NULL Comparison Error", IssueSeverity.CRITICAL),
    # Function on column
    ("SELECT * FROM users WHERE UPPER(email) = 'X'", "Function on Indexed Column", IssueSeverity.HIGH),
    # HAVING instead of WHERE
    ("SELECT * FROM users HAVING status='active'", "HAVING Instead of WHERE", IssueSeverity.MEDIUM),
    # UNION missing ALL
    ("SELECT * FROM users UNION SELECT * FROM orders", "UNION Missing ALL", IssueSeverity.MEDIUM),
    # Subquery in SELECT list
    ("SELECT id, (SELECT COUNT(*) FROM orders) FROM users", "Subquery in SELECT List", IssueSeverity.HIGH),
    # BETWEEN timestamps
    ("SELECT * FROM users WHERE created BETWEEN '2023-01-01' AND '2023-12-31'", "BETWEEN with Timestamps", IssueSeverity.MEDIUM),
    # CASE in WHERE
    ("SELECT * FROM users WHERE CASE WHEN status=1 THEN true END", "CASE in WHERE Clause", IssueSeverity.MEDIUM),
    # OFFSET without ORDER
    ("SELECT * FROM users OFFSET 100", "OFFSET without ORDER BY", IssueSeverity.HIGH),
    # LIKE without wildcard
    ("SELECT * FROM users WHERE name LIKE 'John'", "LIKE without Wildcards", IssueSeverity.LOW),
    # Multiple wildcards
    ("SELECT * FROM users WHERE name LIKE '%%%test%%%'","Multiple Wildcards", IssueSeverity.HIGH),
    # ORDER BY ordinal
    ("SELECT * FROM users ORDER BY 1", "ORDER BY Ordinal", IssueSeverity.LOW),
])
def test_detector_patterns(detector, query, expected, severity):
    issues = detector.analyze(query)
    assert any(i.issue_type == expected and i.severity == severity for i in issues), f"Failed for: {query}"

# -------------------------------
# Edge Cases
# -------------------------------
def test_normalize_multiline_query(detector):
    query = """
    SELECT *
    -- Comment here
    FROM users
    /* Block comment */
    WHERE id = 1
    """
    issues = detector.analyze(query)
    assert any(i.issue_type == "SELECT * Usage" for i in issues)

def test_false_positive_no_issue(detector):
    query = "SELECT id, name FROM users WHERE id = 1"
    issues = detector.analyze(query)
    assert issues == []

def test_case_insensitivity(detector):
    query = "select * from USERS"
    issues = detector.analyze(query)
    assert any(i.issue_type == "SELECT * Usage" for i in issues)

def test_multiple_issues_in_one_query(detector):
    query = "SELECT * FROM users WHERE YEAR(created_at)=2023 OR id=1"
    issues = detector.analyze(query)
    types = [i.issue_type for i in issues]
    assert "Non-SARGable WHERE" in types
    assert "OR Prevents Index" in types

@pytest.mark.parametrize("query,expected", [
    ("SELECT name FROM users ORDER BY 1", "ORDER BY Ordinal"),
    ("SELECT name FROM users ORDER BY name", None),
])
def test_order_by_ordinal_branch_coverage(query, expected):
    detector = QueryDetector()
    issue = detector._detect_order_by_ordinal(query, query)
    if expected:
        assert issue.issue_type == expected
    else:
        assert issue is None
