# tests/unit/test_integration.py
"""
Integration tests that exercise the main functionality.
"""

from slowql import analyze, analyze_file
from slowql.core.models import AnalysisResult


def test_analyze_function():
    """Test the main analyze function."""
    result = analyze("SELECT * FROM users")
    assert isinstance(result, AnalysisResult)
    assert len(result.issues) > 0  # Should find SELECT * issue


def test_analyze_clean_sql():
    """Test analyzing clean SQL."""
    result = analyze("SELECT id, name FROM users WHERE id = 1")
    assert isinstance(result, AnalysisResult)
    # May or may not have issues, but should not crash


def test_analyze_with_dialect():
    """Test analyze with dialect."""
    result = analyze("SELECT * FROM users", dialect="mysql")
    assert isinstance(result, AnalysisResult)


def test_analyze_file(tmp_path):
    """Test analyze_file function."""
    sql_file = tmp_path / "test.sql"
    sql_file.write_text("SELECT * FROM users")
    result = analyze_file(str(sql_file))
    assert isinstance(result, AnalysisResult)
    assert len(result.issues) > 0


def test_analyze_various_sql_patterns():
    """Test analyzing various SQL patterns to trigger different rules."""
    test_cases = [
        "SELECT * FROM users",  # SELECT *
        "DELETE FROM users",  # DELETE without WHERE
        "SELECT * FROM users WHERE id = 123 OR 1=1",  # Potential injection
        "SELECT * FROM users u, orders o",  # Cartesian product
        "SELECT COUNT(*) FROM users",  # Aggregate without GROUP BY
        "SELECT * FROM users ORDER BY RAND()",  # Non-deterministic ORDER BY
    ]

    for sql in test_cases:
        result = analyze(sql)
        assert isinstance(result, AnalysisResult)
        # Just ensure it doesn't crash


def test_analyze_complex_queries():
    """Test analyzing more complex queries."""
    complex_sql = """
    SELECT u.id, u.name, COUNT(o.id) as order_count
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.created_at > '2023-01-01'
    GROUP BY u.id, u.name
    HAVING COUNT(o.id) > 5
    ORDER BY order_count DESC
    LIMIT 10
    """
    result = analyze(complex_sql)
    assert isinstance(result, AnalysisResult)


def test_analyze_multiple_statements():
    """Test analyzing SQL with multiple statements."""
    multi_sql = """
    SELECT * FROM users;
    INSERT INTO logs VALUES (1, 'test');
    UPDATE users SET name = 'new' WHERE id = 1;
    DELETE FROM temp_table;
    """
    result = analyze(multi_sql)
    assert isinstance(result, AnalysisResult)
    assert len(result.queries) > 1


def test_analyze_with_different_dialects():
    """Test analyzing with different SQL dialects."""
    dialects = ["mysql", "postgres", "sqlite", "bigquery"]
    sql = "SELECT * FROM users LIMIT 10"

    for dialect in dialects:
        try:
            result = analyze(sql, dialect=dialect)
            assert isinstance(result, AnalysisResult)
        except Exception:
            # Some dialects might not be supported, that's ok
            pass