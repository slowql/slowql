# tests/conftest.py
import pytest
from pathlib import Path

from slowql.core.detector import QueryDetector, DetectedIssue, IssueSeverity
from slowql.core.analyzer import QueryAnalyzer

import importlib.util

# -------------------------------
# Core Fixtures
# -------------------------------

@pytest.fixture(scope="session")
def detector() -> QueryDetector:
    """Shared QueryDetector instance for all tests."""
    return QueryDetector()

@pytest.fixture(scope="session")
def analyzer() -> QueryAnalyzer:
    """Shared QueryAnalyzer instance (non-verbose by default)."""
    return QueryAnalyzer(verbose=False)

@pytest.fixture
def sample_queries() -> dict:
    """Common sample queries for quick detector/analyzer tests."""
    return {
        "select_star": "SELECT * FROM users WHERE id = 1",
        "missing_where": "DELETE FROM users",
        "cartesian": "SELECT * FROM users, orders",
        "clean": "SELECT id, name FROM users WHERE id = 1",
        "non_sargable": "SELECT * FROM users WHERE YEAR(created_at)=2023",
        "implicit_conversion": "SELECT * FROM users WHERE email = 123",
        "leading_wildcard": "SELECT * FROM users WHERE name LIKE '%john%'",
    }

# -------------------------------
# Paths & Files
# -------------------------------

@pytest.fixture
def sample_sql_file(tmp_path: Path) -> Path:
    """Create a temporary SQL file with a few queries."""
    sql_content = """
    SELECT * FROM users;
    DELETE FROM orders;
    SELECT id, name FROM users WHERE id = 1;
    """
    file_path = tmp_path / "sample.sql"
    file_path.write_text(sql_content.strip(), encoding="utf-8")
    return file_path

@pytest.fixture
def empty_sql_file(tmp_path: Path) -> Path:
    """Create an empty SQL file for error handling tests."""
    file_path = tmp_path / "empty.sql"
    file_path.write_text("", encoding="utf-8")
    return file_path

# -------------------------------
# Helper Fixtures
# -------------------------------

@pytest.fixture
def detected_issue_example() -> DetectedIssue:
    """Provide a sample DetectedIssue object for structural tests."""
    return DetectedIssue(
        issue_type="SELECT * Usage",
        query="SELECT * FROM users",
        description="Query retrieves all columns unnecessarily",
        fix="Specify only needed columns",
        impact="50-90% less data transfer, enables covering indexes",
        severity=IssueSeverity.MEDIUM,
        line_number=None,
    )

@pytest.fixture
def multiple_queries() -> list[str]:
    """Provide a list of queries for batch analysis tests."""
    return [
        "SELECT * FROM users",
        "DELETE FROM orders",
        "SELECT id FROM users WHERE email = 123",
        "SELECT * FROM users OFFSET 5000",
    ]


if importlib.util.find_spec("pandas") is None:
    raise ImportError(
        "Missing required test dependency 'pandas'. Install it in your virtualenv:\n"
        "  pip install pandas\n"
        "or install all dev dependencies:\n"
        "  pip install -r requirements-dev.txt"
    )
