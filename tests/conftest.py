# tests/conftest.py
import importlib.util
from pathlib import Path

import pytest

from slowql.core.engine import SlowQL
from slowql.core.models import Dimension, Issue, Location, Severity

# -------------------------------
# Core Fixtures
# -------------------------------


@pytest.fixture(scope="session")
def analyzer() -> SlowQL:
    """Shared SlowQL instance for all tests."""
    return SlowQL()


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
def detected_issue_example() -> Issue:
    """Provide a sample Issue object for structural tests."""
    return Issue(
        rule_id="QUAL-001",
        message="Query retrieves all columns unnecessarily",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=Location(line=1, column=1),
        snippet="SELECT * FROM users",
        fix=None,
        impact="50-90% less data transfer, enables covering indexes",
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
