import pandas as pd
import pytest

from slowql.core.analyzer import QueryAnalyzer
from slowql.formatters.console import print_analysis


@pytest.fixture(scope="module")
def analyzer():
    """Shared QueryAnalyzer instance for demo tests."""
    return QueryAnalyzer(verbose=True)


@pytest.fixture
def demo_queries():
    """Representative queries with common issues."""
    return [
        "SELECT * FROM users WHERE id = 1",
        "DELETE FROM orders",
        "SELECT * FROM users, orders",
        "SELECT * FROM users WHERE UPPER(email) = 'TEST@EMAIL.COM'",
        "SELECT * FROM users WHERE created_at BETWEEN '2023-01-01' AND '2023-12-31'",
        "SELECT id FROM users WHERE status = NULL",
        "SELECT * FROM products WHERE price = 19.99",
        "SELECT * FROM users WHERE id IN " + "(" + ",".join(map(str, range(100))) + ")",
    ]


def test_demo_analysis(analyzer, demo_queries, capsys):
    """Run analyzer on demo queries and validate formatter output."""
    results = analyzer.analyze(demo_queries)

    # Convert list of issues into DataFrame if needed
    if isinstance(results, list):
        results = pd.DataFrame(results)

    # Ensure we got a DataFrame with content
    assert isinstance(results, pd.DataFrame)
    assert not results.empty

    # Print analysis (captured by pytest)
    print_analysis(results)

    # Capture console output and assert key phrases
    captured = capsys.readouterr()
    assert "Analyzing SQL queries" in captured.out or "issue" in captured.out.lower()
