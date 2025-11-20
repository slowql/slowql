import pytest
from slowql.core.detector import QueryDetector, DetectedIssue, IssueSeverity
from slowql.core.analyzer import QueryAnalyzer

@pytest.fixture
def detector():
    return QueryDetector()

@pytest.fixture
def analyzer():
    return QueryAnalyzer(verbose=False)

@pytest.fixture
def sample_queries():
    return {
        'select_star': "SELECT * FROM users WHERE id = 1",
        'missing_where': "DELETE FROM users",
        'cartesian': "SELECT * FROM users, orders",
        'clean': "SELECT id, name FROM users WHERE id = 1"
    }