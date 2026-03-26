
import pytest

from slowql.core.models import Dimension, Issue, Location, Query, Severity
from slowql.core.scoring import ComplexityScorer, TrendTracker


@pytest.fixture
def scorer():
    return ComplexityScorer(base_score=10)

@pytest.fixture
def sample_query():
    return Query(
        raw="SELECT * FROM users JOIN orders ON users.id = orders.user_id",
        normalized="SELECT * FROM users JOIN orders ON users.id = orders.user_id",
        dialect="postgresql",
        location=Location(file="test.sql", line=1, column=1)
    )

def test_structural_complexity(scorer, sample_query):
    # Base 10 + 1 join (10) = 20
    score = scorer.calculate_score(sample_query, [])
    assert score == 20

def test_issue_complexity(scorer, sample_query):
    issues = [
        Issue(
            rule_id="RULE-1",
            message="Test",
            severity=Severity.HIGH,
            dimension=Dimension.PERFORMANCE,
            location=Location(file="test.sql", line=1, column=1),
            snippet="SELECT *",
            impact="Slow query",
            category=None
        )
    ]
    # Base 10 + 1 join (10) + High issue (15) = 35
    score = scorer.calculate_score(sample_query, issues)
    assert score == 35

def test_trend_tracker(tmp_path):
    tracker = TrendTracker(cache_dir=tmp_path)
    query_id = "test_query_hash"

    # First run
    trend = tracker.get_trend(query_id, 50)
    assert trend is None

    # Second run with same score
    trend = tracker.get_trend(query_id, 50)
    assert trend == 0

    # Third run with higher score
    trend = tracker.get_trend(query_id, 65)
    assert trend == 15
