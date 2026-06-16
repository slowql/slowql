import pytest
from slowql import analyze
from slowql.rules.catalog import get_all_rules
from tests.e2e.trigger_corpus import TRIGGER_CORPUS

CROSS_FILE_RULES = {
    "SCH-BRK-001", "COST-IDX-002", "MIG-BRK-001", "QUAL-DBT-001", "QUAL-DBT-002",
    "QUAL-DEAD-002", "QUAL-SCHEMA-003", "REL-CH-001", "REL-RACE-001",
    "REL-REC-001", "REL-STALE-001", "PERF-CH-002", "PERF-JOIN-003",
    "PERF-SCALAR-002", "SCHEMA-COL-001", "SCHEMA-IDX-001", "SCHEMA-TBL-001",
    "PERF-SPARK-002", "QUAL-DEBT-001", "QUAL-DOC-003", "QUAL-MODERN-001",
    "QUAL-STYLE-004", "SEC-AUTH-005", "SEC-INFO-004", "SEC-INJ-007", "SEC-INJ-009"
}

@pytest.mark.parametrize("rule_id", sorted(set(TRIGGER_CORPUS)))
def test_rule_triggers_at_least_one_issue(rule_id):
    if rule_id in CROSS_FILE_RULES:
        pytest.skip("context-dependent or multi-statement rule")
    sql, dialect = TRIGGER_CORPUS[rule_id]
    result = analyze(sql, dialect=dialect) if dialect else analyze(sql)
    triggered = {issue.rule_id for issue in result.issues}
    assert rule_id in triggered, f"Expected {rule_id} to fire for SQL: {sql}"

