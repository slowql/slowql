"""Direct tests for stateful rules that can't be triggered via analyze()."""
import pytest
from slowql.core.models import Query, Location
from slowql.rules.catalog import get_all_rules

RULES = {r.id: r for r in get_all_rules()}
LOC = Location(line=1, column=1)

def make_query(raw, dialect="generic"):
    return Query(raw=raw, normalized=raw, dialect=dialect, location=LOC)

class TestStatefulRules:
    def test_read_modify_write(self):
        """REL-RACE-001: SELECT + UPDATE without FOR UPDATE."""
        rule = RULES["REL-RACE-001"]
        q = make_query("SELECT balance FROM accounts WHERE id = 1; UPDATE accounts SET balance = balance - 100 WHERE id = 1;")
        issues = rule.check(q)
        assert "REL-RACE-001" in {i.rule_id for i in issues}

    def test_stale_read(self):
        """REL-STALE-001: INSERT/UPDATE + SELECT without BEGIN."""
        rule = RULES["REL-STALE-001"]
        q = make_query("INSERT INTO users (id) VALUES (1); SELECT * FROM users;")
        issues = rule.check(q)
        assert "REL-STALE-001" in {i.rule_id for i in issues}

    def test_over_indexed(self):
        """COST-IDX-002: 3+ CREATE INDEX on same table."""
        rule = RULES["COST-IDX-002"]
        q = make_query("CREATE INDEX a ON t(x); CREATE INDEX b ON t(y); CREATE INDEX c ON t(z);")
        issues = rule.check(q)
        assert "COST-IDX-002" in {i.rule_id for i in issues}

    def test_breaking_change(self):
        """MIG-BRK-001: DROP TABLE with schema_before set."""
        from slowql.schema.models import Schema, Table, Column
        schema = Schema()
        users = Table(name="users", columns=[
            Column(name="id", type="INT"),
            Column(name="email", type="VARCHAR"),
        ])
        schema.tables = [users]
        rule = RULES["MIG-BRK-001"]
        rule.schema_before = schema
        q = make_query("DROP TABLE users;")
        issues = rule.check(q)
        assert "MIG-BRK-001" in {i.rule_id for i in issues}
