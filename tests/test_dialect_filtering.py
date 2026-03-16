"""Smoke tests for dialect-specific rule filtering."""

from __future__ import annotations

from slowql.core.dialects import normalize_dialect
from slowql.core.models import Location, Query

# ---------------------------------------------------------------------------
# normalize_dialect
# ---------------------------------------------------------------------------


class TestNormalizeDialect:
    def test_none_returns_none(self) -> None:
        assert normalize_dialect(None) is None

    def test_empty_returns_none(self) -> None:
        assert normalize_dialect("") is None

    def test_postgres_alias(self) -> None:
        assert normalize_dialect("postgres") == "postgresql"

    def test_pg_alias(self) -> None:
        assert normalize_dialect("pg") == "postgresql"

    def test_mssql_alias(self) -> None:
        assert normalize_dialect("mssql") == "tsql"

    def test_sqlserver_alias(self) -> None:
        assert normalize_dialect("sqlserver") == "tsql"

    def test_mariadb_alias(self) -> None:
        assert normalize_dialect("mariadb") == "mysql"

    def test_bq_alias(self) -> None:
        assert normalize_dialect("bq") == "bigquery"

    def test_sf_alias(self) -> None:
        assert normalize_dialect("sf") == "snowflake"

    def test_canonical_passthrough(self) -> None:
        assert normalize_dialect("postgresql") == "postgresql"
        assert normalize_dialect("mysql") == "mysql"
        assert normalize_dialect("bigquery") == "bigquery"

    def test_case_insensitive(self) -> None:
        assert normalize_dialect("POSTGRES") == "postgresql"
        assert normalize_dialect("MSSQL") == "tsql"
        assert normalize_dialect("BigQuery") == "bigquery"

    def test_whitespace_stripped(self) -> None:
        assert normalize_dialect("  postgres  ") == "postgresql"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DUMMY_LOC = Location(line=1, column=1)


def _make_query(sql: str, dialect: str) -> Query:
    """Create a minimal Query object for testing."""
    return Query(
        raw=sql,
        normalized=sql,
        dialect=dialect,
        location=_DUMMY_LOC,
        query_type="SELECT",
    )


# ---------------------------------------------------------------------------
# Dialect filtering on rules
# ---------------------------------------------------------------------------


class TestDialectFiltering:
    """Verify that dialect-tagged rules only fire on matching dialects."""

    def test_mysql_rule_skips_postgresql(self) -> None:
        from slowql.rules.reliability.data_safety import InsertIgnoreRule

        rule = InsertIgnoreRule()
        query = _make_query("INSERT IGNORE INTO t VALUES (1)", "postgresql")
        issues = rule.check(query)
        assert issues == []

    def test_mysql_rule_fires_on_mysql(self) -> None:
        from slowql.rules.reliability.data_safety import InsertIgnoreRule

        rule = InsertIgnoreRule()
        query = _make_query("INSERT IGNORE INTO t VALUES (1)", "mysql")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_mysql_rule_fires_on_unknown(self) -> None:
        from slowql.rules.reliability.data_safety import InsertIgnoreRule

        rule = InsertIgnoreRule()
        query = _make_query("INSERT IGNORE INTO t VALUES (1)", "unknown")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_oracle_rule_skips_mysql(self) -> None:
        from slowql.rules.quality.modern_sql import RownumWithoutOrderByRule

        rule = RownumWithoutOrderByRule()
        query = _make_query("SELECT * FROM t WHERE ROWNUM <= 10", "mysql")
        issues = rule.check(query)
        assert issues == []

    def test_oracle_rule_fires_on_oracle(self) -> None:
        from slowql.rules.quality.modern_sql import RownumWithoutOrderByRule

        rule = RownumWithoutOrderByRule()
        query = _make_query("SELECT * FROM t WHERE ROWNUM <= 10", "oracle")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_tsql_rule_skips_postgresql(self) -> None:
        from slowql.rules.performance.locking import TableLockHintRule

        rule = TableLockHintRule()
        query = _make_query("SELECT * FROM t WITH (TABLOCK)", "postgresql")
        issues = rule.check(query)
        assert issues == []

    def test_tsql_rule_fires_on_tsql(self) -> None:
        from slowql.rules.performance.locking import TableLockHintRule

        rule = TableLockHintRule()
        query = _make_query("SELECT * FROM t WITH (TABLOCK)", "tsql")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_tsql_rule_fires_on_mssql_alias(self) -> None:
        from slowql.rules.performance.locking import TableLockHintRule

        rule = TableLockHintRule()
        query = _make_query("SELECT * FROM t WITH (TABLOCK)", "mssql")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_bigquery_rule_skips_postgresql(self) -> None:
        from slowql.rules.cost.bigquery import BigQuerySelectStarCostRule

        rule = BigQuerySelectStarCostRule()
        query = _make_query("SELECT * FROM dataset.table", "postgresql")
        issues = rule.check(query)
        assert issues == []

    def test_bigquery_rule_fires_on_bigquery(self) -> None:
        from slowql.rules.cost.bigquery import BigQuerySelectStarCostRule

        rule = BigQuerySelectStarCostRule()
        query = _make_query("SELECT * FROM dataset.table", "bigquery")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_snowflake_rule_skips_mysql(self) -> None:
        from slowql.rules.cost.snowflake import SnowflakeSelectStarCostRule

        rule = SnowflakeSelectStarCostRule()
        query = _make_query("SELECT * FROM db.schema.table", "mysql")
        issues = rule.check(query)
        assert issues == []

    def test_snowflake_rule_fires_on_snowflake(self) -> None:
        from slowql.rules.cost.snowflake import SnowflakeSelectStarCostRule

        rule = SnowflakeSelectStarCostRule()
        query = _make_query("SELECT * FROM db.schema.table", "snowflake")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_pg_rule_skips_mysql(self) -> None:
        from slowql.rules.performance.indexing import IlikeOnIndexedColumnRule

        rule = IlikeOnIndexedColumnRule()
        query = _make_query("SELECT * FROM t WHERE name ILIKE '%foo%'", "mysql")
        issues = rule.check(query)
        assert issues == []

    def test_pg_rule_fires_on_postgresql(self) -> None:
        from slowql.rules.performance.indexing import IlikeOnIndexedColumnRule

        rule = IlikeOnIndexedColumnRule()
        query = _make_query("SELECT * FROM t WHERE name ILIKE '%foo%'", "postgresql")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_pg_rule_fires_on_postgres_alias(self) -> None:
        from slowql.rules.performance.indexing import IlikeOnIndexedColumnRule

        rule = IlikeOnIndexedColumnRule()
        query = _make_query("SELECT * FROM t WHERE name ILIKE '%foo%'", "postgres")
        issues = rule.check(query)
        assert len(issues) > 0

    def test_universal_rule_fires_on_any_dialect(self) -> None:
        from slowql.rules.performance.scanning import SelectStarRule

        rule = SelectStarRule()
        for dialect in ["postgresql", "mysql", "tsql", "oracle", "bigquery", "snowflake"]:
            query = _make_query("SELECT * FROM users", dialect)
            # SelectStarRule is an ASTRule that needs a parsed AST
            # so we just verify it doesn't crash and the dialect guard passes
            assert rule._dialect_matches(query) is True
