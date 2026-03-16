"""Tests for Phase 5: ClickHouse, DuckDB, Presto/Trino, Spark/Databricks."""
from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type=query_type)


# ── ClickHouse ───────────────────────────────────────────────────────


class TestClickHouseSelectWithoutPrewhereRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseSelectWithoutPrewhereRule
        assert len(ClickHouseSelectWithoutPrewhereRule().check(_q("SELECT * FROM t WHERE id = 1", "clickhouse"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseSelectWithoutPrewhereRule
        assert ClickHouseSelectWithoutPrewhereRule().check(_q("SELECT * FROM t WHERE id = 1", "postgresql")) == []


class TestClickHouseJoinWithoutGlobalRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseJoinWithoutGlobalRule
        assert len(ClickHouseJoinWithoutGlobalRule().check(_q("SELECT * FROM t JOIN (SELECT id FROM s) USING id", "clickhouse"))) > 0

    def test_no_fire_with_global(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseJoinWithoutGlobalRule
        assert ClickHouseJoinWithoutGlobalRule().check(_q("SELECT * FROM t GLOBAL JOIN (SELECT id FROM s) USING id", "clickhouse")) == []


class TestClickHouseSelectWithoutFinalRule:
    def test_fires_on_replacing(self) -> None:
        from slowql.rules.reliability.clickhouse import ClickHouseSelectWithoutFinalRule
        assert len(ClickHouseSelectWithoutFinalRule().check(_q("SELECT * FROM t -- ReplacingMergeTree", "clickhouse"))) > 0

    def test_no_fire_with_final(self) -> None:
        from slowql.rules.reliability.clickhouse import ClickHouseSelectWithoutFinalRule
        assert ClickHouseSelectWithoutFinalRule().check(_q("SELECT * FROM t FINAL -- ReplacingMergeTree", "clickhouse")) == []


class TestClickHouseSelectStarRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.clickhouse import ClickHouseSelectStarRule
        assert len(ClickHouseSelectStarRule().check(_q("SELECT * FROM events", "clickhouse"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.clickhouse import ClickHouseSelectStarRule
        assert ClickHouseSelectStarRule().check(_q("SELECT * FROM events", "postgresql")) == []


# ── DuckDB ───────────────────────────────────────────────────────────


class TestDuckDBCopyWithoutFormatRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.duckdb import DuckDBCopyWithoutFormatRule
        assert len(DuckDBCopyWithoutFormatRule().check(_q("COPY t FROM 'data.csv'", "duckdb"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.duckdb import DuckDBCopyWithoutFormatRule
        assert DuckDBCopyWithoutFormatRule().check(_q("COPY t FROM 'data.csv'", "postgresql")) == []


class TestDuckDBLargeInListRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.duckdb import DuckDBLargeInListRule
        vals = ", ".join(str(i) for i in range(15))
        assert len(DuckDBLargeInListRule().check(_q(f"SELECT * FROM t WHERE id IN ({vals})", "duckdb"))) > 0


class TestDuckDBOldStyleCastRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.duckdb import DuckDBOldStyleCastRule
        assert len(DuckDBOldStyleCastRule().check(_q("SELECT INTEGER(col) FROM t", "duckdb"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.quality.duckdb import DuckDBOldStyleCastRule
        assert DuckDBOldStyleCastRule().check(_q("SELECT INTEGER(col) FROM t", "postgresql")) == []


# ── Presto/Trino ─────────────────────────────────────────────────────


class TestPrestoCrossJoinRule:
    def test_fires_on_presto(self) -> None:
        from slowql.rules.performance.presto import PrestoCrossJoinRule
        assert len(PrestoCrossJoinRule().check(_q("SELECT * FROM a, b WHERE a.id = b.id", "presto"))) > 0

    def test_fires_on_trino(self) -> None:
        from slowql.rules.performance.presto import PrestoCrossJoinRule
        assert len(PrestoCrossJoinRule().check(_q("SELECT * FROM a, b WHERE a.id = b.id", "trino"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.presto import PrestoCrossJoinRule
        assert PrestoCrossJoinRule().check(_q("SELECT * FROM a, b WHERE a.id = b.id", "postgresql")) == []


class TestPrestoOrderByWithoutLimitRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.presto import PrestoOrderByWithoutLimitRule
        assert len(PrestoOrderByWithoutLimitRule().check(_q("SELECT id FROM t ORDER BY id", "trino"))) > 0

    def test_no_fire_with_limit(self) -> None:
        from slowql.rules.performance.presto import PrestoOrderByWithoutLimitRule
        assert PrestoOrderByWithoutLimitRule().check(_q("SELECT id FROM t ORDER BY id LIMIT 10", "presto")) == []


class TestPrestoSelectStarPartitionedRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.presto import PrestoSelectStarPartitionedRule
        assert len(PrestoSelectStarPartitionedRule().check(_q("SELECT * FROM hive.db.table", "presto"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.presto import PrestoSelectStarPartitionedRule
        assert PrestoSelectStarPartitionedRule().check(_q("SELECT * FROM hive.db.table", "postgresql")) == []


class TestPrestoInsertOverwriteRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.presto import PrestoInsertOverwriteWithoutPartitionRule
        assert len(PrestoInsertOverwriteWithoutPartitionRule().check(_q("INSERT OVERWRITE hive.db.t SELECT * FROM src", "trino"))) > 0

    def test_no_fire_with_partition(self) -> None:
        from slowql.rules.reliability.presto import PrestoInsertOverwriteWithoutPartitionRule
        assert PrestoInsertOverwriteWithoutPartitionRule().check(_q("INSERT OVERWRITE t PARTITION (dt='2024-01-01') SELECT * FROM src", "presto")) == []


# ── Spark/Databricks ─────────────────────────────────────────────────


class TestSparkBroadcastHintRule:
    def test_fires_on_spark(self) -> None:
        from slowql.rules.performance.spark import SparkBroadcastHintRule
        assert len(SparkBroadcastHintRule().check(_q("SELECT /*+ BROADCAST(big) */ * FROM big JOIN small", "spark"))) > 0

    def test_fires_on_databricks(self) -> None:
        from slowql.rules.performance.spark import SparkBroadcastHintRule
        assert len(SparkBroadcastHintRule().check(_q("SELECT /*+ BROADCAST(big) */ * FROM big JOIN small", "databricks"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.spark import SparkBroadcastHintRule
        assert SparkBroadcastHintRule().check(_q("SELECT /*+ BROADCAST(big) */ * FROM big JOIN small", "postgresql")) == []


class TestSparkUdfInWhereRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.spark import SparkUdfInWhereRule
        assert len(SparkUdfInWhereRule().check(_q("SELECT * FROM t WHERE udf(col) = 1", "spark"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.spark import SparkUdfInWhereRule
        assert SparkUdfInWhereRule().check(_q("SELECT * FROM t WHERE udf(col) = 1", "postgresql")) == []


class TestSparkFullScanRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.spark import SparkFullScanWithoutPartitionFilterRule
        assert len(SparkFullScanWithoutPartitionFilterRule().check(_q("SELECT * FROM delta.events", "databricks"))) > 0

    def test_no_fire_with_where(self) -> None:
        from slowql.rules.cost.spark import SparkFullScanWithoutPartitionFilterRule
        assert SparkFullScanWithoutPartitionFilterRule().check(_q("SELECT * FROM delta.events WHERE dt = '2024-01-01'", "spark")) == []


class TestSparkOverwriteRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.spark import SparkOverwriteWithoutPartitionRule
        assert len(SparkOverwriteWithoutPartitionRule().check(_q("INSERT OVERWRITE TABLE t SELECT * FROM src", "spark"))) > 0

    def test_no_fire_with_partition(self) -> None:
        from slowql.rules.reliability.spark import SparkOverwriteWithoutPartitionRule
        assert SparkOverwriteWithoutPartitionRule().check(_q("INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01') SELECT * FROM src", "databricks")) == []


# ── Catalog ──────────────────────────────────────────────────────────


class TestPhase5Catalog:
    def test_all_in_catalog(self) -> None:
        from slowql.rules.catalog import get_all_rules
        ids = {r.id for r in get_all_rules()}
        for eid in ["PERF-CH-001", "PERF-CH-002", "REL-CH-001", "COST-CH-001",
                     "PERF-DUCK-001", "PERF-DUCK-002", "QUAL-DUCK-001",
                     "PERF-PRESTO-001", "PERF-PRESTO-002", "COST-PRESTO-001", "REL-PRESTO-001",
                     "PERF-SPARK-001", "PERF-SPARK-002", "COST-SPARK-001", "REL-SPARK-001"]:
            assert eid in ids, f"{eid} missing"

    def test_total(self) -> None:
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) == 256

    def test_no_duplicates(self) -> None:
        from collections import Counter

        from slowql.rules.catalog import get_all_rules
        ids = [r.id for r in get_all_rules()]
        dupes = {k: v for k, v in Counter(ids).items() if v > 1}
        assert not dupes, f"Duplicate rule IDs: {dupes}"
