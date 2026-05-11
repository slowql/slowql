import pytest

from slowql.core.models import Location, Query
from slowql.rules.cost.bigquery import BigQueryMissingLimitRule, BigQuerySelectStarCostRule
from slowql.rules.cost.snowflake import (
    SnowflakeCopyIntoWithoutFileFormatRule,
    SnowflakeSelectStarCostRule,
)
from slowql.rules.cost.spark import (
    SparkCacheTableWithoutFilterRule,
    SparkFullScanWithoutPartitionFilterRule,
)
from slowql.rules.performance.clickhouse import (
    ClickHouseJoinWithoutGlobalRule,
    ClickHouseMutationRule,
    ClickHouseSelectWithoutPrewhereRule,
)
from slowql.rules.performance.execution import ScalarUdfInQueryRule
from slowql.rules.performance.hints import IndexHintRule, QueryOptimizerHintRule
from slowql.rules.performance.indexing import IlikeOnIndexedColumnRule
from slowql.rules.performance.memory import UnboundedTempTableRule
from slowql.rules.performance.presto import PrestoCrossJoinRule, PrestoOrderByWithoutLimitRule
from slowql.rules.performance.redshift import (
    NotInOnRedshiftRule,
    OrderByWithoutLimitRedshiftRule,
    RedshiftSelectStarRule,
)
from slowql.rules.quality.modern_sql import RownumWithoutOrderByRule, SelectFromDualRule
from slowql.rules.reliability.clickhouse import ClickHouseSelectWithoutFinalRule
from slowql.rules.reliability.data_safety import InsertIgnoreRule, ReplaceIntoRule
from slowql.rules.reliability.presto import PrestoInsertOverwriteWithoutPartitionRule
from slowql.rules.reliability.spark import SparkOverwriteWithoutPartitionRule
from slowql.rules.security.command import OSCommandInjectionPostgresRule, OSCommandInjectionTsqlRule


@pytest.fixture
def loc():
    return Location(line=1, column=1)

@pytest.fixture
def mysql_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="mysql", location=loc)

@pytest.fixture
def pg_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="postgres", location=loc)

@pytest.fixture
def tsql_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="tsql", location=loc)

@pytest.fixture
def oracle_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="oracle", location=loc)

@pytest.fixture
def bq_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="bigquery", location=loc)

@pytest.fixture
def sf_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="snowflake", location=loc)

@pytest.fixture
def ch_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="clickhouse", location=loc)

@pytest.fixture
def presto_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="presto", location=loc)

@pytest.fixture
def spark_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="spark", location=loc)

@pytest.fixture
def rs_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="redshift", location=loc)

@pytest.fixture
def duckdb_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="duckdb", location=loc)

def test_mysql_specific_rules(mysql_query, pg_query):
    # InsertIgnoreRule
    rule = InsertIgnoreRule()
    assert len(rule.check(mysql_query("INSERT IGNORE INTO t (a) VALUES (1)"))) == 1
    assert len(rule.check(pg_query("INSERT INTO t (a) VALUES (1)"))) == 0  # Wrong dialect

    # ReplaceIntoRule
    rule = ReplaceIntoRule()
    assert len(rule.check(mysql_query("REPLACE INTO t (a) VALUES (1)"))) == 1
    assert len(rule.check(pg_query("INSERT INTO t (a) VALUES (1)"))) == 0

def test_postgres_specific_rules(pg_query, mysql_query):
    # IlikeOnIndexedColumnRule
    rule = IlikeOnIndexedColumnRule()
    assert len(rule.check(pg_query("SELECT * FROM t WHERE a ILIKE 'v%'"))) == 1
    assert len(rule.check(mysql_query("SELECT * FROM t WHERE a LIKE 'v%'"))) == 0

def test_oracle_specific_rules(oracle_query, pg_query):
    # RownumWithoutOrderByRule
    rule = RownumWithoutOrderByRule()
    assert len(rule.check(oracle_query("SELECT * FROM t WHERE ROWNUM <= 10"))) == 1
    assert len(rule.check(oracle_query("SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY id"))) == 0
    assert len(rule.check(pg_query("SELECT * FROM t LIMIT 10"))) == 0

    # SelectFromDualRule
    rule = SelectFromDualRule()
    assert len(rule.check(oracle_query("SELECT 1 FROM DUAL"))) == 1
    assert len(rule.check(pg_query("SELECT 1"))) == 0

def test_bigquery_specific_rules(bq_query, pg_query):
    # BigQuerySelectStarCostRule
    rule = BigQuerySelectStarCostRule()
    assert len(rule.check(bq_query("SELECT * FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # BigQueryMissingLimitRule
    rule = BigQueryMissingLimitRule()
    assert len(rule.check(bq_query("SELECT a FROM t"))) == 1
    assert len(rule.check(bq_query("SELECT a FROM t LIMIT 10"))) == 0

def test_snowflake_specific_rules(sf_query, pg_query):
    # SnowflakeSelectStarCostRule
    rule = SnowflakeSelectStarCostRule()
    assert len(rule.check(sf_query("SELECT * FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # SnowflakeCopyIntoWithoutFileFormatRule
    rule = SnowflakeCopyIntoWithoutFileFormatRule()
    assert len(rule.check(sf_query("COPY INTO t FROM @s"))) == 1
    assert len(rule.check(sf_query("COPY INTO t FROM @s FILE_FORMAT = (TYPE = CSV)"))) == 0

def test_security_dialect_splitting(tsql_query, pg_query):
    # TSQL
    rule = OSCommandInjectionTsqlRule()
    assert len(rule.check(tsql_query("EXEC xp_cmdshell 'dir'"))) == 1
    assert len(rule.check(pg_query("SELECT pg_read_file('etc/passwd')"))) == 0

    # Postgres
    rule = OSCommandInjectionPostgresRule()
    assert len(rule.check(pg_query("SELECT pg_read_file('etc/passwd')"))) == 1
    assert len(rule.check(tsql_query("EXEC xp_cmdshell 'dir'"))) == 0

def test_existing_rules_dialect_guards(tsql_query, pg_query, mysql_query):
    # QueryOptimizerHintRule (tsql only)
    rule = QueryOptimizerHintRule()
    assert len(rule.check(tsql_query("SELECT * FROM t OPTION(HASH JOIN)"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # ScalarUdfInQueryRule (tsql only)
    rule = ScalarUdfInQueryRule()
    assert len(rule.check(tsql_query("SELECT dbo.fn(a) FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT fn(a) FROM t"))) == 0

    # UnboundedTempTableRule (tsql only)
    rule = UnboundedTempTableRule()
    assert len(rule.check(tsql_query("SELECT * INTO #t FROM s"))) == 1
    assert len(rule.check(pg_query("CREATE TEMP TABLE t AS SELECT * FROM s"))) == 0

    rule = IndexHintRule()
    assert len(rule.check(mysql_query("SELECT * FROM t USE INDEX (i)"))) == 1
    assert len(rule.check(tsql_query("SELECT * FROM t WITH(INDEX=i)"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0


# --- Coverage gap tests for dialect-specific rules below 95% ---

def test_clickhouse_select_without_final_triggers(ch_query):
    rule = ClickHouseSelectWithoutFinalRule()
    issues = rule.check(ch_query("SELECT * FROM my_table REPLACING"))
    assert len(issues) == 1
    assert "FINAL" in issues[0].message


def test_clickhouse_select_with_final_ok(ch_query):
    rule = ClickHouseSelectWithoutFinalRule()
    issues = rule.check(ch_query("SELECT * FROM my_table FINAL"))
    assert len(issues) == 0


def test_clickhouse_select_without_replacing_ok(ch_query):
    rule = ClickHouseSelectWithoutFinalRule()
    issues = rule.check(ch_query("SELECT * FROM my_table WHERE id = 1"))
    assert len(issues) == 0


def test_clickhouse_select_wrong_dialect(pg_query):
    rule = ClickHouseSelectWithoutFinalRule()
    issues = rule.check(pg_query("SELECT * FROM my_table REPLACING"))
    assert len(issues) == 0


def test_presto_insert_overwrite_without_partition(presto_query):
    rule = PrestoInsertOverwriteWithoutPartitionRule()
    issues = rule.check(presto_query("INSERT OVERWRITE TABLE t SELECT * FROM s"))
    assert len(issues) == 1
    assert "PARTITION" in issues[0].message


def test_presto_insert_overwrite_with_partition_ok(presto_query):
    rule = PrestoInsertOverwriteWithoutPartitionRule()
    issues = rule.check(presto_query("INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01') SELECT * FROM s"))
    assert len(issues) == 0


def test_presto_insert_normal_ok(presto_query):
    rule = PrestoInsertOverwriteWithoutPartitionRule()
    issues = rule.check(presto_query("INSERT INTO TABLE t SELECT * FROM s"))
    assert len(issues) == 0


def test_presto_insert_wrong_dialect(pg_query):
    rule = PrestoInsertOverwriteWithoutPartitionRule()
    issues = rule.check(pg_query("INSERT OVERWRITE TABLE t SELECT * FROM s"))
    assert len(issues) == 0


def test_spark_overwrite_without_partition(spark_query):
    rule = SparkOverwriteWithoutPartitionRule()
    issues = rule.check(spark_query("INSERT OVERWRITE TABLE t SELECT * FROM s"))
    assert len(issues) == 1
    assert "PARTITION" in issues[0].message


def test_spark_overwrite_with_partition_ok(spark_query):
    rule = SparkOverwriteWithoutPartitionRule()
    issues = rule.check(spark_query("INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01') SELECT * FROM s"))
    assert len(issues) == 0


def test_spark_overwrite_wrong_dialect(pg_query):
    rule = SparkOverwriteWithoutPartitionRule()
    issues = rule.check(pg_query("INSERT OVERWRITE TABLE t SELECT * FROM s"))
    assert len(issues) == 0


def test_spark_full_scan_without_where(spark_query):
    rule = SparkFullScanWithoutPartitionFilterRule()
    issues = rule.check(spark_query("SELECT * FROM my_table"))
    assert len(issues) == 1
    assert "WHERE" in issues[0].message or "partition" in issues[0].message.lower()


def test_spark_full_scan_with_where_ok(spark_query):
    rule = SparkFullScanWithoutPartitionFilterRule()
    issues = rule.check(spark_query("SELECT * FROM my_table WHERE dt = '2024-01-01'"))
    assert len(issues) == 0


def test_spark_full_scan_wrong_dialect(pg_query):
    rule = SparkFullScanWithoutPartitionFilterRule()
    issues = rule.check(pg_query("SELECT * FROM my_table"))
    assert len(issues) == 0


def test_spark_cache_table_without_filter(spark_query):
    rule = SparkCacheTableWithoutFilterRule()
    issues = rule.check(spark_query("CACHE TABLE my_table"))
    assert len(issues) == 1


def test_spark_cache_table_with_where_ok(spark_query):
    rule = SparkCacheTableWithoutFilterRule()
    issues = rule.check(spark_query("CACHE TABLE my_table WHERE dt = '2024-01-01'"))
    assert len(issues) == 0


def test_presto_cross_join(presto_query):
    rule = PrestoCrossJoinRule()
    issues = rule.check(presto_query("SELECT * FROM a, b"))
    assert len(issues) == 1
    assert "cross-join" in issues[0].message.lower()


def test_presto_cross_join_with_join_ok(presto_query):
    rule = PrestoCrossJoinRule()
    issues = rule.check(presto_query("SELECT * FROM a, b JOIN c ON b.id = c.id"))
    assert len(issues) == 0


def test_presto_cross_join_wrong_dialect(pg_query):
    rule = PrestoCrossJoinRule()
    issues = rule.check(pg_query("SELECT * FROM a, b"))
    assert len(issues) == 0


def test_presto_order_by_without_limit(presto_query):
    rule = PrestoOrderByWithoutLimitRule()
    issues = rule.check(presto_query("SELECT * FROM t ORDER BY id"))
    assert len(issues) == 1
    assert "LIMIT" in issues[0].message or "OOM" in issues[0].message


def test_presto_order_by_with_limit_ok(presto_query):
    rule = PrestoOrderByWithoutLimitRule()
    issues = rule.check(presto_query("SELECT * FROM t ORDER BY id LIMIT 10"))
    assert len(issues) == 0


def test_clickhouse_select_without_prewhere(ch_query):
    rule = ClickHouseSelectWithoutPrewhereRule()
    issues = rule.check(ch_query("SELECT * FROM my_table WHERE id = 1"))
    assert len(issues) == 1


def test_clickhouse_select_with_prewhere_ok(ch_query):
    rule = ClickHouseSelectWithoutPrewhereRule()
    issues = rule.check(ch_query("SELECT * FROM my_table PREWHERE id = 1"))
    assert len(issues) == 0


def test_clickhouse_join_without_global(ch_query):
    rule = ClickHouseJoinWithoutGlobalRule()
    issues = rule.check(ch_query("SELECT * FROM t1 JOIN (SELECT id FROM t2) USING id"))
    assert len(issues) == 1
    assert "GLOBAL" in issues[0].message


def test_clickhouse_join_with_global_ok(ch_query):
    rule = ClickHouseJoinWithoutGlobalRule()
    issues = rule.check(ch_query("SELECT * FROM t1 GLOBAL JOIN (SELECT id FROM t2) USING id"))
    assert len(issues) == 0


def test_clickhouse_mutation(ch_query):
    rule = ClickHouseMutationRule()
    issues = rule.check(ch_query("ALTER TABLE my_table UPDATE col = 1 WHERE id = 10"))
    assert len(issues) == 1


def test_clickhouse_mutation_wrong_dialect(pg_query):
    rule = ClickHouseMutationRule()
    issues = rule.check(pg_query("ALTER TABLE my_table UPDATE col = 1 WHERE id = 10"))
    assert len(issues) == 0


def test_redshift_select_star(rs_query):
    rule = RedshiftSelectStarRule()
    issues = rule.check(rs_query("SELECT * FROM my_table"))
    assert len(issues) == 1


def test_redshift_select_star_wrong_dialect(pg_query):
    rule = RedshiftSelectStarRule()
    issues = rule.check(pg_query("SELECT * FROM my_table"))
    assert len(issues) == 0


def test_redshift_order_by_without_limit(rs_query):
    rule = OrderByWithoutLimitRedshiftRule()
    issues = rule.check(rs_query("SELECT * FROM t ORDER BY id"))
    assert len(issues) == 1


def test_redshift_order_by_with_limit_ok(rs_query):
    rule = OrderByWithoutLimitRedshiftRule()
    issues = rule.check(rs_query("SELECT * FROM t ORDER BY id LIMIT 10"))
    assert len(issues) == 0


def test_redshift_order_by_with_top_ok(rs_query):
    rule = OrderByWithoutLimitRedshiftRule()
    issues = rule.check(rs_query("SELECT TOP 10 * FROM t ORDER BY id"))
    assert len(issues) == 0


def test_redshift_not_in(rs_query):
    rule = NotInOnRedshiftRule()
    issues = rule.check(rs_query("SELECT * FROM t WHERE id NOT IN (SELECT id FROM s)"))
    assert len(issues) == 1


def test_redshift_not_in_wrong_dialect(pg_query):
    rule = NotInOnRedshiftRule()
    issues = rule.check(pg_query("SELECT * FROM t WHERE id NOT IN (SELECT id FROM s)"))
    assert len(issues) == 0


# --- Additional coverage for rules below 95% ---

# jsonb_style.py (80% -> need postgres query with double space)
def test_jsonb_spacing_triggers(pg_query):
    from slowql.rules.quality.jsonb_style import JSONBOperatorSpacingRule
    rule = JSONBOperatorSpacingRule()
    issues = rule.check(pg_query("SELECT * FROM t WHERE data  ->> 'id' = 1"))
    assert len(issues) == 1
    assert issues[0].fix is not None
    assert "data ->>" in issues[0].fix.replacement


def test_jsonb_spacing_clean_ok(pg_query):
    from slowql.rules.quality.jsonb_style import JSONBOperatorSpacingRule
    rule = JSONBOperatorSpacingRule()
    issues = rule.check(pg_query("SELECT * FROM t WHERE data ->> 'id' = 1"))
    assert len(issues) == 0


def test_jsonb_spacing_wrong_dialect(mysql_query):
    from slowql.rules.quality.jsonb_style import JSONBOperatorSpacingRule
    rule = JSONBOperatorSpacingRule()
    issues = rule.check(mysql_query("SELECT * FROM t WHERE data  ->> 'id' = 1"))
    assert len(issues) == 0


# performance/spark.py (83% -> SparkUdfInWhereRule)
def test_spark_udf_in_where(spark_query):
    from slowql.rules.performance.spark import SparkUdfInWhereRule
    rule = SparkUdfInWhereRule()
    issues = rule.check(spark_query("SELECT * FROM t WHERE udf(name) = 'x'"))
    assert len(issues) == 1


def test_spark_udf_not_in_where_ok(spark_query):
    from slowql.rules.performance.spark import SparkUdfInWhereRule
    rule = SparkUdfInWhereRule()
    issues = rule.check(spark_query("SELECT udf(name) FROM t"))
    assert len(issues) == 0


def test_spark_udf_wrong_dialect(pg_query):
    from slowql.rules.performance.spark import SparkUdfInWhereRule
    rule = SparkUdfInWhereRule()
    issues = rule.check(pg_query("SELECT * FROM t WHERE udf(name) = 'x'"))
    assert len(issues) == 0


# cost/bigquery.py (87% -> BigQueryRepeatedSubqueryRule)
def test_bq_repeated_subquery(bq_query):
    from slowql.rules.cost.bigquery import BigQueryRepeatedSubqueryRule
    rule = BigQueryRepeatedSubqueryRule()
    issues = rule.check(bq_query("SELECT * FROM (SELECT a FROM t) x, (SELECT b FROM t) y"))
    assert len(issues) == 1


def test_bq_repeated_subquery_with_cte_ok(bq_query):
    from slowql.rules.cost.bigquery import BigQueryRepeatedSubqueryRule
    rule = BigQueryRepeatedSubqueryRule()
    issues = rule.check(bq_query("WITH cte AS (SELECT a FROM t) SELECT * FROM cte"))
    assert len(issues) == 0


def test_bq_repeated_subquery_single_ok(bq_query):
    from slowql.rules.cost.bigquery import BigQueryRepeatedSubqueryRule
    rule = BigQueryRepeatedSubqueryRule()
    issues = rule.check(bq_query("SELECT * FROM (SELECT a FROM t) x"))
    assert len(issues) == 0


# reliability/timeouts.py (87% -> ConnectByWithoutNocycleRule)
def test_connect_by_without_nocycle(oracle_query):
    from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
    rule = ConnectByWithoutNocycleRule()
    issues = rule.check(oracle_query("SELECT * FROM t CONNECT BY PRIOR id = parent_id"))
    assert len(issues) == 1


def test_connect_by_with_nocycle_ok(oracle_query):
    from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
    rule = ConnectByWithoutNocycleRule()
    issues = rule.check(oracle_query("SELECT * FROM t CONNECT BY NOCYCLE PRIOR id = parent_id"))
    assert len(issues) == 0


def test_connect_by_wrong_dialect(pg_query):
    from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
    rule = ConnectByWithoutNocycleRule()
    issues = rule.check(pg_query("SELECT * FROM t CONNECT BY PRIOR id = parent_id"))
    assert len(issues) == 0


# reliability/race_conditions.py (89% -> MergeWithoutHoldlockRule)
def test_merge_without_holdlock(tsql_query):
    from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
    rule = MergeWithoutHoldlockRule()
    issues = rule.check(tsql_query("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.val = s.val"))
    assert len(issues) == 1


def test_merge_with_holdlock_ok(tsql_query):
    from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
    rule = MergeWithoutHoldlockRule()
    issues = rule.check(tsql_query("MERGE INTO t WITH (HOLDLOCK) USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.val = s.val"))
    assert len(issues) == 0


def test_merge_with_serializable_ok(tsql_query):
    from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
    rule = MergeWithoutHoldlockRule()
    issues = rule.check(tsql_query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.val = s.val"))
    assert len(issues) == 0


# quality/duckdb.py (93% -> DuckDBOldStyleCastRule fix generation)
def test_duckdb_old_style_cast(duckdb_query):
    from slowql.rules.quality.duckdb import DuckDBOldStyleCastRule
    rule = DuckDBOldStyleCastRule()
    issues = rule.check(duckdb_query("SELECT INTEGER(col) FROM t"))
    assert len(issues) == 1


def test_duckdb_old_style_cast_wrong_dialect(pg_query):
    from slowql.rules.quality.duckdb import DuckDBOldStyleCastRule
    rule = DuckDBOldStyleCastRule()
    issues = rule.check(pg_query("SELECT INTEGER(col) FROM t"))
    assert len(issues) == 0


# reliability/spark.py (93% -> non-SELECT query_type branch)
def test_spark_overwrite_non_select_ok(spark_query):
    from slowql.rules.reliability.spark import SparkOverwriteWithoutPartitionRule
    rule = SparkOverwriteWithoutPartitionRule()
    # The rule checks INSERT OVERWRITE pattern, not query_type, so this should pass
    issues = rule.check(spark_query("INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01') SELECT * FROM s"))
    assert len(issues) == 0


# reliability/clickhouse.py (94% -> non-SELECT query_type branch)
def test_clickhouse_non_select_ok(ch_query):
    from slowql.rules.reliability.clickhouse import ClickHouseSelectWithoutFinalRule
    rule = ClickHouseSelectWithoutFinalRule()
    q = ch_query("INSERT INTO t VALUES (1, 2)")
    q = Query(raw=q.raw, normalized=q.normalized, dialect=q.dialect, location=q.location, query_type="INSERT")
    issues = rule.check(q)
    assert len(issues) == 0
