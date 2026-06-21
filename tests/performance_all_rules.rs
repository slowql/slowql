use slowql_lib::models::{Location, Query};
use slowql_lib::rules::performance;
use slowql_lib::rules::Rule;

fn q(sql: &str, dialect: &str, qt: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: dialect.to_string(),
        location: Location::new(1, 1),
        start_offset: None,
        end_offset: None,
        tables: vec![],
        columns: vec![],
        query_type: Some(qt.to_string()),
        is_ddl: false,
        is_dynamic: false,
        complexity_score: 0,
        source_context: "application".to_string(),
        ..Default::default()
    }
}

fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule {
    rules
        .iter()
        .find(|r| r.id() == id)
        .map(|r| r.as_ref())
        .unwrap_or_else(|| panic!("rule {} not found", id))
}

fn all() -> Vec<Box<dyn Rule>> {
    performance::all_rules()
}

#[test]
fn performance_rule_count() {
    assert_eq!(all().len(), 70, "Expected 70 performance rules");
}

// --- Scanning ---
#[test]
fn scan_001_select_star() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-001");
    assert!(!rule
        .check(&q("SELECT * FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT id FROM users", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn scan_002_missing_where() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-002");
    assert!(!rule
        .check(&q("DELETE FROM users", "postgresql", "DELETE"))
        .is_empty());
    assert!(rule
        .check(&q("DELETE FROM users WHERE id=1", "postgresql", "DELETE"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM users", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn scan_003_unbounded_select() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-003");
    assert!(!rule
        .check(&q("SELECT id FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT id FROM users LIMIT 10", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT COUNT(*) FROM users", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn scan_004_not_in_subquery() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-004");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE id NOT IN (SELECT id FROM s)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE id IN (1,2,3)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn scan_005_distinct() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-005");
    assert!(!rule
        .check(&q(
            "SELECT DISTINCT name FROM users",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT name FROM users", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn pg_002_count_star() {
    let r = all();
    let rule = find(&r, "PERF-PG-002");
    assert!(!rule
        .check(&q("SELECT COUNT(*) FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT COUNT(*) FROM users WHERE active=true",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT COUNT(*) FROM users", "mysql", "SELECT"))
        .is_empty());
}
#[test]
fn pg_003_not_in_nullable() {
    let r = all();
    let rule = find(&r, "PERF-PG-003");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE id NOT IN (SELECT id FROM s)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE id NOT IN (SELECT id FROM s)",
            "mysql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn pg_004_for_update() {
    let r = all();
    let rule = find(&r, "PERF-PG-004");
    assert!(!rule
        .check(&q("SELECT * FROM t FOR UPDATE", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t FOR UPDATE NOWAIT",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t FOR UPDATE", "mysql", "SELECT"))
        .is_empty());
}
#[test]
fn mysql_001_for_update_limit() {
    let r = all();
    let rule = find(&r, "PERF-MYSQL-001");
    assert!(!rule
        .check(&q("SELECT * FROM t FOR UPDATE", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t FOR UPDATE LIMIT 10", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t FOR UPDATE", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn mysql_002_order_rand() {
    let r = all();
    let rule = find(&r, "PERF-MYSQL-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t ORDER BY RAND() LIMIT 1",
            "mysql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t ORDER BY id", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t ORDER BY RAND()",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn mysql_003_force_index() {
    let r = all();
    let rule = find(&r, "PERF-MYSQL-003");
    assert!(!rule
        .check(&q("SELECT * FROM t FORCE INDEX (idx1)", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t FORCE INDEX (idx1)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn bq_001_distinct_unnest() {
    let r = all();
    let rule = find(&r, "PERF-BQ-001");
    assert!(!rule
        .check(&q(
            "SELECT DISTINCT x FROM UNNEST(arr) x",
            "bigquery",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT DISTINCT x FROM t", "bigquery", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT DISTINCT x FROM UNNEST(arr) x",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn bq_002_regexp() {
    let r = all();
    let rule = find(&r, "PERF-BQ-002");
    assert!(!rule
        .check(&q(
            "SELECT REGEXP_CONTAINS(col, 'pat') FROM t",
            "bigquery",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT REGEXP_CONTAINS(col, 'pat') FROM t",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

// --- Indexing ---
#[test]
fn idx_001_function_where() {
    let r = all();
    let rule = find(&r, "PERF-IDX-001");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE LOWER(email) = 'x'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE email = 'x'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn idx_002_leading_wildcard() {
    let r = all();
    let rule = find(&r, "PERF-IDX-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE name LIKE '%john'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE name LIKE 'john%'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn idx_004_or_where() {
    let r = all();
    let rule = find(&r, "PERF-IDX-004");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE a=1 OR b=2",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn idx_005_deep_offset() {
    let r = all();
    let rule = find(&r, "PERF-IDX-005");
    assert!(!rule
        .check(&q("SELECT * FROM t OFFSET 5000", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t OFFSET 10", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn idx_008_coalesce() {
    let r = all();
    let rule = find(&r, "PERF-IDX-008");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE COALESCE(status, 'x') = 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn pg_001_ilike() {
    let r = all();
    let rule = find(&r, "PERF-PG-001");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE name ILIKE '%foo%'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE name ILIKE '%foo%'",
            "mysql",
            "SELECT"
        ))
        .is_empty());
}

// --- Joins ---
#[test]
fn join_001_cross() {
    let r = all();
    let rule = find(&r, "PERF-JOIN-001");
    assert!(!rule
        .check(&q("SELECT * FROM a CROSS JOIN b", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM a JOIN b ON a.id=b.id",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn join_002_too_many() {
    let r = all();
    let rule = find(&r, "PERF-JOIN-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1 JOIN e ON 1=1 JOIN f ON 1=1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM a JOIN b ON a.id=b.id",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn join_003_left_not_null() {
    let r = all();
    let rule = find(&r, "PERF-JOIN-003");
    assert!(!rule
        .check(&q(
            "SELECT * FROM a LEFT JOIN b ON a.id=b.id WHERE b.col IS NOT NULL",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM a LEFT JOIN b ON a.id=b.id",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

// --- Aggregation ---
#[test]
fn agg_001_unfiltered() {
    let r = all();
    let rule = find(&r, "PERF-AGG-001");
    assert!(!rule
        .check(&q("SELECT COUNT(*) FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT COUNT(*) FROM users WHERE active=true",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn agg_002_order_subquery() {
    let r = all();
    let rule = find(&r, "PERF-AGG-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM (SELECT * FROM t ORDER BY id) x",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn agg_003_having_no_group() {
    let r = all();
    let rule = find(&r, "PERF-AGG-003");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t HAVING COUNT(*) > 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t GROUP BY x HAVING COUNT(*) > 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

// --- Locking ---
#[test]
fn lock_001_table_lock() {
    let r = all();
    let rule = find(&r, "PERF-LOCK-001");
    assert!(!rule
        .check(&q("SELECT * FROM t WITH (TABLOCK)", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t WITH (TABLOCK)", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn lock_002_nolock() {
    let r = all();
    let rule = find(&r, "PERF-LOCK-002");
    assert!(!rule
        .check(&q("SELECT * FROM t WITH (NOLOCK)", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t WITH (NOLOCK)", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn lock_004_isolation() {
    let r = all();
    let rule = find(&r, "PERF-LOCK-004");
    assert!(!rule
        .check(&q(
            "BEGIN TRANSACTION; UPDATE t SET x=1; COMMIT",
            "tsql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; BEGIN TRANSACTION; COMMIT",
            "tsql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn ora_001_for_update() {
    let r = all();
    let rule = find(&r, "PERF-ORA-001");
    assert!(!rule
        .check(&q("SELECT * FROM t FOR UPDATE", "oracle", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t FOR UPDATE NOWAIT", "oracle", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t FOR UPDATE", "postgresql", "SELECT"))
        .is_empty());
}

// --- Execution ---
#[test]
fn scalar_001_udf() {
    let r = all();
    let rule = find(&r, "PERF-SCALAR-001");
    assert!(!rule
        .check(&q("SELECT dbo.MyFunc(id) FROM t", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT dbo.MyFunc(id) FROM t", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn sort_001_non_indexed() {
    let r = all();
    let rule = find(&r, "PERF-SORT-001");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t ORDER BY description",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t ORDER BY id", "postgresql", "SELECT"))
        .is_empty());
}

// --- Cursors ---
#[test]
fn cursor_001() {
    let r = all();
    let rule = find(&r, "PERF-CURSOR-001");
    assert!(!rule
        .check(&q(
            "DECLARE cur CURSOR FOR SELECT * FROM t",
            "tsql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule.check(&q("SELECT 1", "tsql", "SELECT")).is_empty());
}
#[test]
fn cursor_002_while() {
    let r = all();
    let rule = find(&r, "PERF-CURSOR-002");
    assert!(!rule
        .check(&q(
            "WHILE (@i > 0) BEGIN UPDATE t SET x=1; END",
            "tsql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "WHILE (@i > 0) BEGIN UPDATE t SET x=1; END",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn cursor_003_loop_join() {
    let r = all();
    let rule = find(&r, "PERF-CURSOR-003");
    assert!(!rule
        .check(&q(
            "SELECT * FROM a INNER LOOP JOIN b ON a.id=b.id",
            "tsql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM a INNER LOOP JOIN b ON a.id=b.id",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

// --- Hints ---
#[test]
fn hint_001_optimizer() {
    let r = all();
    let rule = find(&r, "PERF-HINT-001");
    assert!(!rule
        .check(&q("SELECT * FROM t OPTION (FORCE ORDER)", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t OPTION (FORCE ORDER)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn hint_002_index() {
    let r = all();
    let rule = find(&r, "PERF-HINT-002");
    assert!(!rule
        .check(&q("SELECT * FROM t FORCE INDEX (idx1)", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t", "mysql", "SELECT"))
        .is_empty());
}
#[test]
fn hint_003_maxdop() {
    let r = all();
    let rule = find(&r, "PERF-HINT-003");
    assert!(!rule
        .check(&q("SELECT * FROM t OPTION (MAXDOP 1)", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t", "tsql", "SELECT"))
        .is_empty());
}

// --- Memory ---
#[test]
fn mem_001_large_in() {
    let r = all();
    let rule = find(&r, "PERF-MEM-001");
    let vals = (0..60).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT * FROM t WHERE id IN ({})", vals);
    assert!(!rule.check(&q(&sql, "postgresql", "SELECT")).is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE id IN (1,2,3)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn mem_004_group_high_card() {
    let r = all();
    let rule = find(&r, "PERF-MEM-004");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t GROUP BY created_at",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t GROUP BY status",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn tsql_002_temp_no_index() {
    let r = all();
    let rule = find(&r, "PERF-TSQL-002");
    assert!(!rule
        .check(&q("SELECT * INTO #tmp FROM t", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * INTO #tmp FROM t", "postgresql", "SELECT"))
        .is_empty());
}

// --- Batching ---
#[test]
fn batch_001_unbatched() {
    let r = all();
    let rule = find(&r, "PERF-BATCH-001");
    assert!(!rule
        .check(&q("DELETE FROM users", "postgresql", "DELETE"))
        .is_empty());
    assert!(rule
        .check(&q("DELETE FROM users LIMIT 1000", "postgresql", "DELETE"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM users", "postgresql", "SELECT"))
        .is_empty());
}

// --- Network / dialect-specific ---
#[test]
fn net_001_excessive_cols() {
    let r = all();
    let rule = find(&r, "PERF-NET-001");
    let cols = (0..25)
        .map(|i| format!("c{}", i))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {} FROM t", cols);
    assert!(!rule.check(&q(&sql, "postgresql", "SELECT")).is_empty());
    assert!(rule
        .check(&q("SELECT a, b, c FROM t", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn tsql_001_nocount() {
    let r = all();
    let rule = find(&r, "PERF-TSQL-001");
    assert!(!rule
        .check(&q(
            "CREATE PROCEDURE sp_test AS BEGIN SELECT 1 END",
            "tsql",
            "CREATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "CREATE PROCEDURE sp_test AS BEGIN SET NOCOUNT ON; SELECT 1 END",
            "tsql",
            "CREATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "CREATE PROCEDURE sp_test AS BEGIN SELECT 1 END",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
}
#[test]
fn rs_001_select_star() {
    let r = all();
    let rule = find(&r, "PERF-RS-001");
    assert!(!rule
        .check(&q("SELECT * FROM t", "redshift", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn rs_002_order_no_limit() {
    let r = all();
    let rule = find(&r, "PERF-RS-002");
    assert!(!rule
        .check(&q("SELECT * FROM t ORDER BY id", "redshift", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t ORDER BY id LIMIT 10",
            "redshift",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn ch_001_no_prewhere() {
    let r = all();
    let rule = find(&r, "PERF-CH-001");
    assert!(!rule
        .check(&q("SELECT * FROM t WHERE x=1", "clickhouse", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t PREWHERE x=1 WHERE y=2",
            "clickhouse",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t WHERE x=1", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn ch_003_mutation() {
    let r = all();
    let rule = find(&r, "PERF-CH-003");
    assert!(!rule
        .check(&q(
            "ALTER TABLE t UPDATE x=1 WHERE id=1",
            "clickhouse",
            "ALTER"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "ALTER TABLE t UPDATE x=1 WHERE id=1",
            "postgresql",
            "ALTER"
        ))
        .is_empty());
}
#[test]
fn presto_001_cross_join() {
    let r = all();
    let rule = find(&r, "PERF-PRESTO-001");
    assert!(!rule
        .check(&q("SELECT * FROM a, b WHERE a.x=b.x", "presto", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM a JOIN b ON a.x=b.x", "presto", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM a, b", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn presto_002_order_no_limit() {
    let r = all();
    let rule = find(&r, "PERF-PRESTO-002");
    assert!(!rule
        .check(&q("SELECT * FROM t ORDER BY id", "presto", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t ORDER BY id LIMIT 10",
            "presto",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn spark_001_broadcast() {
    let r = all();
    let rule = find(&r, "PERF-SPARK-001");
    assert!(!rule
        .check(&q(
            "SELECT /*+ BROADCAST(t) */ * FROM t JOIN s ON t.id=s.id",
            "spark",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t JOIN s ON t.id=s.id", "spark", "SELECT"))
        .is_empty());
}
#[test]
fn sqlite_001_wal() {
    let r = all();
    let rule = find(&r, "PERF-SQLITE-001");
    assert!(!rule
        .check(&q("PRAGMA journal_mode=DELETE", "sqlite", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("PRAGMA journal_mode=wal", "sqlite", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("PRAGMA journal_mode=DELETE", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn sqlite_002_like() {
    let r = all();
    let rule = find(&r, "PERF-SQLITE-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE name LIKE 'foo%'",
            "sqlite",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE name LIKE 'foo%'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn duck_001_copy_format() {
    let r = all();
    let rule = find(&r, "PERF-DUCK-001");
    assert!(!rule
        .check(&q("COPY t FROM 'file.csv'", "duckdb", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "COPY t FROM 'file.csv' (FORMAT CSV)",
            "duckdb",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("COPY t FROM 'file.csv'", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn mysql_004_group_sort() {
    let r = all();
    let rule = find(&r, "PERF-MYSQL-004");
    assert!(!rule
        .check(&q("SELECT x FROM t GROUP BY x", "mysql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT x FROM t GROUP BY x ORDER BY x",
            "mysql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT x FROM t GROUP BY x", "postgresql", "SELECT"))
        .is_empty());
}

// --- Missing rules added ---
#[test]
fn idx_006_composite_order() {
    let r = all();
    let rule = find(&r, "PERF-IDX-006");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE user_id = 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE tenant_id = 1 AND user_id = 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn idx_007_non_sargable_or() {
    let r = all();
    let rule = find(&r, "PERF-IDX-007");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE email = 'x' OR name = 'y'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE email = 'x'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn idx_009_negation() {
    let r = all();
    let rule = find(&r, "PERF-IDX-009");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE status != 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE status <> 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE status = 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn mem_003_order_subquery_no_limit() {
    let r = all();
    let rule = find(&r, "PERF-MEM-003");
    assert!(!rule
        .check(&q(
            "SELECT * FROM (SELECT * FROM t ORDER BY id) x",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn net_002_large_object() {
    let r = all();
    let rule = find(&r, "PERF-NET-002");
    assert!(!rule
        .check(&q(
            "SELECT id, content FROM articles",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT id, content FROM articles WHERE id = 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT id FROM articles", "postgresql", "SELECT"))
        .is_empty());
}

// --- PERF-SCAN-003 adhoc context guard ---

#[test]
fn scan_003_adhoc_no_fire() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-003");
    let mut query = q("SELECT id FROM users", "postgresql", "SELECT");
    query.source_context = "adhoc".to_string();
    assert!(
        rule.check(&query).is_empty(),
        "PERF-SCAN-003 should not fire in adhoc context"
    );
}

#[test]
fn scan_003_empty_context_no_fire() {
    let r = all();
    let rule = find(&r, "PERF-SCAN-003");
    let mut query = q("SELECT id FROM users", "postgresql", "SELECT");
    query.source_context = String::new();
    assert!(
        rule.check(&query).is_empty(),
        "PERF-SCAN-003 should not fire with empty context"
    );
}

// --- PERF-IDX-004 same-column OR guard ---

#[test]
fn idx_004_same_column_or_no_fire() {
    let r = all();
    let rule = find(&r, "PERF-IDX-004");
    assert!(
        rule.check(&q(
            "SELECT id FROM users WHERE status = 'active' OR status = 'pending'",
            "postgresql",
            "SELECT"
        ))
        .is_empty(),
        "same-column OR should not fire PERF-IDX-004"
    );
}

#[test]
fn idx_004_different_column_or_fires() {
    let r = all();
    let rule = find(&r, "PERF-IDX-004");
    assert!(
        !rule
            .check(&q(
                "SELECT id FROM users WHERE status = 'active' OR role = 'admin'",
                "postgresql",
                "SELECT"
            ))
            .is_empty(),
        "cross-column OR should fire PERF-IDX-004"
    );
}

// --- PERF-IDX-007 numeric literal guard ---

#[test]
fn idx_007_tautology_no_fire() {
    let r = all();
    let rule = find(&r, "PERF-IDX-007");
    assert!(
        rule.check(&q(
            "SELECT * FROM users WHERE id = 1 OR 1 = 1",
            "postgresql",
            "SELECT"
        ))
        .is_empty(),
        "tautology OR 1=1 should not fire PERF-IDX-007"
    );
}

// --- PERF-AGG-001 GROUP BY guard ---

#[test]
fn agg_001_group_by_no_fire() {
    let r = all();
    let rule = find(&r, "PERF-AGG-001");
    assert!(
        rule.check(&q(
            "SELECT department_id, COUNT(*) FROM employees GROUP BY department_id",
            "postgresql",
            "SELECT"
        ))
        .is_empty(),
        "GROUP BY without WHERE should not fire PERF-AGG-001"
    );
}

#[test]
fn agg_001_no_where_no_group_fires() {
    let r = all();
    let rule = find(&r, "PERF-AGG-001");
    assert!(
        !rule
            .check(&q("SELECT COUNT(*) FROM users", "postgresql", "SELECT"))
            .is_empty(),
        "COUNT without WHERE or GROUP BY should fire PERF-AGG-001"
    );
}

#[test]
fn join_003_only_fires_on_left_join_alias_is_not_null() {
    let r = all();
    let rule = find(&r, "PERF-JOIN-003");

    // True positive: IS NOT NULL on the right-side LEFT JOIN alias
    assert!(
        !rule.check(&q(
            "SELECT u.id FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE o.id IS NOT NULL",
            "postgresql",
            "SELECT"
        )).is_empty()
    );

    // False positive before fix: IS NOT NULL on base table alias must NOT fire
    assert!(
        rule.check(&q(
            "SELECT u.id FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.deleted_at IS NOT NULL",
            "postgresql",
            "SELECT"
        )).is_empty()
    );

    // Cal.com regression: no IS NOT NULL on LEFT JOIN alias, so must NOT fire
    assert!(
        rule.check(&q(
            r#"SELECT
  TO_TIMESTAMP(sc."googleChannelExpiration"::bigint / 1000 - 86400)::date as "humanReadableExpireDate",
  sc.*
FROM
  "SelectedCalendar" sc
  LEFT JOIN "users" AS u ON u.id = sc."userId"
  LEFT JOIN "Membership" AS m ON m."userId" = u.id
  LEFT JOIN "Team" AS t ON t.id = m."teamId"
  LEFT JOIN "TeamFeatures" AS tf ON tf."teamId" = t.id
WHERE
  tf."featureId" = 'calendar-cache'
  AND tf.enabled = true
  AND sc."integration" = 'google_calendar'
  AND (
      sc."googleChannelExpiration" IS NULL
    OR (
          sc."googleChannelExpiration" IS NOT NULL
          AND TO_TIMESTAMP(sc."googleChannelExpiration"::bigint / 1000 - 86400)::date < CURRENT_TIMESTAMP
      )
    )"#,
            "postgresql",
            "SELECT"
        )).is_empty()
    );
}

#[test]
fn batch_002_while_with_limit() {
    let r = all();
    let rule = find(&r, "PERF-BATCH-002");
    assert!(rule.check(&q("WHILE @count > 0 BEGIN DELETE TOP (1000) FROM t WHERE x = 1 END", "tsql", "SELECT")).is_empty());
}

#[test]
fn mem_002_unbounded_temp() {
    let r = all();
    let rule = find(&r, "PERF-MEM-002");
    assert!(!rule.check(&q("SELECT * INTO #temp FROM large_table", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * INTO #temp FROM large_table WHERE id = 1", "tsql", "SELECT")).is_empty());
}

#[test]
fn tsql_003_convert_in_join() {
    let r = all();
    let rule = find(&r, "PERF-TSQL-003");
    assert!(!rule.check(&q("SELECT * FROM a JOIN b ON CONVERT(VARCHAR, a.id) = b.id", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM a JOIN b ON a.id = b.id", "tsql", "SELECT")).is_empty());
}

#[test]
fn net_001_many_columns() {
    let r = all();
    let rule = find(&r, "PERF-NET-001");
    let cols = (0..25).map(|i| format!("col{}", i)).collect::<Vec<_>>().join(", ");
    let sql = format!("SELECT {} FROM t", cols);
    assert!(!rule.check(&q(&sql, "postgresql", "SELECT")).is_empty());
}

#[test]
fn lock_003_long_transaction() {
    let r = all();
    let rule = find(&r, "PERF-LOCK-003");
    let long_sql = format!("BEGIN TRANSACTION; {} COMMIT", "UPDATE t SET x = 1; ".repeat(30));
    assert!(!rule.check(&q(&long_sql, "tsql", "SELECT")).is_empty());
}

#[test]
fn execution_sort_001() {
    let r = all();
    let rule = find(&r, "PERF-SORT-001");
    assert!(!rule.check(&q("SELECT * FROM t ORDER BY description", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM t ORDER BY id", "postgresql", "SELECT")).is_empty());
}
