use slowql_lib::models::{Location, Query};
use slowql_lib::rules::cost;
use slowql_lib::rules::Rule;
fn q(sql: &str, dialect: &str, qt: &str) -> Query { Query { raw: sql.to_string(), normalized: sql.to_string(), dialect: dialect.to_string(), location: Location::new(1, 1), start_offset: None, end_offset: None, tables: vec![], columns: vec![], query_type: Some(qt.to_string()), is_ddl: false, is_dynamic: false, complexity_score: 0, source_context: "application".to_string(), ..Default::default() } }
fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule { rules.iter().find(|r| r.id() == id).map(|r| r.as_ref()).unwrap_or_else(|| panic!("rule {} not found", id)) }
fn all() -> Vec<Box<dyn Rule>> { cost::all_rules() }

#[test] fn cost_rule_count() { assert_eq!(all().len(), 37); }
#[test] fn compute_001() { let r=all(); let rule=find(&r,"COST-COMPUTE-001"); assert!(!rule.check(&q("SELECT id FROM users","postgresql","SELECT")).is_empty()); assert!(rule.check(&q("SELECT id FROM users WHERE active=true","postgresql","SELECT")).is_empty()); }
#[test] fn compute_002() { let r=all(); let rule=find(&r,"COST-COMPUTE-002"); assert!(!rule.check(&q("SELECT ROW_NUMBER() OVER () FROM t","postgresql","SELECT")).is_empty()); assert!(rule.check(&q("SELECT ROW_NUMBER() OVER (PARTITION BY id) FROM t","postgresql","SELECT")).is_empty()); }
#[test] fn storage_001() { let r=all(); let rule=find(&r,"COST-STORAGE-001"); assert!(!rule.check(&q("INSERT INTO t SELECT * FROM s","postgresql","INSERT")).is_empty()); assert!(rule.check(&q("INSERT INTO t SELECT id FROM s","postgresql","INSERT")).is_empty()); }
#[test] fn io_001() { let r=all(); let rule=find(&r,"COST-IO-001"); assert!(!rule.check(&q("SELECT * FROM (SELECT * FROM t ORDER BY id) x","postgresql","SELECT")).is_empty()); }
#[test] fn page_002() { let r=all(); let rule=find(&r,"COST-PAGE-002"); assert!(!rule.check(&q("SELECT * FROM t OFFSET 5000","postgresql","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t OFFSET 10","postgresql","SELECT")).is_empty()); }
#[test] fn bq_001() { let r=all(); let rule=find(&r,"COST-BQ-001"); assert!(!rule.check(&q("SELECT * FROM t","bigquery","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t","postgresql","SELECT")).is_empty()); }
#[test] fn sf_001() { let r=all(); let rule=find(&r,"COST-SF-001"); assert!(!rule.check(&q("SELECT * FROM t","snowflake","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t","postgresql","SELECT")).is_empty()); }
#[test] fn ch_001() { let r=all(); let rule=find(&r,"COST-CH-001"); assert!(!rule.check(&q("SELECT * FROM t","clickhouse","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t","postgresql","SELECT")).is_empty()); }
#[test] fn sf_variant() { let r=all(); let rule=find(&r,"PERF-SF-001"); assert!(!rule.check(&q("SELECT * FROM t WHERE data:field = 'x'","snowflake","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t WHERE data:field = 'x'","postgresql","SELECT")).is_empty()); }
#[test] fn rel_sf_001() { let r=all(); let rule=find(&r,"REL-SF-001"); assert!(!rule.check(&q("COPY INTO t FROM @stage","snowflake","SELECT")).is_empty()); assert!(rule.check(&q("COPY INTO t FROM @stage ON_ERROR='CONTINUE'","snowflake","SELECT")).is_empty()); }
#[test] fn spark_001() { let r=all(); let rule=find(&r,"COST-SPARK-001"); assert!(!rule.check(&q("SELECT id FROM t","spark","SELECT")).is_empty()); assert!(rule.check(&q("SELECT id FROM t WHERE dt='2024'","spark","SELECT")).is_empty()); }
#[test] fn tsql_cursor() { let r=all(); let rule=find(&r,"COST-TSQL-001"); assert!(!rule.check(&q("DECLARE cur CURSOR FOR SELECT * FROM t","tsql","SELECT")).is_empty()); assert!(rule.check(&q("DECLARE cur CURSOR FAST_FORWARD FOR SELECT * FROM t","tsql","SELECT")).is_empty()); }

// --- COST-PARTITION-001: metadata-driven partition rule ---

#[test]
fn partition_001_no_metadata_no_fire() {
    // Without metadata, COST-PARTITION-001 must never fire
    let r = all();
    let rule = find(&r, "COST-PARTITION-001");
    // check() without context always returns empty
    assert!(rule.check(&q("SELECT * FROM transactions", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM events", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM logs", "postgresql", "SELECT")).is_empty());
}

#[test]
fn partition_001_with_context_fires() {
    use slowql_lib::config::TableMetadata;
    use slowql_lib::rules::base::RuleContext;

    let r = all();
    let rule = find(&r, "COST-PARTITION-001");

    let mut partitioned = std::collections::HashMap::new();
    partitioned.insert("transactions".to_string(), vec!["created_at".to_string()]);

    let meta = TableMetadata {
        large_tables: vec!["transactions".to_string()],
        partitioned_tables: partitioned,
    };
    let ctx = RuleContext {
        schema: None,
        table_metadata: &meta,
        source_context: "application",
    };

    // Query without partition column in WHERE: must fire
    let mut query = q("SELECT id, amount FROM transactions WHERE account_id = 42", "postgresql", "SELECT");
    query.tables = vec!["transactions".to_string()];
    query.facts = Some(slowql_lib::query_analysis::QueryFacts::from_sql(&query.raw, "postgresql"));
    let issues = rule.check_with_context(&query, &ctx);
    assert!(!issues.is_empty(), "should fire when partition column missing from WHERE");
    assert_eq!(issues[0].rule_id, "COST-PARTITION-001");
}

#[test]
fn partition_001_with_context_no_fire_when_partition_col_present() {
    use slowql_lib::config::TableMetadata;
    use slowql_lib::rules::base::RuleContext;

    let r = all();
    let rule = find(&r, "COST-PARTITION-001");

    let mut partitioned = std::collections::HashMap::new();
    partitioned.insert("transactions".to_string(), vec!["created_at".to_string()]);

    let meta = TableMetadata {
        large_tables: vec!["transactions".to_string()],
        partitioned_tables: partitioned,
    };
    let ctx = RuleContext {
        schema: None,
        table_metadata: &meta,
        source_context: "application",
    };

    // Query WITH partition column in WHERE: must not fire
    let mut query = q("SELECT id, amount FROM transactions WHERE created_at >= '2024-01-01' AND account_id = 42", "postgresql", "SELECT");
    query.tables = vec!["transactions".to_string()];
    query.facts = Some(slowql_lib::query_analysis::QueryFacts::from_sql(&query.raw, "postgresql"));
    let issues = rule.check_with_context(&query, &ctx);
    assert!(issues.is_empty(), "should not fire when partition column is in WHERE");
}

#[test]
fn partition_001_non_partitioned_table_no_fire() {
    use slowql_lib::config::TableMetadata;
    use slowql_lib::rules::base::RuleContext;

    let r = all();
    let rule = find(&r, "COST-PARTITION-001");

    let mut partitioned = std::collections::HashMap::new();
    partitioned.insert("transactions".to_string(), vec!["created_at".to_string()]);

    let meta = TableMetadata {
        large_tables: vec!["transactions".to_string()],
        partitioned_tables: partitioned,
    };
    let ctx = RuleContext {
        schema: None,
        table_metadata: &meta,
        source_context: "application",
    };

    // Query on a table NOT declared as partitioned: must not fire
    let mut query = q("SELECT * FROM users", "postgresql", "SELECT");
    query.tables = vec!["users".to_string()];
    query.facts = Some(slowql_lib::query_analysis::QueryFacts::from_sql(&query.raw, "postgresql"));
    let issues = rule.check_with_context(&query, &ctx);
    assert!(issues.is_empty(), "should not fire on non-partitioned table");
}

#[test]
fn partition_001_schema_partition_metadata() {
    use slowql_lib::config::TableMetadata;
    use slowql_lib::rules::base::RuleContext;
    use slowql_lib::schema::{Schema, Table, Column};
    use std::collections::HashMap;

    let r = all();
    let rule = find(&r, "COST-PARTITION-001");

    let meta = TableMetadata::default(); // no config metadata

    let mut tables = HashMap::new();
    tables.insert("events".to_string(), Table {
        name: "events".to_string(),
        columns: vec![
            Column { name: "id".to_string(), col_type: "INT".to_string(), nullable: false, primary_key: true, foreign_key: None },
            Column { name: "event_date".to_string(), col_type: "DATE".to_string(), nullable: false, primary_key: false, foreign_key: None },
        ],
        indexes: vec![],
        primary_key: vec!["id".to_string()],
        partition_columns: vec!["event_date".to_string()],
        estimated_rows: Some(50_000_000),
    });
    let schema = Schema { tables, dialect: "postgresql".to_string() };

    let ctx = RuleContext {
        schema: Some(&schema),
        table_metadata: &meta,
        source_context: "application",
    };

    // Query without partition column: fires from schema metadata
    let mut query = q("SELECT * FROM events WHERE user_id = 1", "postgresql", "SELECT");
    query.tables = vec!["events".to_string()];
    query.facts = Some(slowql_lib::query_analysis::QueryFacts::from_sql(&query.raw, "postgresql"));
    let issues = rule.check_with_context(&query, &ctx);
    assert!(!issues.is_empty(), "should fire from schema partition metadata");

    // Query WITH partition column: does not fire
    let mut query2 = q("SELECT * FROM events WHERE event_date = '2024-01-01'", "postgresql", "SELECT");
    query2.tables = vec!["events".to_string()];
    query2.facts = Some(slowql_lib::query_analysis::QueryFacts::from_sql(&query2.raw, "postgresql"));
    let issues2 = rule.check_with_context(&query2, &ctx);
    assert!(issues2.is_empty(), "should not fire when schema partition column is in WHERE");
}
