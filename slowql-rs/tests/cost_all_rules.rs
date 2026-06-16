use slowql_lib::models::{Location, Query};
use slowql_lib::rules::cost;
use slowql_lib::rules::Rule;
fn q(sql: &str, dialect: &str, qt: &str) -> Query { Query { raw: sql.to_string(), normalized: sql.to_string(), dialect: dialect.to_string(), location: Location::new(1, 1), start_offset: None, end_offset: None, tables: vec![], columns: vec![], query_type: Some(qt.to_string()), is_ddl: false, is_dynamic: false, complexity_score: 0, source_context: String::new(), ..Default::default() } }
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
