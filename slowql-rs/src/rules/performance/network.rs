use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct ExcessiveColumnCountRule;
impl Rule for ExcessiveColumnCountRule {
    fn id(&self) -> &'static str { "PERF-NET-001" }
    fn name(&self) -> &'static str { "Excessive Column Count in SELECT" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfNetwork) }
    fn impact(&self) -> &'static str { "Wide result sets waste network bandwidth and consume more memory." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() { return Vec::new(); }
        if query.raw_upper().contains("SELECT *") { return Vec::new(); }
        // Count commas in the SELECT list before FROM
        let upper = query.raw_upper();
        if let Some(from_pos) = upper.find("FROM") {
            let select_part = &query.raw[..from_pos.min(query.raw.len())];
            let comma_count = select_part.matches(',').count();
            if comma_count > 20 {
                let msg = format!("SELECT with {} columns - consider reducing.", comma_count + 1);
                let snip = &query.raw[..query.raw.len().min(100)];
                return vec![self.build_issue(query, &msg, snip)];
            }
        }
        Vec::new()
    }
}

struct MissingSetNocountRule;
static PAT_NOCOUNT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+(?:OR\s+ALTER\s+)?PROC(?:EDURE)?\b").unwrap());
impl Rule for MissingSetNocountRule {
    fn id(&self) -> &'static str { "PERF-TSQL-001" }
    fn name(&self) -> &'static str { "Missing SET NOCOUNT ON" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfNetwork) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Each DML statement sends a row count message to the client, wasting bandwidth." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !PAT_NOCOUNT.is_match(&query.raw) { return Vec::new(); }
        if query.raw_upper().contains("SET NOCOUNT ON") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "Stored procedure without SET NOCOUNT ON - unnecessary network overhead.", snip)]
    }
}

// Dialect-specific scanning rules that belong in the performance dimension
struct RedshiftSelectStarRule;
static PAT_RS_STAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSELECT\s+\*").unwrap());
impl Rule for RedshiftSelectStarRule {
    fn id(&self) -> &'static str { "PERF-RS-001" }
    fn name(&self) -> &'static str { "SELECT * on Redshift Columnar Storage" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["redshift"]) }
    fn impact(&self) -> &'static str { "Redshift charges for bytes scanned. SELECT * reads 100x more data than needed." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_RS_STAR.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "SELECT * on Redshift - reads all columns from columnar storage.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct OrderByWithoutLimitRedshiftRule;
impl Rule for OrderByWithoutLimitRedshiftRule {
    fn id(&self) -> &'static str { "PERF-RS-002" }
    fn name(&self) -> &'static str { "ORDER BY Without LIMIT on Redshift" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfSort) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["redshift"]) }
    fn impact(&self) -> &'static str { "All rows must be sent to the leader node for global sorting." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !query.is_select() { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("ORDER BY") { return Vec::new(); }
        if upper.contains("LIMIT") || upper.contains("TOP") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "ORDER BY without LIMIT on Redshift - full redistribution to leader node.", snip)]
    }
}

struct NotInOnRedshiftRule;
static PAT_RS_NOTIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bNOT\s+IN\s*\(\s*SELECT\b").unwrap());
impl Rule for NotInOnRedshiftRule {
    fn id(&self) -> &'static str { "PERF-RS-003" }
    fn name(&self) -> &'static str { "NOT IN on Redshift (Hash Join Explosion)" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["redshift"]) }
    fn impact(&self) -> &'static str { "NOT IN forces Redshift to build a hash table. With NULLs it degrades to a nested loop." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_RS_NOTIN.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "NOT IN with subquery on Redshift - use NOT EXISTS or LEFT JOIN/NULL.", m.as_str())]
        }).unwrap_or_default()
    }
}

// ClickHouse
struct ClickHouseSelectWithoutPrewhereRule;
static PAT_CH_PRE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSELECT\b.*\bWHERE\b").unwrap());
impl Rule for ClickHouseSelectWithoutPrewhereRule {
    fn id(&self) -> &'static str { "PERF-CH-001" }
    fn name(&self) -> &'static str { "SELECT Without PREWHERE" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["clickhouse"]) }
    fn impact(&self) -> &'static str { "Without PREWHERE, ClickHouse reads all columns from disk before filtering." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !PAT_CH_PRE.is_match(&query.raw) { return Vec::new(); }
        if query.raw_upper().contains("PREWHERE") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "WHERE without PREWHERE - consider PREWHERE for I/O reduction.", snip)]
    }
}

struct ClickHouseJoinWithoutGlobalRule;
impl Rule for ClickHouseJoinWithoutGlobalRule {
    fn id(&self) -> &'static str { "PERF-CH-002" }
    fn name(&self) -> &'static str { "JOIN Without GLOBAL on Distributed Table" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["clickhouse"]) }
    fn impact(&self) -> &'static str { "Without GLOBAL, each shard executes the right-side subquery independently." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("JOIN") { return Vec::new(); }
        if upper.contains("GLOBAL") { return Vec::new(); }
        static PAT_CH_JOIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bJOIN\s*\(\s*SELECT\b").unwrap());
        if !PAT_CH_JOIN.is_match(&query.raw) { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "JOIN with subquery without GLOBAL - redundant execution on each shard.", snip)]
    }
}

struct ClickHouseMutationRule;
static PAT_CH_MUT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bALTER\s+TABLE\s+\w+\s+(?:UPDATE|DELETE)\b").unwrap());
impl Rule for ClickHouseMutationRule {
    fn id(&self) -> &'static str { "PERF-CH-003" }
    fn name(&self) -> &'static str { "ClickHouse Mutation (ALTER UPDATE/DELETE)" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["clickhouse"]) }
    fn impact(&self) -> &'static str { "Mutations rewrite entire data parts asynchronously. Not designed for frequent modifications." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_CH_MUT.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "ClickHouse mutation detected - heavy async part rewrite.", m.as_str())]
        }).unwrap_or_default()
    }
}

// Presto/Trino
struct PrestoCrossJoinRule;
static PAT_PRESTO_CROSS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bFROM\s+\w+\s*,\s*\w+\b").unwrap());
impl Rule for PrestoCrossJoinRule {
    fn id(&self) -> &'static str { "PERF-PRESTO-001" }
    fn name(&self) -> &'static str { "Implicit Cross-Join on Distributed Engine" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["presto", "trino"]) }
    fn impact(&self) -> &'static str { "Cross-joins on distributed engines shuffle all data. Two 1M-row tables produce 1 trillion intermediate rows." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if query.raw_upper().contains("JOIN") { return Vec::new(); }
        PAT_PRESTO_CROSS.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "Implicit cross-join detected - use explicit JOIN with ON clause.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct PrestoOrderByWithoutLimitRule;
impl Rule for PrestoOrderByWithoutLimitRule {
    fn id(&self) -> &'static str { "PERF-PRESTO-002" }
    fn name(&self) -> &'static str { "ORDER BY Without LIMIT on Distributed Engine" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfSort) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["presto", "trino"]) }
    fn impact(&self) -> &'static str { "All rows are sent to the coordinator node for sorting, causing OOM." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !query.is_select() { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("ORDER BY") || upper.contains("LIMIT") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "ORDER BY without LIMIT on Presto/Trino - coordinator OOM risk.", snip)]
    }
}

// Spark
struct SparkBroadcastHintRule;
static PAT_SPARK_BC: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/\*\+\s*BROADCAST\s*\(").unwrap());
impl Rule for SparkBroadcastHintRule {
    fn id(&self) -> &'static str { "PERF-SPARK-001" }
    fn name(&self) -> &'static str { "BROADCAST Hint on Large Table" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["spark", "databricks"]) }
    fn impact(&self) -> &'static str { "Broadcasting a large table causes OOM on executors and driver." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_SPARK_BC.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "BROADCAST hint detected - ensure table fits in executor memory.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct SparkUdfInWhereRule;
static PAT_SPARK_UDF: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.*\b(?:udf|UDF)\s*\(").unwrap());
impl Rule for SparkUdfInWhereRule {
    fn id(&self) -> &'static str { "PERF-SPARK-002" }
    fn name(&self) -> &'static str { "UDF in WHERE Prevents Pushdown" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["spark", "databricks"]) }
    fn impact(&self) -> &'static str { "Without pushdown, Spark reads the entire table from storage." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_SPARK_UDF.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "UDF in WHERE clause - prevents predicate pushdown to data source.", m.as_str())]
        }).unwrap_or_default()
    }
}

// SQLite
struct SqliteWalModeRule;
static PAT_SQLITE_WAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bPRAGMA\s+journal_mode\s*=\s*\w+").unwrap());
impl Rule for SqliteWalModeRule {
    fn id(&self) -> &'static str { "PERF-SQLITE-001" }
    fn name(&self) -> &'static str { "Consider WAL Mode for Concurrent Access" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["sqlite"]) }
    fn impact(&self) -> &'static str { "Without WAL, any write locks the entire database file." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if let Some(m) = PAT_SQLITE_WAL.find(&query.raw) {
            let matched_upper = m.as_str().to_uppercase();
            if matched_upper.ends_with("WAL") { return Vec::new(); }
            return vec![self.build_issue(query, "Non-WAL journal mode detected - consider WAL for concurrency.", m.as_str())];
        }
        Vec::new()
    }
}

struct LikeWithoutCollateNocaseRule;
static PAT_SQLITE_LIKE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bLIKE\s+'[^']*'").unwrap());
impl Rule for LikeWithoutCollateNocaseRule {
    fn id(&self) -> &'static str { "PERF-SQLITE-002" }
    fn name(&self) -> &'static str { "LIKE Without COLLATE NOCASE" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["sqlite"]) }
    fn impact(&self) -> &'static str { "Without COLLATE NOCASE on the column, LIKE cannot use indexes." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_SQLITE_LIKE.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "LIKE query detected - ensure column has COLLATE NOCASE for index usage.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct SqliteAutoIncrementRule;
static PAT_SQLITE_AUTO: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bAUTOINCREMENT\b").unwrap());
impl Rule for SqliteAutoIncrementRule {
    fn id(&self) -> &'static str { "QUAL-SQLITE-001" }
    fn name(&self) -> &'static str { "AUTOINCREMENT Overhead in SQLite" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Quality }
    fn category(&self) -> Option<Category> { Some(Category::QualSchemaDesign) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["sqlite"]) }
    fn impact(&self) -> &'static str { "AUTOINCREMENT adds CPU overhead by maintaining the sqlite_sequence table." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_SQLITE_AUTO.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "AUTOINCREMENT adds overhead - INTEGER PRIMARY KEY auto-generates IDs.", m.as_str())]
        }).unwrap_or_default()
    }
}

// DuckDB
struct DuckDBCopyWithoutFormatRule;
static PAT_DUCK_COPY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCOPY\b").unwrap());
impl Rule for DuckDBCopyWithoutFormatRule {
    fn id(&self) -> &'static str { "PERF-DUCK-001" }
    fn name(&self) -> &'static str { "COPY Without FORMAT Specification" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfScan) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["duckdb"]) }
    fn impact(&self) -> &'static str { "Without FORMAT, DuckDB guesses from file extension, which can fail." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !PAT_DUCK_COPY.is_match(&query.raw) { return Vec::new(); }
        if query.raw_upper().contains("FORMAT") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "COPY without explicit FORMAT - may cause incorrect parsing.", snip)]
    }
}

struct DuckDBLargeInListRule;
static PAT_DUCK_IN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bIN\s*\(\s*(?:[^()]*,\s*){9,}").unwrap());
impl Rule for DuckDBLargeInListRule {
    fn id(&self) -> &'static str { "PERF-DUCK-002" }
    fn name(&self) -> &'static str { "Large IN List - Use VALUES Table" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["duckdb"]) }
    fn impact(&self) -> &'static str { "Large IN lists are slower than VALUES table with semi-join." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_DUCK_IN.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "Large IN list detected - consider VALUES table expression.", m.as_str())]
        }).unwrap_or_default()
    }
}

// MySQL GROUP BY implicit sort
struct MysqlGroupByImplicitSortRule;
static PAT_MYSQL_GB: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bGROUP\s+BY\b").unwrap());
impl Rule for MysqlGroupByImplicitSortRule {
    fn id(&self) -> &'static str { "PERF-MYSQL-004" }
    fn name(&self) -> &'static str { "GROUP BY Implicit Sort (Removed in MySQL 8.0)" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfSort) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) }
    fn impact(&self) -> &'static str { "Results appear sorted on MySQL 5.x but are unordered on 8.0+." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if !PAT_MYSQL_GB.is_match(&query.raw) { return Vec::new(); }
        if query.raw_upper().contains("ORDER BY") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "GROUP BY without ORDER BY - implicit sort removed in MySQL 8.0.", snip)]
    }
}


// PERF-NET-002: Large Object Column in Non-Filtered Query
struct LargeObjectUnboundedRule;
static BLOB_COLS: &[&str] = &[
    "blob", "clob", "text", "content", "body", "data", "image",
    "document", "file", "attachment", "payload", "binary",
];
impl Rule for LargeObjectUnboundedRule {
    fn id(&self) -> &'static str { "PERF-NET-002" }
    fn name(&self) -> &'static str { "Large Object Column in Non-Filtered Query" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfNetwork) }
    fn impact(&self) -> &'static str { "Selecting BLOB columns without filtering can transfer gigabytes of data." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() { return Vec::new(); }
        let upper = query.raw_upper();
        if upper.contains("WHERE") || upper.contains("LIMIT") { return Vec::new(); }
        let raw_lower = query.raw.to_lowercase();
        for col in BLOB_COLS {
            if raw_lower.contains(col) {
                let msg = format!("Unbounded SELECT of large object column '{}'.", col);
                let snip = &query.raw[..query.raw.len().min(100)];
                return vec![self.build_issue(query, &msg, snip)];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ExcessiveColumnCountRule),
        Box::new(MissingSetNocountRule),
        Box::new(RedshiftSelectStarRule),
        Box::new(OrderByWithoutLimitRedshiftRule),
        Box::new(NotInOnRedshiftRule),
        Box::new(ClickHouseSelectWithoutPrewhereRule),
        Box::new(ClickHouseJoinWithoutGlobalRule),
        Box::new(ClickHouseMutationRule),
        Box::new(PrestoCrossJoinRule),
        Box::new(PrestoOrderByWithoutLimitRule),
        Box::new(SparkBroadcastHintRule),
        Box::new(SparkUdfInWhereRule),
        Box::new(SqliteWalModeRule),
        Box::new(LikeWithoutCollateNocaseRule),
        Box::new(SqliteAutoIncrementRule),
        Box::new(DuckDBCopyWithoutFormatRule),
        Box::new(DuckDBLargeInListRule),
        Box::new(MysqlGroupByImplicitSortRule),
        Box::new(LargeObjectUnboundedRule),
    ]
}
