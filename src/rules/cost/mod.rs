use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence, RuleContext};
use once_cell::sync::Lazy;
use regex::Regex;

// COST-COMPUTE-001
struct FullTableScanRule;
impl Rule for FullTableScanRule {
    fn id(&self) -> &'static str {
        "COST-COMPUTE-001"
    }
    fn name(&self) -> &'static str {
        "Full Table Scan on Large Tables"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn impact(&self) -> &'static str {
        "Full table scans linearly increase compute cost with table size."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("WHERE")
            || upper.contains("LIMIT")
            || upper.contains("TOP ")
            || upper.contains("GROUP BY")
        {
            return Vec::new();
        }
        if !upper.contains("FROM") {
            return Vec::new();
        }
        let lower = query.raw_lower();
        if lower.contains("pg_stat")
            || lower.contains("pg_catalog")
            || lower.contains("information_schema")
            || lower.contains("sys.")
        {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "Potential full table scan missing WHERE clause.",
            query.snippet(80),
        )]
    }
}

// COST-COMPUTE-002
struct ExpensiveWindowFunctionRule;
static PAT_WINDOW: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOVER\s*\(").unwrap());
impl Rule for ExpensiveWindowFunctionRule {
    fn id(&self) -> &'static str {
        "COST-COMPUTE-002"
    }
    fn name(&self) -> &'static str {
        "Expensive Window Functions Without Partitioning"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn impact(&self) -> &'static str {
        "Window functions without partitioning process the entire result set in a single partition."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_WINDOW.find(&query.raw) {
            if query.raw_upper().contains("PARTITION BY") {
                return Vec::new();
            }
            // Global window functions (OVER ()) are intentional when the developer wants
            // a table-wide aggregate alongside each row. Only flag when:
            // - No WHERE clause bounds the result set, AND
            // - No LIMIT bounds the output
            // A bounded global window is cheap. An unbounded one on a full table is expensive.
            let upper = query.raw_upper();
            if upper.contains("WHERE") || upper.contains("LIMIT") || upper.contains("TOP ") {
                return Vec::new();
            }
            return vec![self.build_issue(
                query,
                "Window function without PARTITION BY on unbounded query.",
                m.as_str(),
            )];
        }
        Vec::new()
    }
}

// COST-STORAGE-001
struct SelectStarInEtlRule;
impl Rule for SelectStarInEtlRule {
    fn id(&self) -> &'static str {
        "COST-STORAGE-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * in ETL/CTAS Queries"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostStorage)
    }
    fn impact(&self) -> &'static str {
        "Storing unnecessary columns increases storage costs linearly with row count."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        let is_persist = upper.contains("CREATE TABLE") || upper.contains("INSERT INTO");
        if !is_persist {
            return Vec::new();
        }
        if upper.contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "SELECT * in persistence query detected.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

// COST-IO-001
struct RedundantOrderByRule;
impl Rule for RedundantOrderByRule {
    fn id(&self) -> &'static str {
        "COST-IO-001"
    }
    fn name(&self) -> &'static str {
        "Redundant ORDER BY in Subqueries"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostIo)
    }
    fn impact(&self) -> &'static str {
        "Unnecessary sorting forces the database to write intermediate results to disk."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        static PAT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i)\(\s*SELECT\b[^)]*\bORDER\s+BY\b").unwrap());
        if let Some(m) = PAT.find(&query.raw) {
            let matched_upper = m.as_str().to_uppercase();
            if !matched_upper.contains("LIMIT") && !matched_upper.contains("TOP") {
                return vec![self.build_issue(
                    query,
                    "Redundant ORDER BY in subquery detected.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// COST-NETWORK-001
struct CrossRegionDataTransferCostRule;
static PAT_CROSS_REGION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(OPENQUERY|OPENDATASOURCE|EXTERNAL\s+TABLE|DBLink)\b").unwrap()
});
impl Rule for CrossRegionDataTransferCostRule {
    fn id(&self) -> &'static str {
        "COST-NETWORK-001"
    }
    fn name(&self) -> &'static str {
        "Cross-Region Data Transfer"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostNetwork)
    }
    fn impact(&self) -> &'static str {
        "Cross-region queries incur data egress charges."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CROSS_REGION
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Potential cross-region data transfer detected.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-PAGE-001
struct OffsetPaginationWithoutCoveringIndexRule;
static PAT_PAGE001_OFFSET: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOFFSET\s+(\d+)").unwrap());
impl Rule for OffsetPaginationWithoutCoveringIndexRule {
    fn id(&self) -> &'static str {
        "COST-PAGE-001"
    }
    fn name(&self) -> &'static str {
        "OFFSET Pagination Without Index"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostPagination)
    }
    fn impact(&self) -> &'static str {
        "OFFSET forces the database to scan and discard rows, cost increases with page depth."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        // Only fire when OFFSET is large enough to cause meaningful cost.
        // Small offsets (< 500) are acceptable. COST-PAGE-002 handles deep pagination (> 1000).
        // This rule targets the middle range where cost starts to be non-trivial.
        if let Some(caps) = PAT_PAGE001_OFFSET.captures(&query.raw) {
            if let Some(val) = caps.get(1) {
                if let Ok(n) = val.as_str().parse::<u64>() {
                    if n < 500 {
                        return Vec::new();
                    }
                    let msg = format!(
                        "OFFSET {} pagination detected - cost increases linearly with page depth.",
                        n
                    );
                    return vec![self.build_issue(query, &msg, query.snippet(100))];
                }
            }
        }
        Vec::new()
    }
}

// COST-PAGE-002
struct DeepPaginationWithoutCursorRule;
static PAT_DEEP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOFFSET\s+(\d+)").unwrap());
impl Rule for DeepPaginationWithoutCursorRule {
    fn id(&self) -> &'static str {
        "COST-PAGE-002"
    }
    fn name(&self) -> &'static str {
        "Deep Pagination Without Cursor"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostPagination)
    }
    fn impact(&self) -> &'static str {
        "Deep pagination means scanning thousands of rows per page."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(caps) = PAT_DEEP.captures(&query.raw) {
            if let Some(val) = caps.get(1) {
                if let Ok(n) = val.as_str().parse::<u64>() {
                    if n > 1000 {
                        let msg = format!(
                            "Deep pagination (OFFSET {}) - switch to cursor-based pagination.",
                            n
                        );
                        return vec![self.build_issue(query, &msg, caps.get(0).unwrap().as_str())];
                    }
                }
            }
        }
        Vec::new()
    }
}

// COST-PAGE-003
struct CountStarForPaginationRule;
static PAT_COUNT_STAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bSELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\b").unwrap());
impl Rule for CountStarForPaginationRule {
    fn id(&self) -> &'static str {
        "COST-PAGE-003"
    }
    fn name(&self) -> &'static str {
        "COUNT(*) for Pagination Total"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostPagination)
    }
    fn impact(&self) -> &'static str {
        "COUNT(*) on large tables requires full scan."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_COUNT_STAR.find(&query.raw) {
            let upper = query.raw_upper();
            if !upper.contains("WHERE") && !upper.contains("LIMIT") {
                return vec![self.build_issue(
                    query,
                    "Expensive COUNT(*) for pagination total on unfiltered table.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// COST-IDX-001
struct DuplicateIndexSignalRule;
static PAT_CREATE_INDEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+INDEX\s+\w+\s+ON\s+(\w+)\s*\(([^)]+)\)").unwrap());
impl Rule for DuplicateIndexSignalRule {
    fn id(&self) -> &'static str {
        "COST-IDX-001"
    }
    fn name(&self) -> &'static str {
        "Duplicate Index Signal"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostIndexWaste)
    }
    fn impact(&self) -> &'static str {
        "Duplicate indexes waste storage and slow down writes."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CREATE_INDEX
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Duplicate index signal detected. Verify if index already exists.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-IDX-002
struct OverIndexedTableSignalRule;
static PAT_MULTI_INDEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)(CREATE\s+INDEX\s+\w+\s+ON\s+(\w+)[\s\S]*?){3,}").unwrap());
impl Rule for OverIndexedTableSignalRule {
    fn id(&self) -> &'static str {
        "COST-IDX-002"
    }
    fn name(&self) -> &'static str {
        "Over-Indexed Table Signal"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostIndexWaste)
    }
    fn impact(&self) -> &'static str {
        "Tables with 10+ indexes pay massive write penalties."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_MULTI_INDEX
            .find(&query.raw)
            .map(|_| {
                vec![self.build_issue(
                    query,
                    "Over-indexed table signal: multiple CREATE INDEX statements found.",
                    query.snippet(100),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-IDX-003
struct MissingCoveringIndexOpportunityRule;
impl Rule for MissingCoveringIndexOpportunityRule {
    fn id(&self) -> &'static str {
        "COST-IDX-003"
    }
    fn name(&self) -> &'static str {
        "Missing Covering Index Opportunity"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostIndexOptimization)
    }
    fn impact(&self) -> &'static str {
        "Non-covering indexes require key lookup, doubling I/O."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires schema context - skip for pattern-based analysis */
    }
}

// COST-IDX-004
struct RedundantIndexColumnOrderRule;
static PAT_COMP_IDX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bCREATE\s+INDEX\s+\w+\s+ON\s+\w+\s*\((\w+)\s*,\s*(\w+)").unwrap()
});
impl Rule for RedundantIndexColumnOrderRule {
    fn id(&self) -> &'static str {
        "COST-IDX-004"
    }
    fn name(&self) -> &'static str {
        "Redundant Index Column Order"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostIndexOptimization)
    }
    fn impact(&self) -> &'static str {
        "Wrong column order = wasted index and slower queries."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_COMP_IDX
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Composite index column order signal: check if order matches query patterns.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-CROSS-001
struct CrossDatabaseJoinRule;
impl Rule for CrossDatabaseJoinRule {
    fn id(&self) -> &'static str {
        "COST-CROSS-001"
    }
    fn name(&self) -> &'static str {
        "Cross-Database JOIN"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCrossDatabase)
    }
    fn impact(&self) -> &'static str {
        "Cross-database JOINs cannot use indexes across boundaries."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Only flag when table references use 3-part names (db.schema.table)
        // Do not flag alias.column (a.id) which is normal
        if let Some(ref facts) = query.facts {
            let has_cross_db = facts
                .from_tables
                .iter()
                .any(|t| t.matches('.').count() >= 2);
            if has_cross_db {
                return vec![self.build_issue(
                    query,
                    "Cross-database JOIN detected - forces data transfer.",
                    query.snippet(100),
                )];
            }
        }
        Vec::new()
    }
}

// COST-CROSS-002
struct MultiRegionQueryLatencyRule;
static PAT_MULTI_REGION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\b(us-east|us-west|eu-west|ap-south|@[^.]*\..*\.rds\.amazonaws\.com|@[^.]*\.database\.windows\.net)\b").unwrap()
});
impl Rule for MultiRegionQueryLatencyRule {
    fn id(&self) -> &'static str {
        "COST-CROSS-002"
    }
    fn name(&self) -> &'static str {
        "Multi-Region Query Latency"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCrossRegion)
    }
    fn impact(&self) -> &'static str {
        "Cross-region queries add 50-200ms latency plus egress charges."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_MULTI_REGION
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Multi-region query detected: potential latency and egress costs.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-CROSS-003
struct DistributedTransactionOverheadRule;
static PAT_DIST_TXN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(BEGIN\s+DISTRIBUTED\s+TRANSACTION|XA\s+START|START\s+TRANSACTION\s+WITH\s+CONSISTENT\s+SNAPSHOT)\b").unwrap()
});
impl Rule for DistributedTransactionOverheadRule {
    fn id(&self) -> &'static str {
        "COST-CROSS-003"
    }
    fn name(&self) -> &'static str {
        "Distributed Transaction Overhead"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostDistributed)
    }
    fn impact(&self) -> &'static str {
        "Distributed transactions require 2-phase commit, 10-100x slower than local."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_DIST_TXN
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Distributed transaction detected: major performance and cost overhead.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-SERVERLESS-001
struct ColdStartQueryPatternRule;
static PAT_COLD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\bSELECT\b.*\b(JOIN|UNION|INTERSECT|EXCEPT)\b.*\b(GROUP\s+BY|ORDER\s+BY|DISTINCT)\b",
    )
    .unwrap()
});
impl Rule for ColdStartQueryPatternRule {
    fn id(&self) -> &'static str {
        "COST-SERVERLESS-001"
    }
    fn name(&self) -> &'static str {
        "Cold Start Query Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostServerless)
    }
    fn impact(&self) -> &'static str {
        "Complex queries trigger ACU scaling in serverless databases."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_COLD.find(&query.raw).map(|m| vec![self.build_issue(query, "Complex query in serverless environment: potential cold start and scaling cost.", m.as_str())]).unwrap_or_default()
    }
}

// COST-SERVERLESS-002
struct UnnecessaryConnectionPoolingRule;
static PAT_POOL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(SET\s+SESSION|CONNECTION\s+TIMEOUT\s*=\s*\d{4,}|KEEP\s+ALIVE|POOLING\s*=\s*TRUE)\b").unwrap()
});
impl Rule for UnnecessaryConnectionPoolingRule {
    fn id(&self) -> &'static str {
        "COST-SERVERLESS-002"
    }
    fn name(&self) -> &'static str {
        "Unnecessary Connection Pooling"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostServerless)
    }
    fn impact(&self) -> &'static str {
        "Serverless databases charge per second of connection time."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_POOL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(query, "Wasteful connection management found.", m.as_str())]
            })
            .unwrap_or_default()
    }
}

// COST-ARCHIVE-001
struct OldDataNotArchivedRule;
static DATE_COLS: &[&str] = &[
    "created_at",
    "updated_at",
    "modified_at",
    "date",
    "timestamp",
    "event_date",
    "order_date",
    "transaction_date",
    "posted_at",
];
impl Rule for OldDataNotArchivedRule {
    fn id(&self) -> &'static str {
        "COST-ARCHIVE-001"
    }
    fn name(&self) -> &'static str {
        "Old Data Not Archived"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostArchival)
    }
    fn impact(&self) -> &'static str {
        "Storing years of logs in hot storage costs 10x vs cold storage."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if !query.raw_upper().contains("FROM") {
            return Vec::new();
        }
        let lower = query.raw_lower();
        let has_date = DATE_COLS.iter().any(|c| lower.contains(c));
        if has_date && !lower.contains("where") {
            return vec![self.build_issue(
                query,
                "Query on table with timestamp - consider archiving old data.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

// COST-COMPRESS-001
struct LargeTextColumnWithoutCompressionRule;
static PAT_LARGE_TEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bCREATE\s+TABLE\b[^;]*\b(VARCHAR\s*\(\s*\d{4,}\)|TEXT|CLOB|NVARCHAR\s*\(MAX\)|LONGTEXT)\b").unwrap()
});
impl Rule for LargeTextColumnWithoutCompressionRule {
    fn id(&self) -> &'static str {
        "COST-COMPRESS-001"
    }
    fn name(&self) -> &'static str {
        "Large Text Column Without Compression"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostStorage)
    }
    fn impact(&self) -> &'static str {
        "Uncompressed TEXT columns waste 3-10x storage space."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_LARGE_TEXT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Large text column without compression detected.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-PARTITION-001
struct LargeTableWithoutPartitioningRule;
impl Rule for LargeTableWithoutPartitioningRule {
    fn id(&self) -> &'static str {
        "COST-PARTITION-001"
    }
    fn name(&self) -> &'static str {
        "Large Table Without Partitioning"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostPartitioning)
    }
    fn impact(&self) -> &'static str {
        "Scanning unpartitioned tables costs 100x more than scanning one partition."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        // Requires RuleContext. Use check_with_context instead.
        Vec::new()
    }

    fn check_with_context(&self, query: &Query, ctx: &RuleContext) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if query.raw_upper().contains("PARTITION") {
            return Vec::new();
        }

        // Get table names from AST facts or parsed tables
        let table_names: Vec<&str> = if let Some(ref facts) = query.facts {
            facts.from_tables.iter().map(|s| s.as_str()).collect()
        } else {
            query.tables.iter().map(|s| s.as_str()).collect()
        };

        for table in &table_names {
            // Only fire when we have proof: table is declared partitioned
            if !ctx.is_partitioned(table) {
                continue;
            }

            // Table is partitioned. Check if query uses a partition column in WHERE.
            let partition_cols = ctx.partition_columns(table);
            if partition_cols.is_empty() {
                continue;
            }

            let has_partition_filter = if let Some(ref facts) = query.facts {
                partition_cols.iter().any(|pc| {
                    let pc_lower = pc.to_lowercase();
                    facts
                        .where_columns
                        .iter()
                        .any(|wc| wc.to_lowercase() == pc_lower)
                })
            } else {
                let lower = query.raw_lower();
                partition_cols
                    .iter()
                    .any(|pc| lower.contains(&pc.to_lowercase()))
            };

            if !has_partition_filter {
                let msg = format!(
                    "Query on partitioned table '{}' without partition column ({}) in WHERE - full partition scan.",
                    table,
                    partition_cols.join(", ")
                );
                return vec![self.build_issue(query, &msg, query.snippet(100))];
            }
        }

        Vec::new()
    }
}

// Dialect-specific cost rules
// COST-BQ-001
struct BigQuerySelectStarCostRule;
impl Rule for BigQuerySelectStarCostRule {
    fn id(&self) -> &'static str {
        "COST-BQ-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * in BigQuery Scans All Columns"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "BigQuery charges per byte scanned. SELECT * costs 50x more than selecting needed columns."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if query.raw_upper().contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "SELECT * in BigQuery scans all columns - billed by bytes scanned.",
                "SELECT *",
            )];
        }
        Vec::new()
    }
}

// COST-BQ-002
struct BigQueryMissingLimitRule;
impl Rule for BigQueryMissingLimitRule {
    fn id(&self) -> &'static str {
        "COST-BQ-002"
    }
    fn name(&self) -> &'static str {
        "BigQuery Query Without LIMIT"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "BigQuery bills for bytes scanned regardless of rows returned."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !query.is_select() {
            return Vec::new();
        }
        if query.raw_upper().contains("LIMIT") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "SELECT without LIMIT in BigQuery - full table scan billed.",
            query.snippet(80),
        )]
    }
}

// COST-BQ-003
struct BigQueryRepeatedSubqueryRule;
impl Rule for BigQueryRepeatedSubqueryRule {
    fn id(&self) -> &'static str {
        "COST-BQ-003"
    }
    fn name(&self) -> &'static str {
        "Repeated Subquery Instead of CTE"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "Each repeated subquery scans underlying tables again."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        let subquery_count = upper.matches("(SELECT").count();
        if subquery_count < 2 {
            return Vec::new();
        }
        if upper.contains("WITH") && upper.contains("AS") {
            return Vec::new();
        }
        let msg = format!(
            "Query contains {} subqueries - consider CTEs.",
            subquery_count
        );
        vec![self.build_issue(query, &msg, query.snippet(80))]
    }
}

// COST-SF-001
struct SnowflakeSelectStarCostRule;
impl Rule for SnowflakeSelectStarCostRule {
    fn id(&self) -> &'static str {
        "COST-SF-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * Wastes Snowflake Credits"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "SELECT * prevents column pruning, forces scanning all micro-partitions."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if query.raw_upper().contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "SELECT * in Snowflake scans all micro-partitions - wastes credits.",
                "SELECT *",
            )];
        }
        Vec::new()
    }
}

// COST-SF-002
struct SnowflakeCopyIntoWithoutFileFormatRule;
impl Rule for SnowflakeCopyIntoWithoutFileFormatRule {
    fn id(&self) -> &'static str {
        "COST-SF-002"
    }
    fn name(&self) -> &'static str {
        "COPY INTO Without Explicit File Format"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "COPY INTO without FILE_FORMAT relies on default settings."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("COPY INTO") {
            return Vec::new();
        }
        if upper.contains("FILE_FORMAT") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "COPY INTO without FILE_FORMAT - relies on default format settings.",
            query.snippet(80),
        )]
    }
}

// COST-SF-003
struct SnowflakeWarehouseSizeHintRule;
static PAT_FLATTEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bLATERAL\s+FLATTEN\b").unwrap());
impl Rule for SnowflakeWarehouseSizeHintRule {
    fn id(&self) -> &'static str {
        "COST-SF-003"
    }
    fn name(&self) -> &'static str {
        "LATERAL FLATTEN Without Warehouse Consideration"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "Undersized warehouse causes disk spilling, multiplying credit consumption."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_FLATTEN
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "LATERAL FLATTEN detected - verify warehouse size is appropriate.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-SF-001
struct SnowflakeVariantInWhereRule;
static PAT_VARIANT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.*:[\w.]+").unwrap());
impl Rule for SnowflakeVariantInWhereRule {
    fn id(&self) -> &'static str {
        "PERF-SF-001"
    }
    fn name(&self) -> &'static str {
        "VARIANT Column in WHERE Without CAST"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "Without CAST, Snowflake scans all micro-partitions."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_VARIANT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "VARIANT column access in WHERE - add explicit CAST for pruning.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-SF-002
struct SnowflakeOrderByVariantRule;
static PAT_ORDER_VARIANT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bORDER\s+BY\b.*:[\w.]+").unwrap());
impl Rule for SnowflakeOrderByVariantRule {
    fn id(&self) -> &'static str {
        "PERF-SF-002"
    }
    fn name(&self) -> &'static str {
        "ORDER BY on VARIANT Column"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfSort)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "VARIANT sorting inspects type per row, adding significant overhead."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ORDER_VARIANT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "ORDER BY on VARIANT column - slow runtime type resolution.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-SF-001
struct SnowflakeCopyWithoutOnErrorRule;
impl Rule for SnowflakeCopyWithoutOnErrorRule {
    fn id(&self) -> &'static str {
        "REL-SF-001"
    }
    fn name(&self) -> &'static str {
        "COPY INTO Without ON_ERROR"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "A single malformed row aborts the entire load."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("COPY INTO") {
            return Vec::new();
        }
        if upper.contains("ON_ERROR") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "COPY INTO without explicit ON_ERROR setting.",
            query.snippet(80),
        )]
    }
}

// COST-MYSQL-001
struct MysqlQueryCachePollutionRule;
static PAT_MYSQL_CACHE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bSELECT\b.*\b(?:GROUP\s+BY|ORDER\s+BY|HAVING)\b").unwrap());
impl Rule for MysqlQueryCachePollutionRule {
    fn id(&self) -> &'static str {
        "COST-MYSQL-001"
    }
    fn name(&self) -> &'static str {
        "Query Cache Pollution"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "Large result sets evict frequently-used entries from query cache."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_MYSQL_CACHE.find(&query.raw) {
            if !query.raw_upper().contains("SQL_NO_CACHE") {
                return vec![self.build_issue(
                    query,
                    "Analytical query without SQL_NO_CACHE - may pollute query cache.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// COST-TSQL-001
struct TsqlCursorWithoutFastForwardRule;
static PAT_CURSOR_FF: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bDECLARE\s+\w+\s+CURSOR\b").unwrap());
impl Rule for TsqlCursorWithoutFastForwardRule {
    fn id(&self) -> &'static str {
        "COST-TSQL-001"
    }
    fn name(&self) -> &'static str {
        "Cursor Without FAST_FORWARD"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "Non-FAST_FORWARD cursors maintain key sets in tempdb."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_CURSOR_FF.find(&query.raw) {
            if !query.raw_upper().contains("FAST_FORWARD") {
                return vec![self.build_issue(
                    query,
                    "CURSOR without FAST_FORWARD - unnecessary tempdb overhead.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// COST-ORA-001
struct OracleFullTableHintRule;
static PAT_ORA_FULL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/\*\+\s*FULL\s*\(").unwrap());
impl Rule for OracleFullTableHintRule {
    fn id(&self) -> &'static str {
        "COST-ORA-001"
    }
    fn name(&self) -> &'static str {
        "Full Table Scan Hint"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "Forces reading every block in the table regardless of available indexes."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ORA_FULL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "FULL table scan hint detected - bypasses all indexes.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// COST-CH-001
struct ClickHouseSelectStarRule;
impl Rule for ClickHouseSelectStarRule {
    fn id(&self) -> &'static str {
        "COST-CH-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * on ClickHouse Columnar Storage"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["clickhouse"])
    }
    fn impact(&self) -> &'static str {
        "SELECT * bypasses column pruning, reading and decompressing every column."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if query.raw_upper().contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "SELECT * on ClickHouse - reads all columns from columnar storage.",
                "SELECT *",
            )];
        }
        Vec::new()
    }
}

// COST-PRESTO-001
struct PrestoSelectStarPartitionedRule;
impl Rule for PrestoSelectStarPartitionedRule {
    fn id(&self) -> &'static str {
        "COST-PRESTO-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * on Partitioned Hive Table"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["presto", "trino"])
    }
    fn impact(&self) -> &'static str {
        "SELECT * reads all columns and partitions."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if query.raw_upper().contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "SELECT * on Presto/Trino - reads all columns and partitions.",
                "SELECT *",
            )];
        }
        Vec::new()
    }
}

// COST-RS-001
struct UnloadWithoutParallelRule;
impl Rule for UnloadWithoutParallelRule {
    fn id(&self) -> &'static str {
        "COST-RS-001"
    }
    fn name(&self) -> &'static str {
        "UNLOAD Without PARALLEL Consideration"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostStorage)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["redshift"])
    }
    fn impact(&self) -> &'static str {
        "Default PARALLEL ON creates many small S3 files."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("UNLOAD") {
            return Vec::new();
        }
        if upper.contains("PARALLEL") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "UNLOAD without explicit PARALLEL setting.",
            query.snippet(80),
        )]
    }
}

// COST-SPARK-001
struct SparkFullScanWithoutPartitionFilterRule;
impl Rule for SparkFullScanWithoutPartitionFilterRule {
    fn id(&self) -> &'static str {
        "COST-SPARK-001"
    }
    fn name(&self) -> &'static str {
        "Full Scan Without Partition Filter"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["spark", "databricks"])
    }
    fn impact(&self) -> &'static str {
        "Partitioned table reads 365x more data without partition filter."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !query.is_select() {
            return Vec::new();
        }
        if query.raw_upper().contains("WHERE") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "Query without WHERE on Spark/Databricks - full partition scan.",
            query.snippet(80),
        )]
    }
}

// COST-SPARK-002
struct SparkCacheTableWithoutFilterRule;
static PAT_CACHE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCACHE\s+(?:LAZY\s+)?TABLE\b").unwrap());
impl Rule for SparkCacheTableWithoutFilterRule {
    fn id(&self) -> &'static str {
        "COST-SPARK-002"
    }
    fn name(&self) -> &'static str {
        "CACHE TABLE Without Filter"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Cost
    }
    fn category(&self) -> Option<Category> {
        Some(Category::CostCompute)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["spark", "databricks"])
    }
    fn impact(&self) -> &'static str {
        "Caching entire table consumes executor memory."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_CACHE.find(&query.raw) {
            let upper = query.raw_upper();
            if !upper.contains("WHERE") && !upper.contains("OPTIONS") {
                return vec![self.build_issue(
                    query,
                    "CACHE TABLE without filter - entire table loaded into memory.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(FullTableScanRule),
        Box::new(ExpensiveWindowFunctionRule),
        Box::new(SelectStarInEtlRule),
        Box::new(RedundantOrderByRule),
        Box::new(CrossRegionDataTransferCostRule),
        Box::new(OffsetPaginationWithoutCoveringIndexRule),
        Box::new(DeepPaginationWithoutCursorRule),
        Box::new(CountStarForPaginationRule),
        Box::new(DuplicateIndexSignalRule),
        Box::new(OverIndexedTableSignalRule),
        Box::new(MissingCoveringIndexOpportunityRule),
        Box::new(RedundantIndexColumnOrderRule),
        Box::new(CrossDatabaseJoinRule),
        Box::new(MultiRegionQueryLatencyRule),
        Box::new(DistributedTransactionOverheadRule),
        Box::new(ColdStartQueryPatternRule),
        Box::new(UnnecessaryConnectionPoolingRule),
        Box::new(OldDataNotArchivedRule),
        Box::new(LargeTextColumnWithoutCompressionRule),
        Box::new(LargeTableWithoutPartitioningRule),
        Box::new(BigQuerySelectStarCostRule),
        Box::new(BigQueryMissingLimitRule),
        Box::new(BigQueryRepeatedSubqueryRule),
        Box::new(SnowflakeSelectStarCostRule),
        Box::new(SnowflakeCopyIntoWithoutFileFormatRule),
        Box::new(SnowflakeWarehouseSizeHintRule),
        Box::new(SnowflakeVariantInWhereRule),
        Box::new(SnowflakeOrderByVariantRule),
        Box::new(SnowflakeCopyWithoutOnErrorRule),
        Box::new(MysqlQueryCachePollutionRule),
        Box::new(TsqlCursorWithoutFastForwardRule),
        Box::new(OracleFullTableHintRule),
        Box::new(ClickHouseSelectStarRule),
        Box::new(PrestoSelectStarPartitionedRule),
        Box::new(UnloadWithoutParallelRule),
        Box::new(SparkFullScanWithoutPartitionFilterRule),
        Box::new(SparkCacheTableWithoutFilterRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str, dialect: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: dialect.to_string(),
            location: Location::new(1, 1),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn all_cost_rules_metadata() {
        let rules = all_rules();
        assert!(rules.len() >= 25);
        for rule in &rules {
            let _ = rule.id();
            let _ = rule.name();
            let _ = rule.severity();
            let _ = rule.dimension();
            let _ = rule.category();
            let _ = rule.impact();
            let _ = rule.fix_guidance();
            let _ = rule.confidence();
            let _ = rule.dialects();
        }
    }

    #[test]
    fn all_cost_rules_no_match_simple() {
        let rules = all_rules();
        let query = q("SELECT 1", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn all_cost_rules_dialect_coverage() {
        let rules = all_rules();
        let dialects = [
            "postgresql",
            "mysql",
            "tsql",
            "oracle",
            "bigquery",
            "snowflake",
            "redshift",
            "clickhouse",
            "presto",
            "spark",
        ];
        for dialect in &dialects {
            let query = q("SELECT 1", dialect, "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
                let _ = rule.dialect_matches(&query);
            }
        }
    }

    #[test]
    fn select_star_cost() {
        let rules = all_rules();
        let query = q("SELECT * FROM large_table", "bigquery", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn cross_join_cost() {
        let rules = all_rules();
        let query = q("SELECT * FROM a CROSS JOIN b", "snowflake", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn pagination_patterns() {
        let rules = all_rules();
        let query = q(
            "SELECT * FROM t ORDER BY id LIMIT 10 OFFSET 100000",
            "postgresql",
            "SELECT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn cursor_cost() {
        let rules = all_rules();
        let query = q("DECLARE c CURSOR FOR SELECT * FROM t", "tsql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn storage_patterns() {
        let rules = all_rules();
        let query = q("CREATE TABLE t (data TEXT)", "postgresql", "CREATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn snowflake_patterns() {
        let rules = all_rules();
        for sql in &[
            "SELECT * FROM t",
            "CREATE TABLE t CLUSTER BY (id)",
            "SELECT PARSE_JSON(data) FROM t",
        ] {
            let query = q(sql, "snowflake", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn bigquery_patterns() {
        let rules = all_rules();
        for sql in &["SELECT * FROM t", "SELECT DISTINCT * FROM UNNEST(arr)"] {
            let query = q(sql, "bigquery", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn redshift_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "redshift", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn spark_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "spark", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn insert_path() {
        let rules = all_rules();
        let query = q("INSERT INTO t (a) VALUES (1)", "postgresql", "INSERT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn delete_path() {
        let rules = all_rules();
        let query = q("DELETE FROM t WHERE id = 1", "postgresql", "DELETE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn update_path() {
        let rules = all_rules();
        let query = q("UPDATE t SET x = 1 WHERE id = 1", "postgresql", "UPDATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn adhoc_context() {
        let rules = all_rules();
        let mut query = q("SELECT * FROM t", "bigquery", "SELECT");
        query.source_context = "adhoc".to_string();
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    // Targeted tests for uncovered branches

    #[test]
    fn snowflake_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "SELECT * FROM t CLUSTER BY (id)",
            "CREATE TABLE t CLUSTER BY (date)",
            "ALTER WAREHOUSE wh SET AUTO_SUSPEND = 0",
            "SELECT PARSE_JSON(data):key FROM t",
            "SELECT * FROM t SAMPLE (10)",
            "CREATE TABLE t (data VARIANT)",
        ] {
            let qt = if sql.starts_with("CREATE") || sql.starts_with("ALTER") {
                "CREATE"
            } else {
                "SELECT"
            };
            let query = q(sql, "snowflake", qt);
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn bigquery_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "SELECT * FROM t WHERE _PARTITIONTIME > '2024-01-01'",
            "SELECT DISTINCT * FROM UNNEST(arr) AS x",
            "SELECT REGEXP_EXTRACT(col, r'pattern') FROM t",
        ] {
            let query = q(sql, "bigquery", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn redshift_specific_patterns() {
        let rules = all_rules();
        for sql in &["SELECT * FROM t", "COPY t FROM 's3://bucket/file'"] {
            let query = q(sql, "redshift", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn clickhouse_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "clickhouse", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn presto_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "presto", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn spark_patterns_targeted() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "spark", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn oracle_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t FOR UPDATE", "oracle", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_patterns() {
        let rules = all_rules();
        let query = q("DECLARE c CURSOR FOR SELECT * FROM t", "mysql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn tsql_cursor() {
        let rules = all_rules();
        let query = q("DECLARE c CURSOR FOR SELECT * FROM t", "tsql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn deep_pagination() {
        let rules = all_rules();
        let query = q(
            "SELECT * FROM t ORDER BY id LIMIT 10 OFFSET 500000",
            "postgresql",
            "SELECT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn large_limit() {
        let rules = all_rules();
        let query = q("SELECT * FROM t LIMIT 1000000", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn cross_join_cost_targeted() {
        let rules = all_rules();
        let query = q("SELECT * FROM a, b, c", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn index_cost() {
        let rules = all_rules();
        let query = q(
            "CREATE INDEX idx ON t (a, b, c, d, e, f)",
            "postgresql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn storage_patterns_targeted() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE t (data BLOB, content CLOB)",
            "postgresql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn archive_patterns() {
        let rules = all_rules();
        let query = q(
            "DELETE FROM logs WHERE created_at < '2020-01-01'",
            "postgresql",
            "DELETE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn compress_patterns() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE t (data TEXT) WITH (appendonly=true)",
            "postgresql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }
}
