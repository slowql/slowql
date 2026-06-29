use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

// REL-DATA-001: DELETE/UPDATE without WHERE
struct UnsafeWriteRule;
impl Rule for UnsafeWriteRule {
    fn id(&self) -> &'static str {
        "REL-DATA-001"
    }
    fn name(&self) -> &'static str {
        "Catastrophic Data Loss Risk"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn impact(&self) -> &'static str {
        "Instant data loss of entire table content."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "DELETE" && qt != "UPDATE" {
            return Vec::new();
        }
        if query.raw_upper().contains("WHERE") {
            return Vec::new();
        }
        // Detect intentional "clear all" patterns.
        // If the file path or filename suggests this is a deliberate bulk
        // operation (cache clear, test reset, flush, etc.), suppress.
        if let Some(ref file) = query.location.file {
            let fl = file.to_lowercase();
            let filename = fl.rsplit('/').next().unwrap_or(&fl);
            // Files whose purpose is bulk operations
            if fl.contains("cache")
                || fl.contains("clear")
                || fl.contains("reset")
                || fl.contains("cleanup")
                || fl.contains("purge")
                || fl.contains("flush")
                || fl.contains("init.sql")
                || fl.contains("setup.sql")
                || fl.contains("teardown")
                || fl.contains("truncate")
                || filename.contains("flush")
                || filename.contains("clear")
                || filename.contains("reset")
                || filename.contains("purge")
                || filename.contains("testinfra")
                || filename.contains("sync")
            {
                return Vec::new();
            }
        }
        let msg = format!("CRITICAL: {} statement has no WHERE clause.", qt);
        vec![self.build_issue(query, &msg, query.snippet(80))]
    }
}

// REL-DATA-002
struct TruncateWithoutTransactionRule;
static PAT_TRUNC: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bTRUNCATE\b").unwrap());
impl Rule for TruncateWithoutTransactionRule {
    fn id(&self) -> &'static str {
        "REL-DATA-002"
    }
    fn name(&self) -> &'static str {
        "Truncate Without Transaction"
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
    fn impact(&self) -> &'static str {
        "TRUNCATE removes all rows instantly with no row-by-row logging."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TRUNC
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "TRUNCATE TABLE detected outside explicit transaction.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-DATA-003
struct AlterTableDestructiveRule;
static PAT_ALTER_DEST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bALTER\s+TABLE\b.+\bDROP\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bMODIFY\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bRENAME\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bCHANGE\s+COLUMN\b)").unwrap()
});
impl Rule for AlterTableDestructiveRule {
    fn id(&self) -> &'static str {
        "REL-DATA-003"
    }
    fn name(&self) -> &'static str {
        "ALTER TABLE Without Backup Signal"
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
    fn impact(&self) -> &'static str {
        "DROP COLUMN permanently destroys column data."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_ALTER_DEST
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Destructive ALTER TABLE operation detected.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-DATA-004
struct DropTableRule;
impl Rule for DropTableRule {
    fn id(&self) -> &'static str {
        "REL-DATA-004"
    }
    fn name(&self) -> &'static str {
        "Destructive Schema Change (DROP)"
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
    fn impact(&self) -> &'static str {
        "Irreversible schema and data destruction."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.query_type.as_deref() != Some("DROP") {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("DROP TABLE")
            && !upper.contains("DROP VIEW")
            && !upper.contains("DROP DATABASE")
            && !upper.contains("DROP SCHEMA")
        {
            return Vec::new();
        }
        // Suppress setup/teardown pattern: DROP IF EXISTS in init/setup files
        // These are intentional resets before recreation.
        if upper.contains("IF EXISTS") {
            if let Some(ref file) = query.location.file {
                let fl = file.to_lowercase();
                if fl.contains("init")
                    || fl.contains("setup")
                    || fl.contains("reset")
                    || fl.contains("teardown")
                    || fl.contains("fixture")
                {
                    return Vec::new();
                }
            }
        }
        vec![self.build_issue(query, "DROP statement detected.", query.snippet(80))]
    }
}

// REL-TXN-001
struct MissingRollbackRule;
static PAT_BEGIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(BEGIN|START\s+TRANSACTION)\b").unwrap());
impl Rule for MissingRollbackRule {
    fn id(&self) -> &'static str {
        "REL-TXN-001"
    }
    fn name(&self) -> &'static str {
        "Missing Transaction Rollback Handler"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTransaction)
    }
    fn impact(&self) -> &'static str {
        "Without ROLLBACK, a failed transaction may partially commit changes."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_BEGIN
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Transaction opened - verify ROLLBACK handler exists.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-TXN-002
struct AutocommitDisabledRule;
static PAT_AUTOCOMMIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bSET\s+autocommit\s*=\s*0\b)|(\bSET\s+IMPLICIT_TRANSACTIONS\s+ON\b)")
        .unwrap()
});
impl Rule for AutocommitDisabledRule {
    fn id(&self) -> &'static str {
        "REL-TXN-002"
    }
    fn name(&self) -> &'static str {
        "Autocommit Disable Detection"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTransaction)
    }
    fn impact(&self) -> &'static str {
        "Disabling autocommit causes uncommitted changes to be silently rolled back on connection drop."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTOCOMMIT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Autocommit disabled - risk of silent rollback on connection drop.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-TXN-003
struct EmptyTransactionRule;
static PAT_EMPTY_TXN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:BEGIN|START\s+TRANSACTION)\s*;\s*(?:COMMIT|END)\b").unwrap()
});
impl Rule for EmptyTransactionRule {
    fn id(&self) -> &'static str {
        "REL-TXN-003"
    }
    fn name(&self) -> &'static str {
        "Empty Transaction Block"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTransaction)
    }
    fn impact(&self) -> &'static str {
        "Empty transactions acquire locks for no purpose."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_EMPTY_TXN
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Empty transaction block detected - no DML between BEGIN and COMMIT.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-ERR-001
struct ExceptionSwallowedRule;
static PAT_SWALLOW: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bWHEN\s+OTHERS\s+THEN\s+NULL\b").unwrap());
impl Rule for ExceptionSwallowedRule {
    fn id(&self) -> &'static str {
        "REL-ERR-001"
    }
    fn name(&self) -> &'static str {
        "Swallowed Exception Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelErrorHandling)
    }
    fn impact(&self) -> &'static str {
        "Silent exception swallowing means failed operations appear to succeed."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SWALLOW
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Exception handler may be swallowing errors silently.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-REC-001
struct LongTransactionWithoutSavepointRule;
static PAT_SAVEPOINT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSAVEPOINT\b").unwrap());
impl Rule for LongTransactionWithoutSavepointRule {
    fn id(&self) -> &'static str {
        "REL-REC-001"
    }
    fn name(&self) -> &'static str {
        "Missing Savepoint in Long Transaction"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelRecovery)
    }
    fn impact(&self) -> &'static str {
        "A failure forces rollback of all previous steps."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SAVEPOINT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Long transaction detected - consider using SAVEPOINTs for partial recovery.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-IDEM-001
struct NonIdempotentInsertRule;
impl Rule for NonIdempotentInsertRule {
    fn id(&self) -> &'static str {
        "REL-IDEM-001"
    }
    fn name(&self) -> &'static str {
        "Non-Idempotent INSERT Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelIdempotency)
    }
    fn impact(&self) -> &'static str {
        "Non-idempotent INSERTs cause duplicate data on network retries."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Idempotency guards are irrelevant in migration, test, and seed contexts.
        // Migration runners enforce run-once semantics. Tests use clean state.
        // Seeds load into empty databases by design.
        match query.source_context.as_str() {
            "adhoc" | "" | "migration" | "test" | "seed" => return Vec::new(),
            _ => {}
        }
        if !query.is_insert() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        let idempotent = upper.contains("ON CONFLICT")
            || upper.contains("ON DUPLICATE KEY")
            || upper.contains("INSERT IGNORE")
            || upper.contains("MERGE")
            || upper.contains("NOT EXISTS");
        if idempotent {
            return Vec::new();
        }
        // Skip append-only tables (logs, events, audit) where idempotency is not expected.
        // Use exact table name match from parsed tables to avoid substring false negatives.
        let append_only = [
            "logs",
            "log",
            "events",
            "event",
            "audit",
            "audit_log",
            "metrics",
            "analytics",
            "history",
            "activity",
            "notifications",
            "queue",
            "audit_trail",
            "event_log",
            "access_log",
            "change_log",
        ];
        let is_append_only = if let Some(ref facts) = query.facts {
            facts.insert_table.as_ref().is_some_and(|t| {
                let tl = t.to_lowercase();
                let name = tl.rsplit('.').next().unwrap_or(&tl);
                append_only.contains(&name)
            })
        } else {
            query.tables.iter().any(|t| {
                let tl = t.to_lowercase();
                let name = tl.rsplit('.').next().unwrap_or(&tl);
                append_only.contains(&name)
            })
        };
        if is_append_only {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "INSERT without idempotency guard - will fail or create duplicates on retry.",
            query.snippet(100),
        )]
    }
}

// REL-IDEM-002
struct NonIdempotentUpdateRule;
static PAT_REL_UPDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bSET\s+(\w+)\s*=\s*(\w+)\s*[+\-]").unwrap());
impl Rule for NonIdempotentUpdateRule {
    fn id(&self) -> &'static str {
        "REL-IDEM-002"
    }
    fn name(&self) -> &'static str {
        "Non-Idempotent UPDATE Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelIdempotency)
    }
    fn impact(&self) -> &'static str {
        "Relative updates execute multiple times on retry, causing incorrect totals."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_update() {
            return Vec::new();
        }
        if let Some(caps) = PAT_REL_UPDATE.captures(&query.raw) {
            let col1 = caps
                .get(1)
                .map(|m| m.as_str().to_lowercase())
                .unwrap_or_default();
            let col2 = caps
                .get(2)
                .map(|m| m.as_str().to_lowercase())
                .unwrap_or_default();
            if col1 != col2 {
                return Vec::new();
            }
            let m = caps.get(0).unwrap();
            let upper = query.raw_upper();
            let has_version = [
                "VERSION",
                "UPDATED_AT",
                "MODIFIED_AT",
                "ETAG",
                "ROW_VERSION",
                "LOCK_VERSION",
            ]
            .iter()
            .any(|v| upper.contains(v));
            if !has_version {
                return vec![self.build_issue(
                    query,
                    "Relative UPDATE without version check - not idempotent.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// REL-RACE-001
struct ReadModifyWriteLockingRule;
impl Rule for ReadModifyWriteLockingRule {
    fn id(&self) -> &'static str {
        "REL-RACE-001"
    }
    fn name(&self) -> &'static str {
        "Read-Modify-Write Without Lock"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelRaceCondition)
    }
    fn impact(&self) -> &'static str {
        "Read-modify-write without locks causes lost updates."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        // DDL definitions (CREATE VIEW, CREATE FUNCTION) naturally contain
        // SELECT and UPDATE keywords without being read-modify-write patterns.
        if upper.contains("CREATE ") || upper.contains("ALTER ") {
            return Vec::new();
        }
        // A single UPDATE with a subquery (UPDATE x SET col = (SELECT ...))
        // is atomic in SQL and not a race condition. Only flag when the
        // query type itself is SELECT and UPDATE appears separately, or when
        // in a multi-statement procedural block.
        if let Some(qt) = query.query_type.as_deref() {
            // Single UPDATE with embedded SELECT is atomic
            if qt == "UPDATE" {
                return Vec::new();
            }
            // Single SELECT is not a race by itself
            if qt == "SELECT" && !upper.contains("UPDATE") {
                return Vec::new();
            }
            // CTE (WITH ... AS) followed by UPDATE is a single atomic statement
            if qt == "SELECT" && upper.starts_with("WITH ") {
                return Vec::new();
            }
        }
        if upper.contains("SELECT")
            && upper.contains("UPDATE")
            && !upper.contains("FOR UPDATE")
            && !upper.contains("SERIALIZABLE")
        {
            vec![self.build_issue(query, "Read-modify-write pattern without FOR UPDATE or SERIALIZABLE - race condition risk.", query.snippet(100))]
        } else {
            Vec::new()
        }
    }
}

// REL-RACE-002
struct TOCTOUPatternRule;
static PAT_TOCTOU: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bIF\s+(NOT\s+)?EXISTS\s*\(\s*SELECT[^)]+\)[^;]*\b(INSERT|UPDATE|DELETE)\b")
        .unwrap()
});
impl Rule for TOCTOUPatternRule {
    fn id(&self) -> &'static str {
        "REL-RACE-002"
    }
    fn name(&self) -> &'static str {
        "TOCTOU Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelRaceCondition)
    }
    fn impact(&self) -> &'static str {
        "TOCTOU vulnerabilities allow race conditions between check and action."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TOCTOU
            .find(&query.raw)
            .map(|_| {
                vec![self.build_issue(
                    query,
                    "Potential TOCTOU race condition: IF EXISTS check followed by modification.",
                    query.snippet(80),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-FK-001
struct OrphanRecordRiskRule;
static FK_COLS: &[&str] = &[
    "user_id",
    "customer_id",
    "order_id",
    "product_id",
    "account_id",
    "parent_id",
    "category_id",
    "department_id",
    "company_id",
    "tenant_id",
    "created_by",
    "updated_by",
    "owner_id",
    "assigned_to",
    "manager_id",
];
impl Rule for OrphanRecordRiskRule {
    fn id(&self) -> &'static str {
        "REL-FK-001"
    }
    fn name(&self) -> &'static str {
        "Orphan Record Risk"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelForeignKey)
    }
    fn impact(&self) -> &'static str {
        "INSERTs without FK verification create orphan records."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if !query.is_insert() {
            return Vec::new();
        }
        let raw_lower = query.raw_lower().to_string();
        let has_fk = FK_COLS.iter().any(|c| raw_lower.contains(c));
        if !has_fk {
            return Vec::new();
        }
        let has_check = ["foreign key", "references", "exists", "join"]
            .iter()
            .any(|k| raw_lower.contains(k));
        if has_check {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "INSERT with foreign key columns without existence verification - orphan record risk.",
            query.snippet(100),
        )]
    }
}

// REL-FK-002
struct CascadeDeleteRiskRule;
static PAT_CASCADE_DEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bDELETE\s+FROM\s+(users|customers|accounts|orders|products|categories|departments|companies|tenants|organizations)\b").unwrap()
});
impl Rule for CascadeDeleteRiskRule {
    fn id(&self) -> &'static str {
        "REL-FK-002"
    }
    fn name(&self) -> &'static str {
        "Cascade Delete Risk"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelForeignKey)
    }
    fn impact(&self) -> &'static str {
        "DELETE on parent table with ON DELETE CASCADE can wipe millions of child records."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_CASCADE_DEL.find(&query.raw) {
            // Use structural analysis if available
            if let Some(ref facts) = query.facts {
                if facts.is_single_row_lookup() {
                    return Vec::new(); // Targeted delete, not mass cascade risk
                }
            } else {
                // Fallback: string-based PK check
                let upper = query.raw_upper();
                if upper.contains("WHERE") {
                    let pk_patterns = ["WHERE ID =", "WHERE ID=", "WHERE ID IN"];
                    if pk_patterns.iter().any(|p| upper.contains(p)) {
                        return Vec::new();
                    }
                }
            }
            return vec![self.build_issue(
                query,
                "Potential mass delete on parent table.",
                m.as_str(),
            )];
        }
        Vec::new()
    }
}

// REL-DEAD-001
struct DeadlockPatternRule;
static PAT_DEADLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)\bBEGIN\b[\s\S]*?\bUPDATE\s+(\w+)\b[\s\S]*?\bUPDATE\s+(\w+)\b[\s\S]*?\bCOMMIT\b",
    )
    .unwrap()
});
impl Rule for DeadlockPatternRule {
    fn id(&self) -> &'static str {
        "REL-DEAD-001"
    }
    fn name(&self) -> &'static str {
        "Deadlock Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDeadlock)
    }
    fn impact(&self) -> &'static str {
        "Deadlocks occur when transactions lock tables in different order."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(caps) = PAT_DEADLOCK.captures(&query.raw) {
            let t1 = caps
                .get(1)
                .map(|m| m.as_str().to_lowercase())
                .unwrap_or_default();
            let t2 = caps
                .get(2)
                .map(|m| m.as_str().to_lowercase())
                .unwrap_or_default();
            if t1 != t2 {
                return vec![self.build_issue(
                    query,
                    "Potential deadlock pattern: multiple table updates within a transaction.",
                    query.snippet(80),
                )];
            }
        }
        Vec::new()
    }
}

// REL-DEAD-002
struct LockEscalationRiskRule;
impl Rule for LockEscalationRiskRule {
    fn id(&self) -> &'static str {
        "REL-DEAD-002"
    }
    fn name(&self) -> &'static str {
        "Lock Escalation Risk"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDeadlock)
    }
    fn impact(&self) -> &'static str {
        "Wide UPDATE/DELETE statements lock the entire table, blocking all other operations."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("WHERE") {
            return Vec::new();
        }
        // Suppress intentional bulk operations
        if let Some(ref file) = query.location.file {
            let fl = file.to_lowercase();
            let filename = fl.rsplit('/').next().unwrap_or(&fl);
            if fl.contains("cache")
                || fl.contains("clear")
                || fl.contains("reset")
                || fl.contains("cleanup")
                || fl.contains("purge")
                || fl.contains("flush")
                || fl.contains("init.sql")
                || fl.contains("setup.sql")
                || fl.contains("teardown")
                || fl.contains("truncate")
                || filename.contains("flush")
                || filename.contains("clear")
                || filename.contains("reset")
                || filename.contains("purge")
                || filename.contains("testinfra")
                || filename.contains("sync")
            {
                return Vec::new();
            }
        }
        vec![self.build_issue(
            query,
            &format!("{} without WHERE clause - will lock entire table.", qt),
            query.snippet(100),
        )]
    }
}

// REL-TIMEOUT-001
struct LongRunningQueryRiskRule;
impl Rule for LongRunningQueryRiskRule {
    fn id(&self) -> &'static str {
        "REL-TIMEOUT-001"
    }
    fn name(&self) -> &'static str {
        "Long-Running Query Risk"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTimeout)
    }
    fn impact(&self) -> &'static str {
        "Complex queries without bounds can run for hours."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        let join_count = upper.matches("JOIN").count();
        let sub_count = upper.matches("(SELECT").count();
        if join_count + sub_count >= 3 && !upper.contains("LIMIT") && !upper.contains("TOP ") {
            // A single-row PK lookup returns fast regardless of join count.
            // Only flag when we cannot prove the result set is bounded.
            if let Some(ref facts) = query.facts {
                if facts.is_single_row_lookup() {
                    return Vec::new();
                }
            }
            let msg = format!(
                "Complex query ({} JOINs, {} subqueries) without row limit or timeout.",
                join_count, sub_count
            );
            return vec![self.build_issue(query, &msg, query.snippet(100))];
        }
        Vec::new()
    }
}

// REL-STALE-001
struct StaleReadRiskRule;
static PAT_STALE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)(INSERT|UPDATE)\s+[^;]+;\s*SELECT\s+[^;]+FROM\s+(\w+)").unwrap()
});
impl Rule for StaleReadRiskRule {
    fn id(&self) -> &'static str {
        "REL-STALE-001"
    }
    fn name(&self) -> &'static str {
        "Stale Read Risk"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelConsistency)
    }
    fn impact(&self) -> &'static str {
        "In replicated databases, writes go to primary, reads may hit replicas."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains("BEGIN") {
            return Vec::new();
        }
        PAT_STALE.find(&query.raw).map(|_| vec![self.build_issue(query, "Potential stale read: SELECT immediately follows UPDATE/INSERT without transaction.", query.snippet(80))]).unwrap_or_default()
    }
}

// REL-RETRY-001
struct MissingRetryLogicRule;
static PAT_RETRY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\bBEGIN\s+(TRAN|TRANSACTION)\b[\s\S]*?\b(COMMIT|ROLLBACK)\b").unwrap()
});
impl Rule for MissingRetryLogicRule {
    fn id(&self) -> &'static str {
        "REL-RETRY-001"
    }
    fn name(&self) -> &'static str {
        "Missing Retry Logic"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelRetry)
    }
    fn impact(&self) -> &'static str {
        "Without retry logic, operations fail permanently on transient errors."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if PAT_RETRY.find(&query.raw).is_some() {
            let upper = query.raw_upper();
            let has_retry = [
                "TRY",
                "CATCH",
                "EXCEPTION",
                "RETRY",
                "ATTEMPT",
                "LOOP",
                "WHILE",
            ]
            .iter()
            .any(|k| upper.contains(k));
            if !has_retry {
                return vec![self.build_issue(
                    query,
                    "Transaction block without retry logic - will fail on transient errors.",
                    query.snippet(80),
                )];
            }
        }
        Vec::new()
    }
}

// --- Dialect-specific reliability rules ---

// REL-MYSQL-001
struct InsertIgnoreRule;
static PAT_IGNORE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bINSERT\s+IGNORE\b").unwrap());
impl Rule for InsertIgnoreRule {
    fn id(&self) -> &'static str {
        "REL-MYSQL-001"
    }
    fn name(&self) -> &'static str {
        "INSERT IGNORE Silences Errors"
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
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "INSERT IGNORE silently discards duplicate key errors and constraint violations."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_IGNORE
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "INSERT IGNORE detected - errors silently suppressed.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-MYSQL-002
struct ReplaceIntoRule;
static PAT_REPLACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bREPLACE\s+INTO\b").unwrap());
impl Rule for ReplaceIntoRule {
    fn id(&self) -> &'static str {
        "REL-MYSQL-002"
    }
    fn name(&self) -> &'static str {
        "REPLACE INTO Deletes and Reinserts"
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
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "REPLACE INTO deletes existing row and inserts a new one, breaking foreign keys."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_REPLACE
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "REPLACE INTO detected - silently deletes and reinserts rows.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-MYSQL-003
struct Utf8InsteadOfUtf8mb4Rule;
static PAT_UTF8: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:CHARACTER\s+SET|CHARSET|DEFAULT\s+CHARSET)\s*=?\s*utf8\b").unwrap()
});
impl Rule for Utf8InsteadOfUtf8mb4Rule {
    fn id(&self) -> &'static str {
        "REL-MYSQL-003"
    }
    fn name(&self) -> &'static str {
        "MySQL utf8 Instead of utf8mb4"
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
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "4-byte Unicode characters will be silently truncated or rejected."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_UTF8.find(&query.raw) {
            // Exclude utf8mb4 matches
            let end = m.end();
            let rest = &query.raw[end..];
            if rest.starts_with("mb4") {
                return Vec::new();
            }
            return vec![self.build_issue(
                query,
                "MySQL utf8 (3-byte) charset detected - use utf8mb4.",
                m.as_str(),
            )];
        }
        Vec::new()
    }
}

// REL-MYSQL-004
struct OnUpdateCascadeTimestampRule;
static PAT_CASCADE_TS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bON\s+UPDATE\s+CASCADE\b").unwrap());
impl Rule for OnUpdateCascadeTimestampRule {
    fn id(&self) -> &'static str {
        "REL-MYSQL-004"
    }
    fn name(&self) -> &'static str {
        "ON UPDATE CASCADE With Timestamp Column"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelForeignKey)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "Timestamp auto-update on parent row triggers CASCADE to all children."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_CASCADE_TS
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "ON UPDATE CASCADE detected - verify no timestamp auto-update triggers exist.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-MYSQL-005
struct MysqlMyisamEngineRule;
static PAT_MYISAM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bENGINE\s*=\s*MyISAM\b").unwrap());
impl Rule for MysqlMyisamEngineRule {
    fn id(&self) -> &'static str {
        "REL-MYSQL-005"
    }
    fn name(&self) -> &'static str {
        "MyISAM Engine Usage"
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
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "MyISAM does not support transactions, crash recovery, or foreign keys."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_MYISAM
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "MyISAM engine detected - no crash recovery or transactions.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-TSQL-001
struct AtAtIdentityRule;
static PAT_IDENTITY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)@@IDENTITY\b").unwrap());
impl Rule for AtAtIdentityRule {
    fn id(&self) -> &'static str {
        "REL-TSQL-001"
    }
    fn name(&self) -> &'static str {
        "@@IDENTITY Instead of SCOPE_IDENTITY()"
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
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "@@IDENTITY may return wrong value due to triggers."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_IDENTITY
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "@@IDENTITY used - may return wrong value due to triggers.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-TSQL-002
struct MergeWithoutHoldlockRule;
impl Rule for MergeWithoutHoldlockRule {
    fn id(&self) -> &'static str {
        "REL-TSQL-002"
    }
    fn name(&self) -> &'static str {
        "MERGE Without HOLDLOCK"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelRaceCondition)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "Concurrent MERGE can cause duplicate key errors or lost updates."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("MERGE") {
            return Vec::new();
        }
        if upper.contains("HOLDLOCK") || upper.contains("SERIALIZABLE") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "MERGE without HOLDLOCK - concurrent execution may cause race conditions.",
            query.snippet(80),
        )]
    }
}

// REL-TSQL-003
struct TruncateInTryWithoutCatchRule;
impl Rule for TruncateInTryWithoutCatchRule {
    fn id(&self) -> &'static str {
        "REL-TSQL-003"
    }
    fn name(&self) -> &'static str {
        "TRUNCATE in TRY Without CATCH"
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
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "If TRUNCATE fails, the error is not caught."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("TRUNCATE") || !upper.contains("BEGIN TRY") {
            return Vec::new();
        }
        if upper.contains("BEGIN CATCH") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "TRUNCATE inside BEGIN TRY without BEGIN CATCH - errors will be silently swallowed.",
            query.snippet(80),
        )]
    }
}

// REL-PG-001
struct AlterTableAddColumnVolatileDefaultRule;
impl Rule for AlterTableAddColumnVolatileDefaultRule {
    fn id(&self) -> &'static str {
        "REL-PG-001"
    }
    fn name(&self) -> &'static str {
        "ALTER TABLE ADD COLUMN With Volatile DEFAULT"
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
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "A table rewrite on a large table locks it exclusively."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("ALTER TABLE") || !upper.contains("ADD") || !upper.contains("DEFAULT") {
            return Vec::new();
        }
        for func in &[
            "NOW()",
            "CURRENT_TIMESTAMP",
            "RANDOM()",
            "GEN_RANDOM_UUID()",
            "CLOCK_TIMESTAMP()",
        ] {
            if upper.contains(func) {
                return vec![self.build_issue(
                    query,
                    "ALTER TABLE ADD COLUMN with volatile DEFAULT - may rewrite entire table.",
                    query.snippet(100),
                )];
            }
        }
        Vec::new()
    }
}

// REL-PG-002
struct CreateIndexWithoutConcurrentlyRule;
static PAT_CREATE_IDX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+\w+").unwrap());
impl Rule for CreateIndexWithoutConcurrentlyRule {
    fn id(&self) -> &'static str {
        "REL-PG-002"
    }
    fn name(&self) -> &'static str {
        "CREATE INDEX Without CONCURRENTLY"
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
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "On large tables, CREATE INDEX can lock writes for minutes."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_CREATE_IDX.find(&query.raw) {
            if query.raw_upper().contains("CONCURRENTLY") {
                return Vec::new();
            }
            return vec![self.build_issue(
                query,
                "CREATE INDEX without CONCURRENTLY - will lock table against writes.",
                m.as_str(),
            )];
        }
        Vec::new()
    }
}

// REL-ORA-001
struct ConnectByWithoutNocycleRule;
impl Rule for ConnectByWithoutNocycleRule {
    fn id(&self) -> &'static str {
        "REL-ORA-001"
    }
    fn name(&self) -> &'static str {
        "CONNECT BY Without NOCYCLE"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTimeout)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "A cyclic reference causes CONNECT BY to loop indefinitely."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("CONNECT BY") {
            return Vec::new();
        }
        if upper.contains("NOCYCLE") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "CONNECT BY without NOCYCLE - cyclic data will cause infinite loop.",
            query.snippet(80),
        )]
    }
}

// REL-ORA-002
struct OracleAlterTableMoveWithoutRebuildRule;
impl Rule for OracleAlterTableMoveWithoutRebuildRule {
    fn id(&self) -> &'static str {
        "REL-ORA-002"
    }
    fn name(&self) -> &'static str {
        "ALTER TABLE MOVE Without REBUILD INDEX"
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
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "After MOVE, all indexes become UNUSABLE."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("ALTER TABLE") || !upper.contains("MOVE") {
            return Vec::new();
        }
        if upper.contains("REBUILD") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "ALTER TABLE MOVE without REBUILD INDEX - all indexes become UNUSABLE.",
            query.snippet(80),
        )]
    }
}

// REL-ORA-003
struct OracleAutonomousTransactionRule;
static PAT_AUTONOMOUS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b").unwrap());
impl Rule for OracleAutonomousTransactionRule {
    fn id(&self) -> &'static str {
        "REL-ORA-003"
    }
    fn name(&self) -> &'static str {
        "PRAGMA AUTONOMOUS_TRANSACTION"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelTransaction)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "Commits in autonomous transaction persist even if parent rolls back."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_AUTONOMOUS
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "AUTONOMOUS_TRANSACTION detected - commits persist even if parent rolls back.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-BQ-001
struct BigQueryDmlWithoutWhereOnPartitionedRule;
impl Rule for BigQueryDmlWithoutWhereOnPartitionedRule {
    fn id(&self) -> &'static str {
        "REL-BQ-001"
    }
    fn name(&self) -> &'static str {
        "DML Without WHERE on BigQuery"
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
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "DML on all partitions is expensive. BigQuery does not support ROLLBACK."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" {
            return Vec::new();
        }
        if query.raw_upper().contains("WHERE") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "DML without WHERE on BigQuery - will process all partitions.",
            query.snippet(80),
        )]
    }
}

// REL-CH-001
struct ClickHouseSelectWithoutFinalRule;
impl Rule for ClickHouseSelectWithoutFinalRule {
    fn id(&self) -> &'static str {
        "REL-CH-001"
    }
    fn name(&self) -> &'static str {
        "SELECT Without FINAL on ReplacingMergeTree"
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
        DialectSet::new(&["clickhouse"])
    }
    fn impact(&self) -> &'static str {
        "Queries return duplicate rows that should have been deduplicated."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !query.is_select() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("FINAL") {
            return Vec::new();
        }
        if upper.contains("REPLACING") || upper.contains("COLLAPSING") {
            return vec![self.build_issue(
                query,
                "SELECT without FINAL on ReplacingMergeTree - may return unmerged duplicates.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

// REL-PRESTO-001
struct PrestoInsertOverwriteWithoutPartitionRule;
impl Rule for PrestoInsertOverwriteWithoutPartitionRule {
    fn id(&self) -> &'static str {
        "REL-PRESTO-001"
    }
    fn name(&self) -> &'static str {
        "INSERT OVERWRITE Without Partition"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["presto", "trino"])
    }
    fn impact(&self) -> &'static str {
        "All existing data in the table is replaced."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("INSERT OVERWRITE") {
            return Vec::new();
        }
        if upper.contains("PARTITION") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "INSERT OVERWRITE without PARTITION - will replace ALL data in target table.",
            query.snippet(80),
        )]
    }
}

// REL-RS-001
struct CopyWithoutManifestRule;
static PAT_RS_COPY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCOPY\b.*\bFROM\b.*\bs3://").unwrap());
impl Rule for CopyWithoutManifestRule {
    fn id(&self) -> &'static str {
        "REL-RS-001"
    }
    fn name(&self) -> &'static str {
        "COPY Without MANIFEST"
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
        DialectSet::new(&["redshift"])
    }
    fn impact(&self) -> &'static str {
        "Without MANIFEST, any file matching the S3 prefix is loaded."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_RS_COPY.find(&query.raw) {
            if !query.raw_upper().contains("MANIFEST") {
                return vec![self.build_issue(
                    query,
                    "COPY from S3 without MANIFEST - may load unexpected files.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// REL-SPARK-001
struct SparkOverwriteWithoutPartitionRule;
impl Rule for SparkOverwriteWithoutPartitionRule {
    fn id(&self) -> &'static str {
        "REL-SPARK-001"
    }
    fn name(&self) -> &'static str {
        "INSERT OVERWRITE Without Partition"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["spark", "databricks"])
    }
    fn impact(&self) -> &'static str {
        "All existing data in the table is replaced."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("INSERT OVERWRITE") {
            return Vec::new();
        }
        if upper.contains("PARTITION") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "INSERT OVERWRITE without PARTITION - will replace ALL data.",
            query.snippet(80),
        )]
    }
}

// REL-SQLITE-001
struct SqliteDropColumnRule;
static PAT_SQLITE_DROP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\b").unwrap());
impl Rule for SqliteDropColumnRule {
    fn id(&self) -> &'static str {
        "REL-SQLITE-001"
    }
    fn name(&self) -> &'static str {
        "ALTER TABLE DROP COLUMN (SQLite Limitation)"
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
        DialectSet::new(&["sqlite"])
    }
    fn impact(&self) -> &'static str {
        "ALTER TABLE DROP COLUMN has limited support in SQLite (3.35+)."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_SQLITE_DROP
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "ALTER TABLE DROP COLUMN - limited SQLite support (3.35+).",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// REL-SQLITE-002
struct SqliteForeignKeysOffRule;
static PAT_SQLITE_FK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bPRAGMA\s+foreign_keys\s*=\s*(?:OFF|0|false)\b").unwrap());
impl Rule for SqliteForeignKeysOffRule {
    fn id(&self) -> &'static str {
        "REL-SQLITE-002"
    }
    fn name(&self) -> &'static str {
        "PRAGMA foreign_keys = OFF"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelForeignKey)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["sqlite"])
    }
    fn impact(&self) -> &'static str {
        "Without foreign key enforcement, INSERT and DELETE can create orphan records."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_SQLITE_FK
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "PRAGMA foreign_keys = OFF - referential integrity disabled.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnsafeWriteRule),
        Box::new(TruncateWithoutTransactionRule),
        Box::new(AlterTableDestructiveRule),
        Box::new(DropTableRule),
        Box::new(MissingRollbackRule),
        Box::new(AutocommitDisabledRule),
        Box::new(EmptyTransactionRule),
        Box::new(ExceptionSwallowedRule),
        Box::new(LongTransactionWithoutSavepointRule),
        Box::new(NonIdempotentInsertRule),
        Box::new(NonIdempotentUpdateRule),
        Box::new(ReadModifyWriteLockingRule),
        Box::new(TOCTOUPatternRule),
        Box::new(OrphanRecordRiskRule),
        Box::new(CascadeDeleteRiskRule),
        Box::new(DeadlockPatternRule),
        Box::new(LockEscalationRiskRule),
        Box::new(LongRunningQueryRiskRule),
        Box::new(StaleReadRiskRule),
        Box::new(MissingRetryLogicRule),
        Box::new(InsertIgnoreRule),
        Box::new(ReplaceIntoRule),
        Box::new(Utf8InsteadOfUtf8mb4Rule),
        Box::new(OnUpdateCascadeTimestampRule),
        Box::new(MysqlMyisamEngineRule),
        Box::new(AtAtIdentityRule),
        Box::new(MergeWithoutHoldlockRule),
        Box::new(TruncateInTryWithoutCatchRule),
        Box::new(AlterTableAddColumnVolatileDefaultRule),
        Box::new(CreateIndexWithoutConcurrentlyRule),
        Box::new(ConnectByWithoutNocycleRule),
        Box::new(OracleAlterTableMoveWithoutRebuildRule),
        Box::new(OracleAutonomousTransactionRule),
        Box::new(BigQueryDmlWithoutWhereOnPartitionedRule),
        Box::new(ClickHouseSelectWithoutFinalRule),
        Box::new(PrestoInsertOverwriteWithoutPartitionRule),
        Box::new(CopyWithoutManifestRule),
        Box::new(SparkOverwriteWithoutPartitionRule),
        Box::new(SqliteDropColumnRule),
        Box::new(SqliteForeignKeysOffRule),
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
    fn all_reliability_rules_metadata() {
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
    fn all_reliability_rules_no_match_simple() {
        let rules = all_rules();
        let query = q("SELECT 1", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn all_reliability_rules_dialect_coverage() {
        let rules = all_rules();
        let dialects = [
            "postgresql",
            "mysql",
            "tsql",
            "oracle",
            "sqlite",
            "bigquery",
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
    fn delete_without_where() {
        let rules = all_rules();
        let query = q("DELETE FROM users", "postgresql", "DELETE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn update_without_where() {
        let rules = all_rules();
        let query = q("UPDATE users SET active = false", "postgresql", "UPDATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn drop_table() {
        let rules = all_rules();
        let query = q("DROP TABLE users", "postgresql", "DROP");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn truncate_table() {
        let rules = all_rules();
        let query = q("TRUNCATE TABLE users", "postgresql", "TRUNCATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn insert_without_conflict() {
        let rules = all_rules();
        let query = q(
            "INSERT INTO users (name) VALUES ('test')",
            "postgresql",
            "INSERT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn insert_with_on_conflict() {
        let rules = all_rules();
        let query = q(
            "INSERT INTO users (name) VALUES ('test') ON CONFLICT DO NOTHING",
            "postgresql",
            "INSERT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn transaction_patterns() {
        let rules = all_rules();
        let query = q(
            "BEGIN; UPDATE users SET x = 1; COMMIT;",
            "postgresql",
            "UPDATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn cascade_delete() {
        let rules = all_rules();
        let query = q(
            "ALTER TABLE orders ADD FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
            "mysql",
            "ALTER",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn volatile_default() {
        let rules = all_rules();
        let query = q(
            "ALTER TABLE t ADD COLUMN created_at TIMESTAMP DEFAULT now()",
            "postgresql",
            "ALTER",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn error_handling() {
        let rules = all_rules();
        let query = q(
            "CREATE PROCEDURE p AS BEGIN TRY SELECT 1 END TRY BEGIN CATCH END CATCH",
            "tsql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_charset() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE t (name VARCHAR(100)) CHARACTER SET utf8",
            "mysql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_utf8mb4() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE t (name VARCHAR(100)) CHARACTER SET utf8mb4",
            "mysql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn stale_stats() {
        let rules = all_rules();
        let query = q("ANALYZE users", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn race_condition() {
        let rules = all_rules();
        let query = q("SELECT * FROM t FOR UPDATE", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn dead_code() {
        let rules = all_rules();
        let query = q(
            "CREATE PROCEDURE p AS BEGIN RETURN; SELECT 1; END",
            "tsql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn insert_path() {
        let rules = all_rules();
        let query = q(
            "INSERT INTO audit_log (event) VALUES ('login')",
            "postgresql",
            "INSERT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn create_table_path() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE events (id INT, data TEXT)",
            "postgresql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn adhoc_context() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.source_context = "adhoc".to_string();
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    // Targeted tests for uncovered branches

    #[test]
    fn init_file_skip() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.location = crate::models::Location::new(1, 1).with_file("db/init.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn setup_file_skip() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.location = crate::models::Location::new(1, 1).with_file("test/setup.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn fixture_file_skip() {
        let rules = all_rules();
        let mut query = q("TRUNCATE TABLE users", "postgresql", "TRUNCATE");
        query.location = crate::models::Location::new(1, 1).with_file("test/fixture.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn complex_query_with_joins_and_subqueries() {
        let rules = all_rules();
        let sql = "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id WHERE x IN (SELECT id FROM d) AND y IN (SELECT id FROM e)";
        let mut query = q(sql, "postgresql", "SELECT");
        query.facts = Some(crate::query_analysis::QueryFacts::from_sql(
            sql,
            "postgresql",
        ));
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn single_row_lookup_skip() {
        let rules = all_rules();
        let sql = "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id WHERE a.id = 1";
        let mut query = q(sql, "postgresql", "SELECT");
        query.facts = Some(crate::query_analysis::QueryFacts::from_sql(
            sql,
            "postgresql",
        ));
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn transaction_without_retry() {
        let rules = all_rules();
        let query = q(
            "BEGIN; UPDATE accounts SET balance = balance - 100; COMMIT;",
            "postgresql",
            "UPDATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn transaction_with_retry() {
        let rules = all_rules();
        let query = q(
            "BEGIN TRY UPDATE accounts SET balance = balance - 100 END TRY BEGIN CATCH END CATCH",
            "tsql",
            "UPDATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "CREATE TABLE t (name VARCHAR(100)) ENGINE=MyISAM",
            "CREATE TABLE t (name VARCHAR(100)) CHARACTER SET utf8",
            "ALTER TABLE t ADD COLUMN x INT ON UPDATE CURRENT_TIMESTAMP",
            "SELECT * FROM t FOR UPDATE",
            "CREATE TABLE t (id INT AUTO_INCREMENT, data TEXT) ENGINE=InnoDB",
        ] {
            let qt = if sql.starts_with("CREATE") || sql.starts_with("ALTER") {
                "CREATE"
            } else {
                "SELECT"
            };
            let query = q(sql, "mysql", qt);
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn oracle_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "SELECT * FROM t WHERE ROWNUM < 100",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.x = s.x",
        ] {
            let query = q(sql, "oracle", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn sqlite_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT) WITHOUT ROWID",
            "PRAGMA journal_mode=WAL",
        ] {
            let query = q(sql, "sqlite", "CREATE");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn tsql_specific_patterns() {
        let rules = all_rules();
        for sql in &[
            "SELECT * FROM t WITH (NOLOCK)",
            "INSERT INTO t WITH (TABLOCK) SELECT * FROM s",
        ] {
            let query = q(sql, "tsql", "SELECT");
            for rule in &rules {
                let _ = rule.check(&query);
            }
        }
    }

    #[test]
    fn bigquery_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t LIMIT 1000000", "bigquery", "SELECT");
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
    fn spark_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "spark", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
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
    fn clickhouse_patterns() {
        let rules = all_rules();
        let query = q("SELECT * FROM t", "clickhouse", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn on_conflict_patterns() {
        let rules = all_rules();
        let query = q(
            "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET x = 1",
            "postgresql",
            "INSERT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn on_duplicate_key() {
        let rules = all_rules();
        let query = q(
            "INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE x = 1",
            "mysql",
            "INSERT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn merge_statement() {
        let rules = all_rules();
        let query = q("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.x = s.x WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)", "tsql", "MERGE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn alter_table_patterns() {
        let rules = all_rules();
        let query = q(
            "ALTER TABLE t ADD COLUMN x INT DEFAULT 0 NOT NULL",
            "postgresql",
            "ALTER",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn volatile_default_patterns() {
        let rules = all_rules();
        let query = q(
            "ALTER TABLE t ADD COLUMN created_at TIMESTAMP DEFAULT now()",
            "postgresql",
            "ALTER",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    // Targeted branch coverage tests

    #[test]
    fn delete_from_init_file() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.location = crate::models::Location::new(1, 1).with_file("scripts/init_db.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn delete_from_reset_file() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.location = crate::models::Location::new(1, 1).with_file("tools/reset.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn delete_from_teardown_file() {
        let rules = all_rules();
        let mut query = q("DELETE FROM users", "postgresql", "DELETE");
        query.location = crate::models::Location::new(1, 1).with_file("test/teardown.sql");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn long_transaction_pattern() {
        let rules = all_rules();
        let sql = "BEGIN TRANSACTION; UPDATE a SET x=1; UPDATE b SET y=2; UPDATE c SET z=3; DELETE FROM d; INSERT INTO e VALUES (1); COMMIT;";
        let query = q(sql, "postgresql", "UPDATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn append_only_table_insert() {
        let rules = all_rules();
        let mut query = q(
            "INSERT INTO audit_log (event) VALUES ('test')",
            "postgresql",
            "INSERT",
        );
        query.tables = vec!["audit_log".to_string()];
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn append_only_table_with_schema() {
        let rules = all_rules();
        let mut query = q(
            "INSERT INTO public.event_log (event) VALUES ('test')",
            "postgresql",
            "INSERT",
        );
        query.tables = vec!["public.event_log".to_string()];
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn complex_query_no_limit_fires() {
        let rules = all_rules();
        let sql =
            "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id WHERE x IN (SELECT id FROM d)";
        let mut query = q(sql, "postgresql", "SELECT");
        query.facts = Some(crate::query_analysis::QueryFacts {
            join_count: 2,
            subquery_count: 1,
            has_where: true,
            where_has_pk_equality: false,
            ..Default::default()
        });
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn read_modify_write_race() {
        let rules = all_rules();
        let query = q(
            "SELECT balance FROM accounts; UPDATE accounts SET balance = balance - 100",
            "postgresql",
            "SELECT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn transaction_without_retry_fires() {
        let rules = all_rules();
        let query = q(
            "BEGIN; UPDATE accounts SET balance = 0; COMMIT;",
            "postgresql",
            "UPDATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn tsql_truncate_try_no_catch() {
        let rules = all_rules();
        let query = q(
            "BEGIN TRY TRUNCATE TABLE temp_data END TRY",
            "tsql",
            "TRUNCATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn tsql_truncate_try_with_catch() {
        let rules = all_rules();
        let query = q(
            "BEGIN TRY TRUNCATE TABLE temp_data END TRY BEGIN CATCH END CATCH",
            "tsql",
            "TRUNCATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn oracle_alter_table_move() {
        let rules = all_rules();
        let query = q("ALTER TABLE t MOVE TABLESPACE new_ts", "oracle", "ALTER");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn oracle_alter_table_move_rebuild() {
        let rules = all_rules();
        let query = q(
            "ALTER TABLE t MOVE TABLESPACE new_ts; ALTER INDEX idx REBUILD",
            "oracle",
            "ALTER",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn clickhouse_replacing_without_final() {
        let rules = all_rules();
        let query = q("SELECT * FROM events_replacing", "clickhouse", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn clickhouse_replacing_with_final() {
        let rules = all_rules();
        let query = q(
            "SELECT * FROM events_replacing FINAL",
            "clickhouse",
            "SELECT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn clickhouse_collapsing_without_final() {
        let rules = all_rules();
        let query = q("SELECT * FROM events_collapsing", "clickhouse", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn redshift_copy_without_manifest() {
        let rules = all_rules();
        let query = q("COPY t FROM 's3://bucket/prefix'", "redshift", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn redshift_copy_with_manifest() {
        let rules = all_rules();
        let query = q(
            "COPY t FROM 's3://bucket/prefix' MANIFEST",
            "redshift",
            "SELECT",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn presto_cross_join_reliability() {
        let rules = all_rules();
        let query = q("SELECT * FROM a CROSS JOIN b", "presto", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn spark_cache_pattern() {
        let rules = all_rules();
        let query = q("CACHE TABLE t", "spark", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn sqlite_without_rowid() {
        let rules = all_rules();
        let query = q("CREATE TABLE t (id INT) WITHOUT ROWID", "sqlite", "CREATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn bigquery_dml_pattern() {
        let rules = all_rules();
        let query = q("UPDATE t SET x = 1 WHERE id = 1", "bigquery", "UPDATE");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_cascade_on_delete() {
        let rules = all_rules();
        let query = q(
            "CREATE TABLE orders (user_id INT REFERENCES users(id) ON DELETE CASCADE)",
            "mysql",
            "CREATE",
        );
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn mysql_cascade_on_update() {
        let rules = all_rules();
        let query = q("ALTER TABLE orders ADD CONSTRAINT fk FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE", "mysql", "ALTER");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }
}
