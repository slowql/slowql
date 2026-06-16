use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

// REL-DATA-001: DELETE/UPDATE without WHERE
struct UnsafeWriteRule;
impl Rule for UnsafeWriteRule {
    fn id(&self) -> &'static str { "REL-DATA-001" }
    fn name(&self) -> &'static str { "Catastrophic Data Loss Risk" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) }
    fn impact(&self) -> &'static str { "Instant data loss of entire table content." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "DELETE" && qt != "UPDATE" { return Vec::new(); }
        if query.raw_upper().contains("WHERE") { return Vec::new(); }
        let msg = format!("CRITICAL: {} statement has no WHERE clause.", qt);
        vec![self.build_issue(query, &msg, &query.raw[..query.raw.len().min(80)])]
    }
}

// REL-DATA-002
struct TruncateWithoutTransactionRule;
static PAT_TRUNC: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bTRUNCATE\b").unwrap());
impl Rule for TruncateWithoutTransactionRule {
    fn id(&self) -> &'static str { "REL-DATA-002" }
    fn name(&self) -> &'static str { "Truncate Without Transaction" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) }
    fn impact(&self) -> &'static str { "TRUNCATE removes all rows instantly with no row-by-row logging." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TRUNC.find(&query.raw).map(|m| vec![self.build_issue(query, "TRUNCATE TABLE detected outside explicit transaction.", m.as_str())]).unwrap_or_default()
    }
}

// REL-DATA-003
struct AlterTableDestructiveRule;
static PAT_ALTER_DEST: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\bALTER\s+TABLE\b.+\bDROP\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bMODIFY\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bRENAME\s+COLUMN\b)|(\bALTER\s+TABLE\b.+\bCHANGE\s+COLUMN\b)").unwrap());
impl Rule for AlterTableDestructiveRule {
    fn id(&self) -> &'static str { "REL-DATA-003" }
    fn name(&self) -> &'static str { "ALTER TABLE Without Backup Signal" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) }
    fn impact(&self) -> &'static str { "DROP COLUMN permanently destroys column data." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_ALTER_DEST.find(&query.raw).map(|m| vec![self.build_issue(query, "Destructive ALTER TABLE operation detected.", m.as_str())]).unwrap_or_default()
    }
}

// REL-DATA-004
struct DropTableRule;
impl Rule for DropTableRule {
    fn id(&self) -> &'static str { "REL-DATA-004" }
    fn name(&self) -> &'static str { "Destructive Schema Change (DROP)" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) }
    fn impact(&self) -> &'static str { "Irreversible schema and data destruction." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.query_type.as_deref() == Some("DROP") { vec![self.build_issue(query, "DROP statement detected.", &query.raw[..query.raw.len().min(80)])] } else { Vec::new() }
    }
}

// REL-TXN-001
struct MissingRollbackRule;
static PAT_BEGIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(BEGIN|START\s+TRANSACTION)\b").unwrap());
impl Rule for MissingRollbackRule {
    fn id(&self) -> &'static str { "REL-TXN-001" }
    fn name(&self) -> &'static str { "Missing Transaction Rollback Handler" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelTransaction) }
    fn impact(&self) -> &'static str { "Without ROLLBACK, a failed transaction may partially commit changes." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_BEGIN.find(&query.raw).map(|m| vec![self.build_issue(query, "Transaction opened - verify ROLLBACK handler exists.", m.as_str())]).unwrap_or_default()
    }
}

// REL-TXN-002
struct AutocommitDisabledRule;
static PAT_AUTOCOMMIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\bSET\s+autocommit\s*=\s*0\b)|(\bSET\s+IMPLICIT_TRANSACTIONS\s+ON\b)").unwrap());
impl Rule for AutocommitDisabledRule {
    fn id(&self) -> &'static str { "REL-TXN-002" }
    fn name(&self) -> &'static str { "Autocommit Disable Detection" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelTransaction) }
    fn impact(&self) -> &'static str { "Disabling autocommit causes uncommitted changes to be silently rolled back on connection drop." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTOCOMMIT.find(&query.raw).map(|m| vec![self.build_issue(query, "Autocommit disabled - risk of silent rollback on connection drop.", m.as_str())]).unwrap_or_default()
    }
}

// REL-TXN-003
struct EmptyTransactionRule;
static PAT_EMPTY_TXN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:BEGIN|START\s+TRANSACTION)\s*;\s*(?:COMMIT|END)\b").unwrap());
impl Rule for EmptyTransactionRule {
    fn id(&self) -> &'static str { "REL-TXN-003" }
    fn name(&self) -> &'static str { "Empty Transaction Block" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelTransaction) }
    fn impact(&self) -> &'static str { "Empty transactions acquire locks for no purpose." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_EMPTY_TXN.find(&query.raw).map(|m| vec![self.build_issue(query, "Empty transaction block detected - no DML between BEGIN and COMMIT.", m.as_str())]).unwrap_or_default()
    }
}

// REL-ERR-001
struct ExceptionSwallowedRule;
static PAT_SWALLOW: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHEN\s+OTHERS\s+THEN\s+NULL\b").unwrap());
impl Rule for ExceptionSwallowedRule {
    fn id(&self) -> &'static str { "REL-ERR-001" }
    fn name(&self) -> &'static str { "Swallowed Exception Pattern" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelErrorHandling) }
    fn impact(&self) -> &'static str { "Silent exception swallowing means failed operations appear to succeed." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SWALLOW.find(&query.raw).map(|m| vec![self.build_issue(query, "Exception handler may be swallowing errors silently.", m.as_str())]).unwrap_or_default()
    }
}

// REL-REC-001
struct LongTransactionWithoutSavepointRule;
static PAT_SAVEPOINT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSAVEPOINT\b").unwrap());
impl Rule for LongTransactionWithoutSavepointRule {
    fn id(&self) -> &'static str { "REL-REC-001" }
    fn name(&self) -> &'static str { "Missing Savepoint in Long Transaction" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelRecovery) }
    fn impact(&self) -> &'static str { "A failure forces rollback of all previous steps." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SAVEPOINT.find(&query.raw).map(|m| vec![self.build_issue(query, "Long transaction detected - consider using SAVEPOINTs for partial recovery.", m.as_str())]).unwrap_or_default()
    }
}

// REL-IDEM-001
struct NonIdempotentInsertRule;
impl Rule for NonIdempotentInsertRule {
    fn id(&self) -> &'static str { "REL-IDEM-001" }
    fn name(&self) -> &'static str { "Non-Idempotent INSERT Pattern" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelIdempotency) }
    fn impact(&self) -> &'static str { "Non-idempotent INSERTs cause duplicate data on network retries." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_insert() { return Vec::new(); }
        let upper = query.raw_upper();
        let idempotent = upper.contains("ON CONFLICT") || upper.contains("ON DUPLICATE KEY") || upper.contains("INSERT IGNORE") || upper.contains("MERGE") || upper.contains("NOT EXISTS");
        if idempotent { return Vec::new(); }
        vec![self.build_issue(query, "INSERT without idempotency guard - will fail or create duplicates on retry.", &query.raw[..query.raw.len().min(100)])]
    }
}

// REL-IDEM-002
struct NonIdempotentUpdateRule;
static PAT_REL_UPDATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSET\s+(\w+)\s*=\s*\1\s*[+\-]").unwrap());
impl Rule for NonIdempotentUpdateRule {
    fn id(&self) -> &'static str { "REL-IDEM-002" }
    fn name(&self) -> &'static str { "Non-Idempotent UPDATE Pattern" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelIdempotency) }
    fn impact(&self) -> &'static str { "Relative updates execute multiple times on retry, causing incorrect totals." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_update() { return Vec::new(); }
        if let Some(m) = PAT_REL_UPDATE.find(&query.raw) {
            let upper = query.raw_upper();
            let has_version = ["VERSION", "UPDATED_AT", "MODIFIED_AT", "ETAG", "ROW_VERSION", "LOCK_VERSION"].iter().any(|v| upper.contains(v));
            if !has_version {
                return vec![self.build_issue(query, "Relative UPDATE without version check - not idempotent.", m.as_str())];
            }
        }
        Vec::new()
    }
}

// REL-RACE-001
struct ReadModifyWriteLockingRule;
impl Rule for ReadModifyWriteLockingRule {
    fn id(&self) -> &'static str { "REL-RACE-001" }
    fn name(&self) -> &'static str { "Read-Modify-Write Without Lock" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelRaceCondition) }
    fn impact(&self) -> &'static str { "Read-modify-write without locks causes lost updates." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("SELECT") && upper.contains("UPDATE") && !upper.contains("FOR UPDATE") && !upper.contains("SERIALIZABLE") {
            vec![self.build_issue(query, "Read-modify-write pattern without FOR UPDATE or SERIALIZABLE - race condition risk.", &query.raw[..query.raw.len().min(100)])]
        } else { Vec::new() }
    }
}

// REL-RACE-002
struct TOCTOUPatternRule;
static PAT_TOCTOU: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bIF\s+(NOT\s+)?EXISTS\s*\(\s*SELECT[^)]+\)[^;]*\b(INSERT|UPDATE|DELETE)\b").unwrap());
impl Rule for TOCTOUPatternRule {
    fn id(&self) -> &'static str { "REL-RACE-002" }
    fn name(&self) -> &'static str { "TOCTOU Pattern" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelRaceCondition) }
    fn impact(&self) -> &'static str { "TOCTOU vulnerabilities allow race conditions between check and action." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TOCTOU.find(&query.raw).map(|_| vec![self.build_issue(query, "Potential TOCTOU race condition: IF EXISTS check followed by modification.", &query.raw[..query.raw.len().min(80)])]).unwrap_or_default()
    }
}

// REL-FK-001
struct OrphanRecordRiskRule;
static FK_COLS: &[&str] = &["user_id","customer_id","order_id","product_id","account_id","parent_id","category_id","department_id","company_id","tenant_id","created_by","updated_by","owner_id","assigned_to","manager_id"];
impl Rule for OrphanRecordRiskRule {
    fn id(&self) -> &'static str { "REL-FK-001" }
    fn name(&self) -> &'static str { "Orphan Record Risk" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelForeignKey) }
    fn impact(&self) -> &'static str { "INSERTs without FK verification create orphan records." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_insert() { return Vec::new(); }
        let raw_lower = query.raw_lower().to_string();
        let has_fk = FK_COLS.iter().any(|c| raw_lower.contains(c));
        if !has_fk { return Vec::new(); }
        let has_check = ["foreign key","references","exists","join"].iter().any(|k| raw_lower.contains(k));
        if has_check { return Vec::new(); }
        vec![self.build_issue(query, "INSERT with foreign key columns without existence verification - orphan record risk.", &query.raw[..query.raw.len().min(100)])]
    }
}

// REL-FK-002
struct CascadeDeleteRiskRule;
static PAT_CASCADE_DEL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bDELETE\s+FROM\s+(users|customers|accounts|orders|products|categories|departments|companies|tenants|organizations)\b").unwrap());
impl Rule for CascadeDeleteRiskRule {
    fn id(&self) -> &'static str { "REL-FK-002" }
    fn name(&self) -> &'static str { "Cascade Delete Risk" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelForeignKey) }
    fn impact(&self) -> &'static str { "DELETE on parent table with ON DELETE CASCADE can wipe millions of child records." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CASCADE_DEL.find(&query.raw).map(|m| vec![self.build_issue(query, "Potential mass delete on parent table.", m.as_str())]).unwrap_or_default()
    }
}

// REL-DEAD-001
struct DeadlockPatternRule;
static PAT_DEADLOCK: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)\bBEGIN\b[\s\S]*?\bUPDATE\s+(\w+)\b[\s\S]*?\bUPDATE\s+(\w+)\b[\s\S]*?\bCOMMIT\b").unwrap());
impl Rule for DeadlockPatternRule {
    fn id(&self) -> &'static str { "REL-DEAD-001" }
    fn name(&self) -> &'static str { "Deadlock Pattern" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDeadlock) }
    fn impact(&self) -> &'static str { "Deadlocks occur when transactions lock tables in different order." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(caps) = PAT_DEADLOCK.captures(&query.raw) {
            let t1 = caps.get(1).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
            let t2 = caps.get(2).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
            if t1 != t2 {
                return vec![self.build_issue(query, "Potential deadlock pattern: multiple table updates within a transaction.", &query.raw[..query.raw.len().min(80)])];
            }
        }
        Vec::new()
    }
}

// REL-DEAD-002
struct LockEscalationRiskRule;
impl Rule for LockEscalationRiskRule {
    fn id(&self) -> &'static str { "REL-DEAD-002" }
    fn name(&self) -> &'static str { "Lock Escalation Risk" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelDeadlock) }
    fn impact(&self) -> &'static str { "Wide UPDATE/DELETE statements lock the entire table, blocking all other operations." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("WHERE") { return vec![self.build_issue(query, &format!("{} without WHERE clause - will lock entire table.", qt), &query.raw[..query.raw.len().min(100)])]; }
        Vec::new()
    }
}

// REL-TIMEOUT-001
struct LongRunningQueryRiskRule;
impl Rule for LongRunningQueryRiskRule {
    fn id(&self) -> &'static str { "REL-TIMEOUT-001" }
    fn name(&self) -> &'static str { "Long-Running Query Risk" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelTimeout) }
    fn impact(&self) -> &'static str { "Complex queries without bounds can run for hours." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() { return Vec::new(); }
        let upper = query.raw_upper();
        let join_count = upper.matches("JOIN").count();
        let sub_count = upper.matches("(SELECT").count();
        if join_count + sub_count >= 3 && !upper.contains("LIMIT") && !upper.contains("TOP ") {
            let msg = format!("Complex query ({} JOINs, {} subqueries) without row limit or timeout.", join_count, sub_count);
            return vec![self.build_issue(query, &msg, &query.raw[..query.raw.len().min(100)])];
        }
        Vec::new()
    }
}

// REL-STALE-001
struct StaleReadRiskRule;
static PAT_STALE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)(INSERT|UPDATE)\s+[^;]+;\s*SELECT\s+[^;]+FROM\s+(\w+)").unwrap());
impl Rule for StaleReadRiskRule {
    fn id(&self) -> &'static str { "REL-STALE-001" }
    fn name(&self) -> &'static str { "Stale Read Risk" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelConsistency) }
    fn impact(&self) -> &'static str { "In replicated databases, writes go to primary, reads may hit replicas." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains("BEGIN") { return Vec::new(); }
        PAT_STALE.find(&query.raw).map(|_| vec![self.build_issue(query, "Potential stale read: SELECT immediately follows UPDATE/INSERT without transaction.", &query.raw[..query.raw.len().min(80)])]).unwrap_or_default()
    }
}

// REL-RETRY-001
struct MissingRetryLogicRule;
static PAT_RETRY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)\bBEGIN\s+(TRAN|TRANSACTION)\b[\s\S]*?\b(COMMIT|ROLLBACK)\b").unwrap());
impl Rule for MissingRetryLogicRule {
    fn id(&self) -> &'static str { "REL-RETRY-001" }
    fn name(&self) -> &'static str { "Missing Retry Logic" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Reliability }
    fn category(&self) -> Option<Category> { Some(Category::RelRetry) }
    fn impact(&self) -> &'static str { "Without retry logic, operations fail permanently on transient errors." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(_) = PAT_RETRY.find(&query.raw) {
            let upper = query.raw_upper();
            let has_retry = ["TRY","CATCH","EXCEPTION","RETRY","ATTEMPT","LOOP","WHILE"].iter().any(|k| upper.contains(k));
            if !has_retry { return vec![self.build_issue(query, "Transaction block without retry logic - will fail on transient errors.", &query.raw[..query.raw.len().min(80)])]; }
        }
        Vec::new()
    }
}

// --- Dialect-specific reliability rules ---

// REL-MYSQL-001
struct InsertIgnoreRule;
static PAT_IGNORE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bINSERT\s+IGNORE\b").unwrap());
impl Rule for InsertIgnoreRule { fn id(&self) -> &'static str { "REL-MYSQL-001" } fn name(&self) -> &'static str { "INSERT IGNORE Silences Errors" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) } fn impact(&self) -> &'static str { "INSERT IGNORE silently discards duplicate key errors and constraint violations." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_IGNORE.find(&query.raw).map(|m| vec![self.build_issue(query, "INSERT IGNORE detected - errors silently suppressed.", m.as_str())]).unwrap_or_default() } }

// REL-MYSQL-002
struct ReplaceIntoRule;
static PAT_REPLACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bREPLACE\s+INTO\b").unwrap());
impl Rule for ReplaceIntoRule { fn id(&self) -> &'static str { "REL-MYSQL-002" } fn name(&self) -> &'static str { "REPLACE INTO Deletes and Reinserts" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) } fn impact(&self) -> &'static str { "REPLACE INTO deletes existing row and inserts a new one, breaking foreign keys." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_REPLACE.find(&query.raw).map(|m| vec![self.build_issue(query, "REPLACE INTO detected - silently deletes and reinserts rows.", m.as_str())]).unwrap_or_default() } }

// REL-MYSQL-003
struct Utf8InsteadOfUtf8mb4Rule;
static PAT_UTF8: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:CHARACTER\s+SET|CHARSET|DEFAULT\s+CHARSET)\s*=?\s*utf8\b").unwrap());
impl Rule for Utf8InsteadOfUtf8mb4Rule { fn id(&self) -> &'static str { "REL-MYSQL-003" } fn name(&self) -> &'static str { "MySQL utf8 Instead of utf8mb4" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) } fn impact(&self) -> &'static str { "4-byte Unicode characters will be silently truncated or rejected." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } if let Some(m) = PAT_UTF8.find(&query.raw) {
            // Exclude utf8mb4 matches
            let end = m.end();
            let rest = &query.raw[end..];
            if rest.starts_with("mb4") { return Vec::new(); }
            return vec![self.build_issue(query, "MySQL utf8 (3-byte) charset detected - use utf8mb4.", m.as_str())];
        }
        Vec::new() } }

// REL-MYSQL-004
struct OnUpdateCascadeTimestampRule;
static PAT_CASCADE_TS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bON\s+UPDATE\s+CASCADE\b").unwrap());
impl Rule for OnUpdateCascadeTimestampRule { fn id(&self) -> &'static str { "REL-MYSQL-004" } fn name(&self) -> &'static str { "ON UPDATE CASCADE With Timestamp Column" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelForeignKey) } fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) } fn impact(&self) -> &'static str { "Timestamp auto-update on parent row triggers CASCADE to all children." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_CASCADE_TS.find(&query.raw).map(|m| vec![self.build_issue(query, "ON UPDATE CASCADE detected - verify no timestamp auto-update triggers exist.", m.as_str())]).unwrap_or_default() } }

// REL-MYSQL-005
struct MysqlMyisamEngineRule;
static PAT_MYISAM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bENGINE\s*=\s*MyISAM\b").unwrap());
impl Rule for MysqlMyisamEngineRule { fn id(&self) -> &'static str { "REL-MYSQL-005" } fn name(&self) -> &'static str { "MyISAM Engine Usage" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql"]) } fn impact(&self) -> &'static str { "MyISAM does not support transactions, crash recovery, or foreign keys." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_MYISAM.find(&query.raw).map(|m| vec![self.build_issue(query, "MyISAM engine detected - no crash recovery or transactions.", m.as_str())]).unwrap_or_default() } }

// REL-TSQL-001
struct AtAtIdentityRule;
static PAT_IDENTITY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)@@IDENTITY\b").unwrap());
impl Rule for AtAtIdentityRule { fn id(&self) -> &'static str { "REL-TSQL-001" } fn name(&self) -> &'static str { "@@IDENTITY Instead of SCOPE_IDENTITY()" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) } fn impact(&self) -> &'static str { "@@IDENTITY may return wrong value due to triggers." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_IDENTITY.find(&query.raw).map(|m| vec![self.build_issue(query, "@@IDENTITY used - may return wrong value due to triggers.", m.as_str())]).unwrap_or_default() } }

// REL-TSQL-002
struct MergeWithoutHoldlockRule;
impl Rule for MergeWithoutHoldlockRule { fn id(&self) -> &'static str { "REL-TSQL-002" } fn name(&self) -> &'static str { "MERGE Without HOLDLOCK" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelRaceCondition) } fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) } fn impact(&self) -> &'static str { "Concurrent MERGE can cause duplicate key errors or lost updates." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("MERGE") { return Vec::new(); } if upper.contains("HOLDLOCK") || upper.contains("SERIALIZABLE") { return Vec::new(); } vec![self.build_issue(query, "MERGE without HOLDLOCK - concurrent execution may cause race conditions.", &query.raw[..query.raw.len().min(80)])] } }

// REL-TSQL-003
struct TruncateInTryWithoutCatchRule;
impl Rule for TruncateInTryWithoutCatchRule { fn id(&self) -> &'static str { "REL-TSQL-003" } fn name(&self) -> &'static str { "TRUNCATE in TRY Without CATCH" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) } fn impact(&self) -> &'static str { "If TRUNCATE fails, the error is not caught." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("TRUNCATE") || !upper.contains("BEGIN TRY") { return Vec::new(); } if upper.contains("BEGIN CATCH") { return Vec::new(); } vec![self.build_issue(query, "TRUNCATE inside BEGIN TRY without BEGIN CATCH - errors will be silently swallowed.", &query.raw[..query.raw.len().min(80)])] } }

// REL-PG-001
struct AlterTableAddColumnVolatileDefaultRule;
impl Rule for AlterTableAddColumnVolatileDefaultRule { fn id(&self) -> &'static str { "REL-PG-001" } fn name(&self) -> &'static str { "ALTER TABLE ADD COLUMN With Volatile DEFAULT" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) } fn impact(&self) -> &'static str { "A table rewrite on a large table locks it exclusively." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("ALTER TABLE") || !upper.contains("ADD") || !upper.contains("DEFAULT") { return Vec::new(); } for func in &["NOW()","CURRENT_TIMESTAMP","RANDOM()","GEN_RANDOM_UUID()","CLOCK_TIMESTAMP()"] { if upper.contains(func) { return vec![self.build_issue(query, "ALTER TABLE ADD COLUMN with volatile DEFAULT - may rewrite entire table.", &query.raw[..query.raw.len().min(100)])]; } } Vec::new() } }

// REL-PG-002
struct CreateIndexWithoutConcurrentlyRule;
static PAT_CREATE_IDX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+\w+").unwrap());
impl Rule for CreateIndexWithoutConcurrentlyRule { fn id(&self) -> &'static str { "REL-PG-002" } fn name(&self) -> &'static str { "CREATE INDEX Without CONCURRENTLY" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) } fn impact(&self) -> &'static str { "On large tables, CREATE INDEX can lock writes for minutes." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } if let Some(m) = PAT_CREATE_IDX.find(&query.raw) {
            if query.raw_upper().contains("CONCURRENTLY") { return Vec::new(); }
            return vec![self.build_issue(query, "CREATE INDEX without CONCURRENTLY - will lock table against writes.", m.as_str())];
        }
        Vec::new() } }

// REL-ORA-001
struct ConnectByWithoutNocycleRule;
impl Rule for ConnectByWithoutNocycleRule { fn id(&self) -> &'static str { "REL-ORA-001" } fn name(&self) -> &'static str { "CONNECT BY Without NOCYCLE" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelTimeout) } fn dialects(&self) -> DialectSet { DialectSet::new(&["oracle"]) } fn impact(&self) -> &'static str { "A cyclic reference causes CONNECT BY to loop indefinitely." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("CONNECT BY") { return Vec::new(); } if upper.contains("NOCYCLE") { return Vec::new(); } vec![self.build_issue(query, "CONNECT BY without NOCYCLE - cyclic data will cause infinite loop.", &query.raw[..query.raw.len().min(80)])] } }

// REL-ORA-002
struct OracleAlterTableMoveWithoutRebuildRule;
impl Rule for OracleAlterTableMoveWithoutRebuildRule { fn id(&self) -> &'static str { "REL-ORA-002" } fn name(&self) -> &'static str { "ALTER TABLE MOVE Without REBUILD INDEX" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["oracle"]) } fn impact(&self) -> &'static str { "After MOVE, all indexes become UNUSABLE." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("ALTER TABLE") || !upper.contains("MOVE") { return Vec::new(); } if upper.contains("REBUILD") { return Vec::new(); } vec![self.build_issue(query, "ALTER TABLE MOVE without REBUILD INDEX - all indexes become UNUSABLE.", &query.raw[..query.raw.len().min(80)])] } }

// REL-ORA-003
struct OracleAutonomousTransactionRule;
static PAT_AUTONOMOUS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b").unwrap());
impl Rule for OracleAutonomousTransactionRule { fn id(&self) -> &'static str { "REL-ORA-003" } fn name(&self) -> &'static str { "PRAGMA AUTONOMOUS_TRANSACTION" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelTransaction) } fn dialects(&self) -> DialectSet { DialectSet::new(&["oracle"]) } fn impact(&self) -> &'static str { "Commits in autonomous transaction persist even if parent rolls back." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_AUTONOMOUS.find(&query.raw).map(|m| vec![self.build_issue(query, "AUTONOMOUS_TRANSACTION detected - commits persist even if parent rolls back.", m.as_str())]).unwrap_or_default() } }

// REL-BQ-001
struct BigQueryDmlWithoutWhereOnPartitionedRule;
impl Rule for BigQueryDmlWithoutWhereOnPartitionedRule { fn id(&self) -> &'static str { "REL-BQ-001" } fn name(&self) -> &'static str { "DML Without WHERE on BigQuery" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["bigquery"]) } fn impact(&self) -> &'static str { "DML on all partitions is expensive. BigQuery does not support ROLLBACK." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let qt = query.query_type.as_deref().unwrap_or(""); if qt != "UPDATE" && qt != "DELETE" { return Vec::new(); } if query.raw_upper().contains("WHERE") { return Vec::new(); } vec![self.build_issue(query, "DML without WHERE on BigQuery - will process all partitions.", &query.raw[..query.raw.len().min(80)])] } }

// REL-CH-001
struct ClickHouseSelectWithoutFinalRule;
impl Rule for ClickHouseSelectWithoutFinalRule { fn id(&self) -> &'static str { "REL-CH-001" } fn name(&self) -> &'static str { "SELECT Without FINAL on ReplacingMergeTree" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["clickhouse"]) } fn impact(&self) -> &'static str { "Queries return duplicate rows that should have been deduplicated." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } if !query.is_select() { return Vec::new(); } let upper = query.raw_upper(); if upper.contains("FINAL") { return Vec::new(); } if upper.contains("REPLACING") || upper.contains("COLLAPSING") { return vec![self.build_issue(query, "SELECT without FINAL on ReplacingMergeTree - may return unmerged duplicates.", &query.raw[..query.raw.len().min(80)])]; } Vec::new() } }

// REL-PRESTO-001
struct PrestoInsertOverwriteWithoutPartitionRule;
impl Rule for PrestoInsertOverwriteWithoutPartitionRule { fn id(&self) -> &'static str { "REL-PRESTO-001" } fn name(&self) -> &'static str { "INSERT OVERWRITE Without Partition" } fn severity(&self) -> Severity { Severity::Critical } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["presto","trino"]) } fn impact(&self) -> &'static str { "All existing data in the table is replaced." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("INSERT OVERWRITE") { return Vec::new(); } if upper.contains("PARTITION") { return Vec::new(); } vec![self.build_issue(query, "INSERT OVERWRITE without PARTITION - will replace ALL data in target table.", &query.raw[..query.raw.len().min(80)])] } }

// REL-RS-001
struct CopyWithoutManifestRule;
static PAT_RS_COPY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCOPY\b.*\bFROM\b.*\bs3://").unwrap());
impl Rule for CopyWithoutManifestRule { fn id(&self) -> &'static str { "REL-RS-001" } fn name(&self) -> &'static str { "COPY Without MANIFEST" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["redshift"]) } fn impact(&self) -> &'static str { "Without MANIFEST, any file matching the S3 prefix is loaded." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } if let Some(m) = PAT_RS_COPY.find(&query.raw) { if !query.raw_upper().contains("MANIFEST") { return vec![self.build_issue(query, "COPY from S3 without MANIFEST - may load unexpected files.", m.as_str())]; } } Vec::new() } }

// REL-SPARK-001
struct SparkOverwriteWithoutPartitionRule;
impl Rule for SparkOverwriteWithoutPartitionRule { fn id(&self) -> &'static str { "REL-SPARK-001" } fn name(&self) -> &'static str { "INSERT OVERWRITE Without Partition" } fn severity(&self) -> Severity { Severity::Critical } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["spark","databricks"]) } fn impact(&self) -> &'static str { "All existing data in the table is replaced." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("INSERT OVERWRITE") { return Vec::new(); } if upper.contains("PARTITION") { return Vec::new(); } vec![self.build_issue(query, "INSERT OVERWRITE without PARTITION - will replace ALL data.", &query.raw[..query.raw.len().min(80)])] } }

// REL-SQLITE-001
struct SqliteDropColumnRule;
static PAT_SQLITE_DROP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\b").unwrap());
impl Rule for SqliteDropColumnRule { fn id(&self) -> &'static str { "REL-SQLITE-001" } fn name(&self) -> &'static str { "ALTER TABLE DROP COLUMN (SQLite Limitation)" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) } fn dialects(&self) -> DialectSet { DialectSet::new(&["sqlite"]) } fn impact(&self) -> &'static str { "ALTER TABLE DROP COLUMN has limited support in SQLite (3.35+)." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_SQLITE_DROP.find(&query.raw).map(|m| vec![self.build_issue(query, "ALTER TABLE DROP COLUMN - limited SQLite support (3.35+).", m.as_str())]).unwrap_or_default() } }

// REL-SQLITE-002
struct SqliteForeignKeysOffRule;
static PAT_SQLITE_FK: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bPRAGMA\s+foreign_keys\s*=\s*(?:OFF|0|false)\b").unwrap());
impl Rule for SqliteForeignKeysOffRule { fn id(&self) -> &'static str { "REL-SQLITE-002" } fn name(&self) -> &'static str { "PRAGMA foreign_keys = OFF" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Reliability } fn category(&self) -> Option<Category> { Some(Category::RelForeignKey) } fn dialects(&self) -> DialectSet { DialectSet::new(&["sqlite"]) } fn impact(&self) -> &'static str { "Without foreign key enforcement, INSERT and DELETE can create orphan records." } fn check(&self, query: &Query) -> Vec<Issue> { if !self.dialect_matches(query) { return Vec::new(); } PAT_SQLITE_FK.find(&query.raw).map(|m| vec![self.build_issue(query, "PRAGMA foreign_keys = OFF - referential integrity disabled.", m.as_str())]).unwrap_or_default() } }

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnsafeWriteRule), Box::new(TruncateWithoutTransactionRule),
        Box::new(AlterTableDestructiveRule), Box::new(DropTableRule),
        Box::new(MissingRollbackRule), Box::new(AutocommitDisabledRule), Box::new(EmptyTransactionRule),
        Box::new(ExceptionSwallowedRule), Box::new(LongTransactionWithoutSavepointRule),
        Box::new(NonIdempotentInsertRule), Box::new(NonIdempotentUpdateRule),
        Box::new(ReadModifyWriteLockingRule), Box::new(TOCTOUPatternRule),
        Box::new(OrphanRecordRiskRule), Box::new(CascadeDeleteRiskRule),
        Box::new(DeadlockPatternRule), Box::new(LockEscalationRiskRule),
        Box::new(LongRunningQueryRiskRule), Box::new(StaleReadRiskRule), Box::new(MissingRetryLogicRule),
        Box::new(InsertIgnoreRule), Box::new(ReplaceIntoRule), Box::new(Utf8InsteadOfUtf8mb4Rule),
        Box::new(OnUpdateCascadeTimestampRule), Box::new(MysqlMyisamEngineRule),
        Box::new(AtAtIdentityRule), Box::new(MergeWithoutHoldlockRule), Box::new(TruncateInTryWithoutCatchRule),
        Box::new(AlterTableAddColumnVolatileDefaultRule), Box::new(CreateIndexWithoutConcurrentlyRule),
        Box::new(ConnectByWithoutNocycleRule), Box::new(OracleAlterTableMoveWithoutRebuildRule), Box::new(OracleAutonomousTransactionRule),
        Box::new(BigQueryDmlWithoutWhereOnPartitionedRule), Box::new(ClickHouseSelectWithoutFinalRule),
        Box::new(PrestoInsertOverwriteWithoutPartitionRule), Box::new(CopyWithoutManifestRule),
        Box::new(SparkOverwriteWithoutPartitionRule),
        Box::new(SqliteDropColumnRule), Box::new(SqliteForeignKeysOffRule),
    ]
}
