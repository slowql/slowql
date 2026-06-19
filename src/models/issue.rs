
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    pub fn weight(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn color_code(self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[1;35m",
            Severity::High => "\x1b[1;31m",
            Severity::Medium => "\x1b[1;33m",
            Severity::Low => "\x1b[1;36m",
            Severity::Info => "\x1b[2m",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dimension {
    Security,
    Performance,
    Reliability,
    Compliance,
    Cost,
    Quality,
    Schema,
    Data,
    Migration,
    Operational,
    Business,
}

impl Dimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Security => "security",
            Dimension::Performance => "performance",
            Dimension::Reliability => "reliability",
            Dimension::Compliance => "compliance",
            Dimension::Cost => "cost",
            Dimension::Quality => "quality",
            Dimension::Schema => "schema",
            Dimension::Data => "data",
            Dimension::Migration => "migration",
            Dimension::Operational => "operational",
            Dimension::Business => "business",
        }
    }
}

impl fmt::Display for Dimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Dimension {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "security" => Ok(Dimension::Security),
            "performance" => Ok(Dimension::Performance),
            "reliability" => Ok(Dimension::Reliability),
            "compliance" => Ok(Dimension::Compliance),
            "cost" => Ok(Dimension::Cost),
            "quality" => Ok(Dimension::Quality),
            "schema" => Ok(Dimension::Schema),
            "data" => Ok(Dimension::Data),
            "migration" => Ok(Dimension::Migration),
            "operational" => Ok(Dimension::Operational),
            "business" => Ok(Dimension::Business),
            other => Err(format!("unknown dimension: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    // Security
    SecInjection,
    SecAuthentication,
    SecDataExposure,
    SecCrypto,
    SecAccess,
    SecAuthorization,
    SecLogging,
    SecSession,
    SecDos,
    // Performance
    PerfIndex,
    PerfScan,
    PerfJoin,
    PerfSubquery,
    PerfAggregation,
    PerfSort,
    PerfLock,
    PerfMemory,
    PerfCursor,
    PerfHints,
    PerfExecution,
    PerfBatch,
    PerfNetwork,
    // Reliability
    RelDataIntegrity,
    RelTransaction,
    RelErrorHandling,
    RelRecovery,
    RelIdempotency,
    RelRaceCondition,
    RelForeignKey,
    RelDeadlock,
    RelTimeout,
    RelConsistency,
    RelRetry,
    // Compliance
    CompGdpr,
    CompHipaa,
    CompPci,
    CompSox,
    CompSoc2,
    CompCcpa,
    // Cost
    CostCloud,
    CostStorage,
    CostCompute,
    CostIo,
    CostNetwork,
    CostPagination,
    CostIndexWaste,
    CostIndexOptimization,
    CostCrossDatabase,
    CostCrossRegion,
    CostDistributed,
    CostServerless,
    CostArchival,
    CostPartitioning,
    // Quality
    QualReadability,
    QualNaming,
    QualDry,
    QualModern,
    QualComplexity,
    QualDocumentation,
    QualSchemaDesign,
    QualTesting,
    QualTechDebt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixConfidence {
    Safe,
    Probable,
    Unsafe,
}

impl fmt::Display for FixConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixConfidence::Safe => write!(f, "safe"),
            FixConfidence::Probable => write!(f, "probable"),
            FixConfidence::Unsafe => write!(f, "unsafe"),
        }
    }
}

/// How certain we are that the issue is a true positive.
/// Proven: deterministic, structural, zero FP by design.
/// Contextual: accurate when context is available, may need schema/config.
/// Advisory: style/best-practice hint, not provable from SQL alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleConfidence {
    Advisory = 1,
    Contextual = 2,
    Proven = 3,
}

impl RuleConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleConfidence::Proven => "proven",
            RuleConfidence::Contextual => "contextual",
            RuleConfidence::Advisory => "advisory",
        }
    }
}

impl fmt::Display for RuleConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for RuleConfidence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "proven" => Ok(RuleConfidence::Proven),
            "contextual" => Ok(RuleConfidence::Contextual),
            "advisory" => Ok(RuleConfidence::Advisory),
            other => Err(format!("unknown confidence: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationMode {
    SafeApply,
    PreviewOnly,
    GuidanceOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub description: String,
    pub replacement: String,
    pub is_safe: bool,
    pub confidence: FixConfidence,
    pub original: String,
    pub rule_id: String,
    pub start: Option<usize>,
    pub end: Option<usize>,
}

impl Fix {
    pub fn guidance(description: impl Into<String>, rule_id: impl Into<String>) -> Self {
        Fix {
            description: description.into(),
            replacement: String::new(),
            is_safe: false,
            confidence: FixConfidence::Unsafe,
            original: String::new(),
            rule_id: rule_id.into(),
            start: None,
            end: None,
        }
    }

    pub fn safe(
        description: impl Into<String>,
        original: impl Into<String>,
        replacement: impl Into<String>,
        rule_id: impl Into<String>,
    ) -> Self {
        Fix {
            description: description.into(),
            replacement: replacement.into(),
            is_safe: true,
            confidence: FixConfidence::Safe,
            original: original.into(),
            rule_id: rule_id.into(),
            start: None,
            end: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub file: Option<String>,
    pub query_index: Option<usize>,
}

impl Location {
    pub fn new(line: u32, column: u32) -> Self {
        Location {
            line,
            column,
            end_line: None,
            end_column: None,
            file: None,
            query_index: None,
        }
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_query_index(mut self, index: usize) -> Self {
        self.query_index = Some(index);
        self
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}:{}:{}", file, self.line, self.column)
        } else {
            write!(f, "{}:{}", self.line, self.column)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub dimension: Dimension,
    pub category: Option<Category>,
    pub location: Location,
    pub snippet: String,
    pub fix: Option<Fix>,
    pub impact: Option<String>,
    pub documentation_url: Option<String>,
    pub confidence: RuleConfidence,
    pub source_context: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Issue {
    pub fn new(
        rule_id: impl Into<String>,
        message: impl Into<String>,
        severity: Severity,
        dimension: Dimension,
        location: Location,
        snippet: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        let doc_url = format!(
            "https://slowql.dev/rules/{}",
            rule_id.to_lowercase().replace('-', "-")
        );
        Issue {
            rule_id,
            message: message.into(),
            severity,
            dimension,
            category: None,
            location,
            snippet: snippet.into(),
            fix: None,
            impact: None,
            documentation_url: Some(doc_url),
            confidence: RuleConfidence::Proven,
            source_context: String::new(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = Some(impact.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}
