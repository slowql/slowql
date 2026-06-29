# Contributing to SlowQL

Thank you for your interest in contributing to SlowQL.

## Quick Start

```bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo build
cargo test
```

## Development Workflow

``` Bash
# Build debug binary
cargo build

# Build release binary
cargo build --release

# Run all tests (625 tests)
cargo test

# Run specific test
cargo test --lib extract_helpers
cargo test --test adversarial_edge_cases

# Format code
cargo fmt --all

# Run against a file
./target/release/slowql path/to/queries.sql

# Run against a directory
./target/release/slowql src/

# Run in proven mode (default, zero false positives)
./target/release/slowql src/

# Run in contextual mode
./target/release/slowql src/ --min-confidence contextual

# Run in advisory mode (all findings including hints)
./target/release/slowql src/ --min-confidence advisory

# Install globally
cargo install --path .
```

## Project Structure
``` text
src/
  cli.rs              # Command-line interface and output formatting
  engine.rs           # Analysis orchestration
  parser.rs           # SQL parsing and statement splitting
  extractor.rs        # SQL extraction from application code
  context.rs          # File context classification
  config.rs           # Configuration loading
  project.rs          # Cross-file analysis (duplicates, breaking changes)
  compare.rs          # Query similarity detection
  query_analysis.rs   # Structural query facts (AST-level)
  schema.rs           # DDL schema parsing and validation
  scoring.rs          # Query complexity scoring
  suppressions.rs     # Inline suppression directives
  baseline.rs         # Baseline mode (diff against known issues)
  autofixer.rs        # Safe autofix engine
  cache.rs            # File-level caching
  git.rs              # Git integration
  jinja.rs            # Jinja template stripping
  mybatis.rs          # MyBatis XML parser
  yaml_rules.rs       # Custom YAML rule loader
  models/
    issue.rs          # Issue, Severity, Dimension, RuleConfidence
    query.rs          # Query model with cached upper/lower
    result.rs         # AnalysisResult and Statistics
  rules/
    base.rs           # Rule trait and RuleContext
    registry.rs       # Rule registry
    mod.rs            # Rule module exports
    security/         # 61 security rules
    performance/      # 73 performance rules
    reliability/      # 44 reliability rules
    quality/          # 52 quality rules
    cost/             # 33 cost rules
    compliance/       # 18 compliance rules
    migration/        # Migration-specific rules
    schema/           # Schema design rules
```

## Adding a Rule
Rules implement the `Rule` trait in `src/rules/base.rs`:
``` Rust
impl Rule for MyRule {
    fn id(&self) -> &'static str { "SEC-CUSTOM-001" }
    fn name(&self) -> &'static str { "My Custom Check" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }

    fn confidence(&self) -> RuleConfidence {
        // Proven: structurally deterministic, zero false positives
        // Contextual: accurate with context, may need review
        // Advisory: style hint, not provably wrong
        RuleConfidence::Proven
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        // Return issues found in the query
        Vec::new()
    }
}
```

### Confidence Guideline
- **Proven**: The pattern is always wrong regardless of context. Example: `WHERE x = NULL` (should be `IS NULL`).
- **Contextual**: The pattern is usually wrong but has legitimate uses. Example: `CREATE USER` without password (valid for Unix socket auth).
- **Advisory**: The pattern is a style preference or best practice. Example: `INSERT` without column list.

### Testing Rules
Every rule must have tests. Add them in the rule file or in `/tests/`:
``` Rust
#[test]
fn my_rule_fires_on_bad_pattern() {
    let query = q("SELECT * FROM users", "postgresql", "SELECT");
    let issues = MyRule.check(&query);
    assert!(!issues.is_empty());
}

#[test]
fn my_rule_does_not_fire_on_safe_pattern() {
    let query = q("SELECT id, name FROM users WHERE id = 1", "postgresql", "SELECT");
    let issues = MyRule.check(&query);
    assert!(issues.is_empty());
}
```

## Adding Context Patterns
Context patterns are in `src/context.rs`. Path patterns are matched in order. More specific patterns must come before general ones (e.g., `src/site/` before `src/`).

## Code Standard
- No nested loops over query collections (use HashMap/HashSet for O(1) lookups)
- All string slicing must use `query.snippet(N)` or validate character boundaries
- Every rule must have a `confidence()` method with a comment explaining the classification
- No guessing. Verify before claiming  

## Running the Hardening Corpus
``` Bash
# Clone test repos
cd /tmp
for repo in django rails prisma-engines supabase; do
  git clone --depth 1 https://github.com/$org/$repo.git
done

# Scan each repo
for repo in /tmp/slowql-repos/*/; do
  slowql "$repo" --format json
done
```

## License
By contributing to SlowQL, you agree that your contributions will be licensed under the AGPL-3.0 license.