# Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the project root.
EOF

cat > docs/development/adding-rules.md << 'EOF'
# Adding Rules

## Rule Trait

Every rule implements the `Rule` trait defined in `src/rules/base.rs`:

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn dimension(&self) -> Dimension;

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Proven  // default
    }

    fn check(&self, query: &Query) -> Vec<Issue>;
}
```

## Confidence Guidelines

Choose the right confidence level:

- **Proven**: The pattern is always wrong regardless of context. Example: `WHERE x = NULL`.
- **Contextual**: The pattern is usually wrong but has legitimate uses. Example: `CREATE USER without password` (valid for Unix socket auth).
- **Advisory**: The pattern is a style preference. Example: `INSERT without column list`.

## File Organization
Rules are organized by dimension:
``` text
src/rules/
  security/        # SEC-* rules
  performance/     # PERF-* rules
  reliability/     # REL-* rules
  quality/         # QUAL-* rules
  cost/            # COST-* rules
  compliance/      # COMP-* rules
  migration/       # MIG-* rules
  schema/          # SCHEMA-* rules
```

## Example Rule
``` Rust
struct MyRule;
static PAT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bDANGEROUS_PATTERN\b").unwrap());

impl Rule for MyRule {
    fn id(&self) -> &'static str { "SEC-CUSTOM-001" }
    fn name(&self) -> &'static str { "Dangerous Pattern Detected" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Proven
    }

    fn impact(&self) -> &'static str {
        "This pattern can lead to data exposure."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT.find(&query.raw)
            .map(|m| vec![self.build_issue(query, "Dangerous pattern found", m.as_str())])
            .unwrap_or_default()
    }
}
```

## Register thre Rule
Add it to the `rules()` function in the appropriate module:
``` Rust
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(MyRule),
        // ... other rules
    ]
}
```

## Testing
Every rule must have tests:
``` Rust
#[test]
fn my_rule_fires() {
    let query = q("SELECT DANGEROUS_PATTERN FROM t", "postgresql", "SELECT");
    let rule = MyRule;
    assert!(!rule.check(&query).is_empty());
}

#[test]
fn my_rule_does_not_fire_on_safe_sql() {
    let query = q("SELECT id FROM users WHERE id = 1", "postgresql", "SELECT");
    let rule = MyRule;
    assert!(rule.check(&query).is_empty());
}
```

## String Slicing
Never use raw byte slicing on query text:
``` Rust
// WRONG: panics on multibyte UTF-8
let snip = &query.raw[..80];

// CORRECT: respects character boundaries
let snip = query.snippet(80);
```

## Custom YAML Rules
Users can define rules without mpdifying source code:
``` YAML
rules:
  - id: ORG-001
    name: "Require tenant_id filter"
    severity: high
    dimension: security
    pattern: "SELECT.*FROM\\s+orders\\b(?!.*tenant_id)"
    message: "All queries on orders table must filter by tenant_id"
```