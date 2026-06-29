# Adding Rules

Rules are implemented as Rust structs in `src/rules/`. Each rule implements the `Rule` trait from `src/rules/base.rs`.

## File Organization

``` text
src/rules/
security/ # SEC-* rules
performance/ # PERF-* rules
reliability/ # REL-* rules
quality/ # QUAL-* rules
cost/ # COST-* rules
compliance/ # COMP-* rules
migration/ # MIG-* rules
schema/ # SCHEMA-* rules
```

## Rule Trait

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn dimension(&self) -> Dimension;

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Proven  // override when needed
    }

    fn dialects(&self) -> DialectSet {
        DialectSet::universal()  // override for dialect-specific rules
    }

    fn impact(&self) -> &'static str { "" }
    fn fix_guidance(&self) -> Option<&'static str> { None }
    fn category(&self) -> Option<Category> { None }

    fn check(&self, query: &Query) -> Vec<Issue>;
}
```

## Minimal Rule Example

``` Rust
struct DeleteWithoutWhereRule;

impl Rule for DeleteWithoutWhereRule {
    fn id(&self) -> &'static str { "REL-DATA-001" }
    fn name(&self) -> &'static str { "Catastrophic Data Loss Risk" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn dimension(&self) -> Dimension { Dimension::Reliability }

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
        let msg = format!("CRITICAL: {} statement has no WHERE clause.", qt);
        vec![self.build_issue(query, &msg, query.snippet(80))]
    }
}
```

## Confidence Guidelines

| **Confidence** | **When to use** |
| ---------- | ---------- |
| **Proven** | Pattern is always wrong. Zero false positives. Example: WHERE x = NULL. |
| **Contextual** | Usually wrong but has legitimate uses. Example: CREATE USER without password (valid for Unix socket auth). |
| **Advisory** | Style preference or best practice. Example: INSERT without column list. |

## Dialect-Specific Rules

``` Rust
fn dialects(&self) -> DialectSet {
    DialectSet::new(&["postgresql"])
}
```
The engine skips rules that do not match the query's dialect.

## Register the Rule

Add it to the `rules()` function in the appropriate module:
``` Rust
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DeleteWithoutWhereRule),
        // ... existing rules
    ]
}
```

## String Slicing
Always use `query.snippet(N)` for snippets. Never use raw byte slicing:
``` Rust
// WRONG: panics on multibyte UTF-8
let snip = &query.raw[..80];

// CORRECT: respects UTF-8 character boundaries
let snip = query.snippet(80);
```

## Testing

Every rule must have tests in the same file or in `tests/`:
``` Rust
#[cfg(test)]
mod tests {
    use super::*;

    fn q(sql: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_delete_without_where() {
        let rule = DeleteWithoutWhereRule;
        let issues = rule.check(&q("DELETE FROM users", "DELETE"));
        assert!(!issues.is_empty());
    }

    #[test]
    fn no_fire_on_delete_with_where() {
        let rule = DeleteWithoutWhereRule;
        let issues = rule.check(&q("DELETE FROM users WHERE id = 1", "DELETE"));
        assert!(issues.is_empty());
    }
}
```

## Cusom YAML Rules

Users can define rules without modifying source code:
``` YAML
rules:
  - id: ORG-001
    name: "Require tenant_id filter"
    severity: high
    dimension: security
    pattern: "SELECT.*FROM\\s+orders\\b(?!.*tenant_id)"
    message: "All queries on orders table must filter by tenant_id"
```

Load via config:
``` YAML
analysis:
  custom_rules: .slowql-rules.yaml
```
