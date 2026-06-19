# Contributing to SlowQL

Thank you for your interest in contributing to SlowQL!

## Quick Start

```bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo build
cargo test
```

## Development
``` Bash
# Build release binary
cargo build --release

# Run tests
cargo test

# Run against a file
./target/release/slowql path/to/queries.sql

# Run against a directory
./target/release/slowql src/

# Run in proven mode (zero false positives)
./target/release/slowql --min-confidence proven src/
```

## Adding Rules
Rules are defined in `src/rules/`. Each rule implements the `Rule` trait:
``` Rust
 impl Rule for MyRule {
    fn id(&self) -> &'static str { "CUSTOM-001" }
    fn name(&self) -> &'static str { "My Custom Rule" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Proven }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // rule logic here
    }
}
```
Every rule must have:
- A unique ID following the naming convention (DIM-CAT-NNN)
- A confidence classification (Proven, Contextual, or Advisory)
- Test in `tests`

## Testing
``` Bash
# Run all tests
cargo test

# Run specific test file
cargo test --test adversarial_edge_cases

# Run with output
cargo test -- --nocapture
```

## Code Quality
``` Bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings
```

We look forward to your contibutions!
