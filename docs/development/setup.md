# Development Setup

## Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable, 1.75+)
- Git

## Clone and Build

```bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo build
```

## Run Tests
``` Bash
# Full test suite (625 tests)
cargo test

# Library tests only (faster)
cargo test --lib

# Specific test
cargo test --lib extract_helpers

# Specific integration test file
cargo test --test adversarial_edge_cases
```

## Format
``` Bash
cargo fmt --all
```

## Build Release Binary
``` Bash
cargo build --release
./target/release/slowql --version
```

## Install Locally
``` Bash
cargo install --path .
slowql --version
```

## Project Structure
``` text
src/
  cli.rs              # CLI and output formatting
  engine.rs           # Analysis orchestration
  parser.rs           # SQL parsing
  extractor.rs        # SQL extraction from app code
  context.rs          # File context classification
  config.rs           # Configuration
  project.rs          # Cross-file analysis
  models/             # Data models
  rules/              # Rule implementations
    security/
    performance/
    reliability/
    quality/
    cost/
    compliance/
    migration/
    schema/
tests/                # Integration tests
  adversarial_edge_cases.rs
  cli_end_to_end.rs
  security_all_rules.rs
  performance_all_rules.rs
  ... (16 test files total)
```

## Editor Configuration

### VS Code
Install the `rust-analyzer` extension for inline type hints and go-to-definition.
Recommended `settings.json`:
``` JSON
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "editor.formatOnSave": true,
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  }
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_BACKTRACE=1` | Enable full backtraces on panics |
| `RUST_LOG=debug` | Enable debug logging |