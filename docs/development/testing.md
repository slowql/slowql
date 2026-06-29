# Testing

## Runing Tests
``` Bash
# Full test suite (625 tests)
cargo test

# Library tests only (fastest)
cargo test --lib

# Specific test
cargo test --lib extract_helpers

# Specific integration test file
cargo test --test adversarial_edge_cases

# Specific test in integration file
cargo test --test quality_all_rules style_005
```

## Test Organization
``` text
tests/
  adversarial_edge_cases.rs    # 80 edge case scenarios
  cli_end_to_end.rs            # CLI integration tests
  compliance_all_rules.rs      # Compliance rule coverage
  cost_all_rules.rs            # Cost rule coverage
  coverage_branches.rs         # Branch coverage tests
  coverage_models.rs           # Model coverage tests
  infrastructure_features.rs   # Infrastructure feature tests
  models_smoke.rs              # Model smoke tests
  performance_all_rules.rs     # Performance rule coverage
  quality_all_rules.rs         # Quality rule coverage
  reliability_all_rules.rs     # Reliability rule coverage
  schema_migration_rules.rs    # Schema/migration rule tests
  security_all_rules.rs        # Security rule coverage
  security_injection_rules.rs  # Injection rule tests
  trigger_corpus.rs            # Real-world trigger patterns
```

## Hardening Corpus
SlowQL is validated against 28 open-source repositories. To run the corpus:
``` Bash
# Clone repos
cd /tmp && mkdir -p slowql-repos && cd slowql-repos
for repo in django/django rails/rails prisma/prisma-engines supabase/supabase; do
  git clone --depth 1 https://github.com/$repo.git
done

# Scan each
for repo in */; do
  slowql "$repo" --format json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'${repo}: issues={len(data.get(\"issues\",[]))}')
"
done
```
Expected: zero issues in proven mode for all repos.



