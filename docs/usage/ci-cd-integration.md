# CI/CD Integration

Deploying SlowQL natively into your CI/CD pipeline guarantees that dangerous query regressions, expensive table scans, and SQL injections are blocked before they ever hit your staging or production environments.

By leveraging SlowQL's default headless mode internally triggered when processing files in workflows, it conforms seamlessly to enterprise security checkpoints.

---

## 1. GitHub Actions (Recommended)

GitHub Actions offers the most streamlined integration by utilizing the `--format github-actions` flag. This outputs diagnostics using GitHub's native `::error file=...::` syntax, placing explicit squiggly lines and comments **directly on the changed code in your Pull Requests**.

Furthermore, exporting via `--export sarif` integrates into GitHub's Advanced Security tab securely.

```yaml
name: "SlowQL Enterprise Scan"

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main", "develop" ]

jobs:
  slowql-analysis:
    name: SQL Static Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      pull-requests: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install SlowQL
        run: pip install slowql

      - name: Run SlowQL Pipeline
        id: slowql_scan
        run: |
          # SlowQL auto-detects non-interactive mode natively when files are provided
          slowql \
            --fail-on high \
            --format github-actions \
            --export sarif \
            --out results/ \
            **/*.sql

      - name: Upload SARIF Security Results
        uses: github/codeql-action/upload-sarif@v3
        if: always() # Ensure SARIF uploads even if the pipeline fails
        with:
          sarif_file: results/slowql_report.sarif
          category: slowql-analyzer
```

---

## 2. GitLab CI

GitLab CI thrives on strict exit codes. SlowQL will intelligently throw an exit code `1` if the designated `--fail-on` threshold is breached, blocking the pipeline seamlessly.

```yaml
stages:
  - lint

slowql-enterprise-scan:
  image: python:3.11-slim
  stage: lint
  before_script:
    - pip install slowql
  script:
    - slowql --fail-on medium --format console **/*.sql
  artifacts:
    when: always
    paths:
      - slowql_report/
```

> [!TIP]
> If you wish to aggregate metrics, append `--export json --out slowql_report/` to retain a static footprint of the pipeline run.

---

## 3. Bitbucket Pipelines

Bitbucket pipelines utilize a lightweight docker ecosystem.

```yaml
image: python:3.11-slim

pipelines:
  pull-requests:
    '**':
      - step:
          name: SlowQL Architecture Validation
          script:
            - pip install slowql
            - slowql --fail-on high --format console source/**/*.sql
```

---

## 4. Jenkins Pipeline (Jenkinsfile)

For enterprise Jenkins orchestrators, simply encasing SlowQL within a standard shell sequence properly triggers build failures when High/Critical issues are encountered.

```groovy
pipeline {
    agent any

    stages {
        stage('Database Initialization') {
            steps {
                // Setup...
            }
        }
        
        stage('SQL Linting (SlowQL)') {
            steps {
                sh '''
                    # Ensure virtual environments or global spaces are activated
                    pip install slowql
                    
                    slowql \
                        --fail-on critical \
                        --dialect postgresql \
                        db/migrations/*.sql
                '''
            }
        }
    }
}
```

---

## Key Headless Considerations

When running in CI/CD, always ensure the following flags are present:
1. `--fail-on {severity}`: Dictates your strictness policy. We recommend starting with `--fail-on critical` for legacy repositories and tightening to `high` or `medium` over time.
2. `--dialect`: Supplying the dialect natively inside the pipeline command guarantees the Universal Parser isn't wasting processing time attempting to guess syntax configurations across thousands of migration files.
