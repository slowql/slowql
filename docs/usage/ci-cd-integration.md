# CI/CD Integration

SlowQL is designed for headless CI/CD environments. It outputs machine-readable formats, returns meaningful exit codes, and runs fast enough to use on every commit.

## GitHub Actions

```yaml
name: SQL Analysis

on: [push, pull_request]

jobs:
  slowql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SlowQL
        run: cargo install --git https://github.com/slowql/slowql.git

      - name: Run SlowQL
        run: slowql src/ --fail-on high --format github-actions

      - name: Export SARIF
        if: always()
        run: slowql src/ --export sarif --out results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/slowql_report.sarif
```

### With Schema Validation

``` Yaml
      - name: Run SlowQL with Schema
        run: slowql src/ --schema db/schema.sql --fail-on high --format github-actions
```

### Only Changed Files

``` Yaml
      - name: Run SlowQL on Changed Files
        run: slowql . --git-diff --fail-on high --format github-actions
```

## GitLab CI

``` Yaml
slowql:
  image: rust:latest
  stage: lint
  before_script:
    - cargo install --git https://github.com/slowql/slowql.git
  script:
    - slowql src/ --fail-on high --format console
  artifacts:
    when: always
    paths:
      - reports/
```

## Bitbucket Pipelines

``` Yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: SQL Analysis
          image: rust:latest
          script:
            - cargo install --git https://github.com/slowql/slowql.git
            - slowql src/ --fail-on high
```

## Jenkins

``` groovy
pipeline {
    agent any
    stages {
        stage('SQL Analysis') {
            steps {
                sh '''
                    cargo install --git https://github.com/slowql/slowql.git
                    slowql src/ --fail-on high --format console
                '''
            }
        }
    }
}
```

## Docker

``` Yaml
      - name: Run SlowQL
        run: |
          docker run --rm -v $(pwd):/src ghcr.io/slowql/slowql /src \
            --fail-on high --format github-actions
```

## Ecit Codes

| **Code** | **Meaning** | **CI Behavior** |
|------|---------|-------------|
| 0 | No issues found | Pass |
| 1 | Medium or low issues found | Pass (unless `--fail-on medium`) |
| 2 | High issues found | Fail (with `--fail-on high`) |
| 3 | Critical issues found | Fail (with `--fail-on critical`) |

## Recommended Settings

For most teams, start with:

``` Bash
slowql src/ --fail-on high
```
This blocks critical and high severity issues while letting medium and low pass without breaking builds. Tighten over time as the codebase improves.

## Output Formats by Use Case

| **Use case** | **Recommended format** |
|----------|-------------------|
| Human-readable terminal output | `console` (default) |
| GitHub PR annotations | `github-actions` |
| Security scanning tab | `sarif` (upload to GitHub) |
| Custom tooling | `json` |
| Audit trail | `--export html` or `--export csv` |


