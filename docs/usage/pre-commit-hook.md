# Pre-commit Hook Integration

SlowQL can be seamlessly embedded into your local development workflow using the [`pre-commit`](https://pre-commit.com/) framework. By intercepting commits before they populate the Git ledger, you guarantee that malicious schemas, unprotected PII access paths, and syntactical bugs never execute natively.

---

## Basic Setup

Create or append slowly to `.pre-commit-config.yaml` located in the absolute root of your project repository.

```yaml
repos:
  - repo: https://github.com/makroumi/slowql
    rev: v1.6.0 # Highly recommended to pin to a specific release
    hooks:
      - id: slowql
```

Because `pre-commit` natively filters and passes only **modified files**, the CLI will execute blazingly fast against isolated query modifications without scanning your entire repository.

---

## Overriding Standard Arguments

You can explicitly pass SlowQL configurations using the `args` array. This completely bypasses the local `slowql.yaml` configuration if necessary.

```yaml
repos:
  - repo: https://github.com/makroumi/slowql
    rev: v1.6.0
    hooks:
      - id: slowql
        args: [
            "--dialect", "postgresql",
            "--fail-on", "high",
            "--fast"
        ]
```

> [!NOTE]
> Because `pre-commit` provides file paths automatically, SlowQL enters non-interactive mode by default, guaranteeing it will never hang your commit process by waiting for `STDIN`.

---

## 🛠️ The `--fix` Automation Limitation

SlowQL boasts a powerful `--fix` ecosystem which outputs `RemediationMode.SAFE_APPLY` transformations.

While it is exceptionally tempting to apply `--fix` via `args: ["--fix"]`, **SlowQL explicitly restricts the `--fix` parameter to single-file executions to guarantee backup integrity (`.bak` handling).**

Because `pre-commit` intrinsically passes an array of multiple files (`slowql file1.sql file2.sql file3.sql`), utilizing `--fix` inside your `.pre-commit-config.yaml` **will trigger an operational warning and bypass the fix sequence.**

### The Recommended Workflow
Instead of hacking the auto-fix into pre-commit logic:
1. Allow `pre-commit` to act as a **Read-Only Gatekeeper**.
2. If the commit is rejected, execute `slowql myfile.sql --diff` locally to preview the issue.
3. Trigger `slowql myfile.sql --fix` locally against the isolated document to rapidly remediate the highlighted vulnerabilities, and re-commit smoothly.

---

## Local Installation & Usage

Once you've mapped your `.pre-commit-config.yaml`, install the hooks globally within your Git repository so that it executes universally on `git commit`.

```bash
# Install the hook logic
pre-commit install
```

If you wish to force the runner against your entire repository (bypassing the 'changed files only' limitation) to establish an initial benchmark:

```bash
pre-commit run --all-files
```
