# Baseline / Diff Mode

Baseline (Diff) Mode allows teams to capture a snapshot of all existing issues in a codebase on day one, so that SlowQL only reports **new** issues on future runs. This is critical for adopting SlowQL in large, existing codebases without overwhelming developers with legacy warnings.

Analogous to SonarQube's "New Code Period", this feature ensures you stop the bleeding first, and incrementally fix the baseline over time.

## How It Works

SlowQL generates a `.slowql-baseline` JSON file that contains a unique "fingerprint" for every issue currently in your code. 

When you run SlowQL in **Baseline Mode**, it compares the issues it finds against the fingerprints in `.slowql-baseline`. 
- If an issue is already in the baseline, it is **suppressed**.
- If an issue is new (or has been modified), it is **reported**.

The fingerprint is stable and ignores line numbers, meaning whitespace changes or adding/removing lines of code above the issue will *not* cause baseline issues to suddenly be reported again.

---

## 1. Creating a Baseline

To generate your initial baseline file, use the `--update-baseline` flag. This will analyze your codebase, save all found issues to the baseline file, and exit with a `0` code.

```bash
# Generate a baseline for the entire `queries/` directory
slowql queries/ --update-baseline
```

By default, this creates a `.slowql-baseline` file in your current directory. You can specify a custom path if needed:

```bash
slowql queries/ --update-baseline path/to/my-custom-baseline.json
```

It is recommended to **commit the `.slowql-baseline` file to your version control system (e.g., Git)** so that all developers and CI/CD pipelines share the same baseline.

---

## 2. Using the Baseline (Diff Mode)

Once the baseline is created, you can run SlowQL in Baseline Mode using the `--baseline` flag.

```bash
# Only report NEW issues not in the baseline
slowql queries/ --baseline
```

If issues are found but they are all present in the baseline, SlowQL will exit successfully (code `0`), allowing your CI pipeline to pass.

You will see a dim message indicating how many legacy issues were suppressed:

```text
✓ Analysis complete: 0 issues found
64 issues suppressed by baseline.
```

---

## 3. Updating the Baseline

Over time, you will likely fix existing issues or perhaps decide to intentionally ignore a new batch of issues. To sync the baseline with the current state of your codebase, simply re-run the update command:

```bash
# Overwrite the baseline with the current set of issues
slowql queries/ --update-baseline
```

## Example CI/CD Workflow (GitHub Actions)

Here is a typical way to integrate Baseline Mode into your CI/CD pipeline:

```yaml
name: SlowQL Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install SlowQL
        run: pip install slowql
        
      - name: Run SlowQL in Baseline Mode
        run: slowql src/ --baseline
```

In this setup, developers can introduce new code without having to fix every pre-existing SlowQL warning, but any *new* violations they introduce will cause the build to fail.
