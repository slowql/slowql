# Test Suite Documentation

This project includes a comprehensive test suite covering **unit**, **integration**, **performance**, and **demo** scenarios.  
All tests are written with [pytest](https://docs.pytest.org/) and can be run inside the project’s virtual environment.

---

## Structure

- **`tests/unit/`**
  - Validates core components (`QueryAnalyzer`, `QueryDetector`, formatters).
  - Ensures analyzer returns DataFrames with expected columns.
  - Covers edge cases: empty queries, invalid formats, multiple identical issues, export functions.

- **`tests/integration/`**
  - Exercises the CLI (`slowql.cli`) end-to-end.
  - Validates flags like `--fast`, `--parallel`, `--verbose`, `--no-intro`, `--export`.
  - Includes error handling tests (`invalid export format`, `no SQL provided`).
  - Covers the `--help-art` flag via `cli_help.show_animated_help`.

- **`tests/performance/`**
  - Benchmarks analyzer and CLI performance using `pytest-benchmark`.
  - Ensures small workloads complete quickly and parallel mode scales.
  - Assertions are inside benchmarked functions to validate correctness during timing.

- **`tests/test_demo.py`**
  - Demonstrates analyzer + formatter pipeline on representative queries.
  - Serves as a smoke test for end-to-end analysis.

---

## Running Tests

Activate your virtual environment and run:

```bash
.venv/bin/python -m pytest -v
```

To run only a subset:

```bash
pytest tests/unit -v
pytest tests/integration -v
pytest tests/performance -v
```

## Performance Benchmarks
Benchmarks are grouped by analyzer and CLI:

 * **Analyzer Fast Mode:** validates single-core analysis speed.

 * **Analyzer Parallel Mode:** validates multi-core scaling.

 * **CLI Fast/Parallel Mode:** measures end-to-end CLI execution.

Results are reported with min/mean/max runtimes and OPS (operations per second).

## Notes
The analyzer now returns a **DataFrame by default;** use 'return_dataframe=False' for raw lists.

CLI '--help-art' is stubbed in 'src/slowql/cli_help.py' and can be expanded with ASCII art.

Detector includes an explicit rule for '"OR Prevents Index"' in WHERE clauses.

Performance tests require 'pytest-benchmark' ('pip install pytest-benchmark').

## CI Integration
Add to your CI pipeline:

```yaml
- name: Run tests
  run: |
    pip install -r requirements.txt
    .venv/bin/python -m pytest --maxfail=1 --disable-warnings -q
```
