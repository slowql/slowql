# Contributing Workflow

First and foremost, thank you for your commitment to expanding SlowQL! 

SlowQL's community aggressively pioneers the advancement of SQL static analysis against security vulnerabilities, unbounded resource consumption, and reliability regressions.

## Standard Operational Workflow

1. **Fork the Upstream Repository:** Clone the repository under your personal GitHub domain.
2. **Target Working Branches:** Checkout a clean branch structurally diverging from `main`:
   ```bash
   git checkout -b feat/add-clickhouse-cost-rule
   ```
3. **Execution & Implementation:** Develop your logic, strictly implementing `ASTRule` structures and explicit `sqlglot` traversal when applicable.
4. **Mandatory Check Suites:** Prior to formulating a Pull Request, absolutely verify the local toolchain generates zero warnings:
   ```bash
   ruff format .
   ruff check .
   mypy src/slowql --strict
   pytest
   ```
5. **Issue a Pull Request:** Deploy your logic towards the primary `main` axis.

## Code Style Conventions

The project repository relies natively on the automation capabilities established within `pyproject.toml` to settle syntax opinions natively natively offline.

- **Formatting:** Administered purely via the Rust-based executable `ruff format`. Execute `ruff format .` prior to commits.
- **Linting:** Verified entirely via `ruff check .`. All configurations including `flake8` bugs, unutilized scopes, and missing docstrings must resolve `0`.
- **Typing Framework:** Dynamic Python types are rejected. Assert static signatures natively with `mypy --strict`.
- **Topology Restrictions:** Native 100 character line boundaries enforced inherently.

## Conventional Commits

We aggressively follow [Conventional Commits](https://www.conventionalcommits.org/) standards. Your underlying logic must explicitly map to these syntax limits:

- `feat:` Newly exposed functionalities (e.g., adding a rule logic mapping).
- `fix:` Engine pipeline repairs and AST traversal overrides.
- `docs:` Internal documentation re-architecting.
- `test:` Scaling test coverage across explicit rule modules.
- `chore:` Internal CI/CD workflow patches, maintenance, packaging dependencies.

## Pull Requests

Isolate PRs dynamically indicating explicit changes. Include comprehensive operational boundaries proving your logic was executed offline natively. Cross-link corresponding issue IDs executing `Closes #123`.

*Pull requests containing cascading compilation faults during internal execution testing checks will be immediately deferred.*
