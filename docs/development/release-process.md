# Release Process

This framework governs how core maintainers prepare, package, and distribute the SlowQL engine across binary and container registries.

## Versioning Standards

SlowQL enforces semantic versioning logic (`MAJOR.MINOR.PATCH`):

- **MAJOR**: Fundamental API breaks or massive CLI argument restructures.
- **MINOR**: New Rules added, new Dialect capabilities, backward-compatible engine features.
- **PATCH**: False positive hotfixes, AST parsing patches, performance improvements.

Declare the version upgrade strictly inside `pyproject.toml` natively:

```toml
[project]
version = "1.6.1"
```

## Changelog Tracking

Document all technical modifications explicitly inside `CHANGELOG.md` utilizing the standard distribution formats:

```markdown
## [1.6.1] - 2026-03-24
### Added
- Created `COST-SF-001` to detect Cartesian loops in Snowflake queries.
- Attached dialect scoping to the `Rule` metaclass.
### Fixed
- Re-architected `sqlglot` parsing to natively support `presto` Window Function clauses.
```

## Internal Release Validation

Prior to generating distribution artifacts, run the absolute gatekeeping pipeline locally to detect regressions:

```bash
ruff format .
ruff check .
mypy src/slowql --strict
pytest
```
*If any component returns a non-zero exit code, immediately abort the release track.*

## Generating Binary Packages

SlowQL relies on the `hatchling` backend to construct modern distribution wheels natively.

```bash
# Clean legacy distribution folders
rm -rf dist/

# Compile source distributions and wheels
python -m build
```
This deposits the immutable artifacts natively under `/dist/`.

## Publishing to Registries

### 1. PyPI (Python Package Index)
Execute standard `twine` uploads strictly pushing the signed artifacts:

```bash
twine upload dist/*
```

### 2. GitHub Releases
Tag the repository natively reflecting the standard `v{VERSION}` logic to trigger internal actions cleanly:

```bash
git tag v1.6.1
git push origin v1.6.1
```
Navigate to the GitHub UI and convert the Tag into a robust Release securely pasting the corresponding `CHANGELOG.md` segment.

### 3. GitHub Container Registry (GHCR)
The master GitHub Action natively intercepts new Tags and automatically compiles, scans, and deposits the immutable Docker Image into `ghcr.io/makroumi/slowql:latest` and `ghcr.io/makroumi/slowql:v1.6.1`.

## Pipeline Best Practices

- Releases should remain aggressively rapid. Do not batch 40 rules; drop 5 rules per minor version.
- Validate AST logic extremely heavily offline prior to publishing `[all]` extras tags.
- Use Draft Releases dynamically within GitHub if coordination across the VS Code Extension pipeline is required.
