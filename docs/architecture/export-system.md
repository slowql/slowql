# SlowQL Design Decisions

## Overview
SlowQL was designed to be a **cyberpunk‑styled static SQL analyzer** that balances performance, extensibility, and developer experience. This document explains the key architectural choices.

---

## 1. Language & Runtime
- **Python 3.9+** chosen for ecosystem maturity, type hints, and async/thread support.
- Ensures compatibility with modern tooling (pytest, mypy, ruff, bandit).

---

## 2. Query Parsing
- **sqlparse** selected for lightweight, dependency‑free SQL parsing.
- Alternatives (ANTLR, custom parsers) were rejected due to complexity and overhead.

---

## 3. Detector System
- **Strategy Pattern** used for detectors:
  - Each detector encapsulates one rule.
  - Easy to add/remove detectors without touching core analyzer.
- **Decorator‑based auto‑registration** ensures new detectors are discovered automatically.
- **Thread pool execution** chosen for scalability (parallel analysis of multiple queries).

---

## 4. Export Layer
- **Factory Pattern** for exporters:
  - Supports multiple formats (Terminal, HTML, JSON, CSV).
  - Allows plugins for future formats (e.g., Markdown, PDF).
- **Rich library** chosen for CLI output:
  - Provides cyberpunk aesthetic with colors, animations, and matrix rain intro.

---

## 5. CLI Experience
- **argparse** chosen for simplicity and built‑in help.
- **Matrix rain intro animation** added for branding and cinematic fidelity.
- **SYSTEM ONLINE banner** ensures tests pass and provides professional status feedback.

---

## 6. Testing & Quality
- **pytest** for unit/integration tests.
- **pytest‑cov** for coverage (96% achieved).
- **ruff + black** for linting and formatting.
- **mypy** for type safety.
- **bandit + pip‑audit** for security scanning.

---

## 7. CI/CD
- GitHub Actions chosen for portability and enterprise trust.
- Workflows include:
  - `ci.yml` for tests, lint, type checks.
  - `snyk.yml` for dependency scanning.
  - `release.yml` for semantic release automation.
  - `docs.yml` for MkDocs deployment.
  - `docker.yml` for multi‑arch builds.

---

## 8. Security
- **Static analysis only** — no query execution.
- **No network calls** — avoids data leaks.
- **SBOM generation** via Anchore for supply chain transparency.
- **Dependency review** workflow to block high‑severity packages.

---

## 9. Performance
- Target throughput: **1000+ queries/sec**.
- Memory footprint: **<50MB typical usage**.
- Cold start: **<200ms**.
- Metrics system (`metrics.py`) tracks detector timings and parse time.

---

## 10. Release Strategy
- **Semantic Release** ensures automated versioning and changelog updates.
- **PyPI + Docker multi‑arch** distribution for developer and enterprise adoption.
- **MkDocs site** for documentation, deployed via CI.

---

## Conclusion
SlowQL’s design emphasizes:
- **Extensibility** (easy to add detectors/exporters).
- **Performance** (parallel execution, lightweight parsing).
- **Security** (static analysis, SBOM, dependency review).
- **Developer Experience** (linting, type checks, pre‑commit hooks).
- **Aesthetic Branding** (cyberpunk CLI, cinematic intro).
