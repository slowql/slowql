# SQLGuard

SQLGuard is a cinematic, interactive SQL analysis tool that finds SQL anti‑patterns, performance issues, and potential bugs using static analysis — no database connection required. It presents findings in a polished, animated terminal experience designed for engineers who value technical rigor and presentation.

© El Mehdi Makroumi 2025. All rights reserved.

---

## What it does

- Detects common and advanced SQL issues: SELECT *, missing WHERE on mutations, non‑SARGable predicates, NULL comparison errors, huge IN lists, cartesian products, correlated subqueries, and more.
- Produces an actionable, prioritized report with suggested fixes and impact descriptions.
- Ships a memorable terminal UX: Matrix rain intro, per‑line query composer with live preview, particle loading, glitch transitions, and a vaporwave/cyberpunk report layout.
- Provides fast modes and non‑interactive options for CI and automation.
- Exports reports as JSON, CSV, or as a styled HTML capture for sharing.

---

## Quick install

Recommended: use a Python virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install slowql