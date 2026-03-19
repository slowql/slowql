# Export System

Once the SlowQL engine translates SQL files into arrays of `Issue` dataclasses via the Rules Pipeline, the final architectural step involves formatting and exporting these findings to either human operators or downstream pipeline consumers.

This is fundamentally managed through subclasses of the `BaseReporter`.

## The BaseReporter Abstraction
Every reporter must inherit from `slowql.reporters.base.BaseReporter` and implement the `report(result: AnalysisResult)` method. Repositories decoupling logic directly via dependency injection ensures that SlowQL can easily be extended into future output topologies (e.g., direct API payloads or Jira ticketing logic) simply by creating a new reporter class.

## Current Subsystems

### 1. `ConsoleReporter`
The default system orchestrator intended for human end-users. Inheriting heavily from the `rich` UI library, `console.py` handles:
- Printing cyberpunk-styled summary banners.
- Rendering explicit SQL text snippets surrounding the vulnerable nodes.
- Handling ANSI escape characters for precise coloring (red for Critical/High, yellow for Medium).
- Aggregating statistical throughput metrics (elapsed analysis time, total files processed).

### 2. `GitHubActionsReporter`
Activated via `--format github-actions`. It strictly bypasses visual fluff and logs standardized string outputs (`::error file=bad_query.sql,line=4,col=1::Message`).

GitHub Actions automatically intercepts these specific outputs on `STDOUT` and directly annotates the exact lines of code on internal PR diff views, making it completely effortless for developers to spot violations without opening logs.

### 3. `JsonReporter`
Standard serialization. Generates a robust, array-based `.json` output via `--export json`. Useful when coupling SlowQL internally into larger automated orchestration systems or security aggregation platforms that parse conventional text objects.

### 4. `SarifReporter`
A highly structured format generated via `--export sarif`. **Static Analysis Results Interchange Format (SARIF)** is a widely accepted OASIS standard. Integrating this into GitHub’s `codeql-action` populates the "Security" tab inside GitHub repositories securely, classifying SQL injections alongside native CodeQL scanning results automatically.
