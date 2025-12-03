# SlowQL Architecture

## System Overview
```
┌─────────────────────────────────────────────────┐
│                CLI / Library API                 │
│  ┌──────────────┐        ┌──────────────┐      │
│  │ slowql CLI   │        │ Python API   │      │
│  └──────┬───────┘        └──────┬───────┘      │
└─────────┼────────────────────────┼──────────────┘
          │                        │
          ▼                        ▼
┌─────────────────────────────────────────────────┐
│             Query Analyzer Core                  │
│  • SQL Parsing (sqlparse)                       │
│  • Detector Orchestration                       │
│  • Result Aggregation                           │
└─────────────┬───────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────┐
│          Detector Registry (50+)                 │
│  ┌──────────────────┬──────────────────────┐   │
│  │ Security         │ Performance          │   │
│  │ • SQL Injection  │ • SELECT *           │   │
│  │ • Missing WHERE  │ • Non-SARGable       │   │
│  └──────────────────┴──────────────────────┘   │
└─────────────┬───────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────┐
│              Export Layer                        │
│  • Terminal (Cyberpunk!)                        │
│  • HTML • JSON • CSV                            │
└─────────────────────────────────────────────────┘
```

## Core Components

### 1. Query Analyzer
- **Responsibility:** Coordinate detection workflow
- **Input:** Raw SQL string or file
- **Output:** List of `Issue` objects
- **Location:** `slowql/core/analyzer.py`

### 2. Detector System
- **Pattern:** Strategy Pattern
- **Base Class:** `BaseDetector`
- **Auto-registration:** Decorator-based
- **Parallel Execution:** Thread pool (configurable)

### 3. Export System
- **Pattern:** Factory Pattern
- **Formats:** Terminal, HTML, JSON, CSV
- **Extensibility:** Plugin-based

## Design Principles

1. **Stateless:** No database connection required
2. **Fast:** Target <100ms for typical queries
3. **Extensible:** Easy to add detectors
4. **CI/CD Ready:** Non-interactive mode
5. **Beautiful:** Cyberpunk aesthetic

## Technology Stack

- **Language:** Python 3.9+
- **Parser:** sqlparse
- **CLI:** argparse + rich (for output)
- **Testing:** pytest
- **Packaging:** setuptools

## Performance

- **Target:** 1000+ queries/sec
- **Memory:** <50MB typical usage
- **Startup:** <200ms cold start

## Security Considerations

- Static analysis only (no code execution)
- No network calls
- Input validation on file paths
- Sanitized output in HTML export