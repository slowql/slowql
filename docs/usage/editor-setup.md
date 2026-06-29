# Editor Setup

SlowQL v2.0.0 does not include an LSP server. The VS Code extension and other IDE integrations based on the previous Python implementation are not available in this release.

## Current Options

### Run SlowQL from Terminal

The fastest way to use SlowQL in your editor is via the integrated terminal:

```bash
slowql src/
```

## File Watcher (VS Code)
You can configure VS Code to run SlowQL automatically on file save using the Run on Save extension or a task:

`.vscode/tasks.json:`
``` JSON
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "SlowQL: Analyze Current File",
      "type": "shell",
      "command": "slowql ${file}",
      "presentation": {
        "reveal": "always",
        "panel": "shared"
      },
      "problemMatcher": []
    },
    {
      "label": "SlowQL: Analyze Project",
      "type": "shell",
      "command": "slowql src/",
      "presentation": {
        "reveal": "always",
        "panel": "shared"
      },
      "problemMatcher": []
    }
  ]
}
```

## Pre-commit Hook
Run SlowQL automatically before each commit:

``` Bash
# .git/hooks/pre-commit
#!/bin/sh
slowql . --git-diff --fail-on high
```

``` Bash
# Make executable
chmod +x .git/hooks/pre-commit
```

See [Pre-Commit Hooks](pre-commit-hooks.md#usage) for more information.

## Planned
IDE integration via LSP is planned for future release.
