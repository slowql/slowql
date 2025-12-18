# slowql/src/slowql/cli/ui/theme.py
"""
Cyberpunk theme definition for the SlowQL CLI.

Defines the color palette, styles, and symbols used in the TUI.
"""

from rich.theme import Theme

# Cyberpunk Color Palette
CYBER_NEON_BLUE = "#00f3ff"
CYBER_NEON_PINK = "#ff00ff"
CYBER_NEON_GREEN = "#00ff41"
CYBER_NEON_YELLOW = "#fcee0a"
CYBER_DARK_BG = "#0d0221"
CYBER_GRID = "#2a2a2a"

# Rich Theme Definition
SLOWQL_THEME = Theme(
    {
        # Base
        "info": "dim cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        # Severity Levels
        "severity.critical": "bold red reverse",
        "severity.high": "bold red",
        "severity.medium": "bold yellow",
        "severity.low": "bold cyan",
        "severity.info": "dim blue",
        # Dimensions
        "dim.security": "red",
        "dim.performance": "yellow",
        "dim.reliability": "blue",
        "dim.compliance": "magenta",
        "dim.cost": "green",
        # UI Elements
        "panel.border": "blue",
        "panel.title": "bold white",
        "table.header": "bold cyan",
        "table.row": "white",
        "progress.bar": "magenta",
        "progress.percentage": "bold white",
        # Code Highlighting
        "code.keyword": "bold magenta",
        "code.literal": "green",
        "code.identifier": "cyan",
        "code.comment": "dim white",
    }
)


# Symbols
class Symbols:
    """Unicode symbols for the UI."""

    LOGO_TOP = "█▀▀ █  █▀▀█ █   █ █▀▀█ █"
    LOGO_BOT = "▄██ █▄ █▄▄█ ▀▄▀▄▀ ▀▄▄█ █▄▄"

    CRITICAL = "💀"
    HIGH = "🔥"
    MEDIUM = "⚡"
    LOW = "💫"
    INFO = "💡"

    CHECK = "✔"
    CROSS = "✖"
    WARNING = "⚠"
    ARROW = "➜"
    BULLET = "•"

    BOX_TOP_LEFT = "╔"
    BOX_TOP_RIGHT = "╗"
    BOX_BOTTOM_LEFT = "╚"
    BOX_BOTTOM_RIGHT = "╝"
    BOX_HORIZ = "═"
    BOX_VERT = "║"
