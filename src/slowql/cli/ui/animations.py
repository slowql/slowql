# slowql/src/slowql/cli/ui/animations.py
"""
SLOWQL Animations Module

Provides cinematic cyberpunk animations for CLI experience:
- MatrixRain intro (Gemini-style 3D Pixel Logo)
- Cinematic Scrolling Features
- Interactive SQL editor
- AnimatedAnalyzer effects
"""

from __future__ import annotations

import contextlib
import random
import shutil
import time
from typing import TYPE_CHECKING

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from rich.renderable import Renderable

try:
    import readchar

    HAVE_READCHAR = True
except ImportError:
    HAVE_READCHAR = False

class MatrixRain:
    """Full-window Matrix rain intro with integrated 3D Pixel-Logo."""

    def __init__(self) -> None:
        self.console: Console = Console()
        size = shutil.get_terminal_size()
        self.width: int = size.columns
        self.height: int = size.lines
        self.chars: str = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789"

        # GEMINI-STYLE 3D PIXEL LOGO
        # Using █ for face and ▒ for shadow/depth
        self.logo_ascii: list[str] = [
            "▓   ██████╗ ██╗      ██████╗ ██╗    ██╗ ██████╗ ██╗     ",
            " ▓  ██╔═══╝ ██║     ██╔═══██╗██║    ██║██╔═══██╗██║     ",
            "  ▓ ██████╗ ██║     ██║   ██║██║ █╗ ██║██║   ██║██║     ",
            " ▓  ╚════██╗██║     ██║   ██║██║███╗██║██║▄▄ ██║██║     ",
            "▓   ██████╔╝███████╗╚██████╔╝╚███╔███╔╝╚██████╔╝███████╗",
            "    ╚═════╝ ╚══════╝ ╚═════╝  ╚══╝╚══╝  ╚══▀▀═╝ ╚══════╝",
        ]

        self.subtitle = "◆ INTELLIGENT SQL ANALYSIS ENGINE ◆"

        # Initialize rain columns
        self.columns: list[dict] = [
            {
                "y": float(random.randint(-self.height, 0)),
                "speed": random.uniform(0.8, 1.2),
                "chars": [random.choice(self.chars) for _ in range(self.height + 5)],
            }
            for _ in range(self.width)
        ]

    def _get_logo_color(self, x_pos: int, total_width: int) -> str:
        """
        Generate the Gemini-style horizontal gradient:
        Cyan (Arrow) -> Blue -> Purple -> Pink
        """
        # Relative position 0.0 to 1.0 within the logo
        ratio = x_pos / max(1, total_width)

        if ratio < 0.1:  # The Arrow area
            return "bold cyan"
        elif ratio < 0.35:  # S-L
            return "bold deep_sky_blue1"
        elif ratio < 0.6:  # O-W
            return "bold medium_purple1"
        elif ratio < 0.8:  # Q
            return "bold magenta"
        else:  # L
            return "bold hot_pink"

    def _get_logo_position(self) -> tuple[int, int, int]:
        """Calculate the top-left position and width of the logo."""
        logo_height = len(self.logo_ascii)
        logo_width = max(len(line) for line in self.logo_ascii)
        start_y = (self.height // 2) - (logo_height // 2) - 2
        start_x = (self.width // 2) - (logo_width // 2)
        return start_y, start_x, logo_width

    def _get_char_for_position(
        self, x: int, y: int, frame: int, frames: int
    ) -> tuple[str, str]:
        """Determine the character and style for a given coordinate."""
        start_y, start_x, logo_width = self._get_logo_position()
        col = self.columns[x]
        cy = int(col["y"])

        char_idx = (y + frame) % len(col["chars"])
        char = col["chars"][char_idx]

        style = "dim green"
        if cy == y:
            style = "bold white"
        elif cy - 6 < y < cy:
            style = "bold green"

        in_logo_y = start_y <= y < start_y + len(self.logo_ascii)
        in_logo_x = start_x <= x < start_x + logo_width

        if in_logo_y and in_logo_x:
            ly, lx = y - start_y, x - start_x
            if lx < len(self.logo_ascii[ly]) and self.logo_ascii[ly][lx] != " ":
                logo_char = self.logo_ascii[ly][lx]
                progress = frame / frames
                if progress > 0.35 and random.random() < (progress - 0.35) * 2.0:
                    logo_color = self._get_logo_color(lx, logo_width)
                    style_override = (
                        logo_color.replace("bold", "dim") if char in "▓▒░" else logo_color
                    )
                    return logo_char, style_override
                if progress > 0.25:
                    return char, "dim purple"

        return (char, style) if cy - 6 < y < cy else (" ", style)

    def _build_frame(self, frame: int, frames: int) -> Group:
        """Build a single animation frame."""
        start_y, _start_x, _logo_width = self._get_logo_position()
        lines: list[Renderable] = []
        for y in range(self.height):
            line_text = Text()
            for x in range(self.width):
                char, style = self._get_char_for_position(x, y, frame, frames)
                line_text.append(char, style=style)
            lines.append(line_text)

        if frame > frames * 0.9:
            sub_y = start_y + len(self.logo_ascii) + 1
            if 0 <= sub_y < len(lines):
                lines[sub_y] = Align.center(Text(self.subtitle, style="bold cyan"))

        return Group(*lines)

    def run(self, duration: float = 4.0) -> None:
        """
        Run the animation loop.
        Phase 1: Matrix Rain.
        Phase 2: Logo glitches into existence.
        """
        frames = int(duration * 20)
        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            for frame in range(frames):
                for col in self.columns:
                    col["y"] += col["speed"]
                    if col["y"] > self.height:
                        col["y"] = float(random.randint(-10, -2))

                renderable = self._build_frame(frame, frames)
                live.update(
                    Panel(
                        renderable,
                        box=box.SIMPLE,
                        style="on black",
                    )
                )

        # Transition to scrolling features
        self._slow_scroll_reveal()

    def _slow_scroll_reveal(self) -> None:
        """
        Instead of clearing screen, print logo statically, then
        slowly scroll the features up the screen.
        """
        self.console.clear()

        # Padding
        self.console.print("\n" * 2)

        # Print Static Logo with Gradient
        logo_width = max(len(line) for line in self.logo_ascii)
        for line in self.logo_ascii:
            text = Text()
            for i, char in enumerate(line):
                color = self._get_logo_color(i, logo_width) if char != " " else "white"
                # Dim the shadow characters for 3D effect
                if char in ["▓", "▒", "░"]:
                    color = color.replace("bold", "dim")
                text.append(char, style=color)
            self.console.print(Align.center(text))

        self.console.print(Align.center(self.subtitle, style="bold cyan"))
        self.console.print()

        time.sleep(0.5)

        # 2. Begin Slow Scroll of Features
        self._show_feature_overview_slow()

        # 3. Final Prompt: block here until user presses Enter
        self.console.print()
        self.console.print(Align.center("[bold green blink]► PRESS ENTER TO ACTIVATE CONSOLE ◄[/]"))

        # Wait for a real Enter press
        try:
            if HAVE_READCHAR:
                while readchar.readkey() not in (readchar.key.ENTER, "\r", "\n"):
                    pass
            else:
                with contextlib.suppress(EOFError):
                    input()
        except Exception:
            with contextlib.suppress(EOFError):
                input()

    def _render_feature_grid(self, features: list[dict]) -> None:
        """Render the two-column grid of feature categories."""
        console_width = getattr(self.console, "width", 100)
        for i in range(0, len(features), 2):
            left_feature = features[i]
            right_feature = features[i + 1] if i + 1 < len(features) else None

            panel_width = (console_width // 2) - 2

            def create_feature_panel(feature: dict | None, panel_width: int = panel_width) -> Panel:
                if not feature:
                    return Panel(
                        "", border_style="dim", box=box.ROUNDED, padding=(1, 1), width=panel_width
                    )

                table = Table(box=None, padding=(0, 1), show_header=False, expand=True)
                table.add_column(ratio=1)
                for item_name, item_desc in feature["items"]:
                    table.add_row(f"[{feature['color']}]{feature['icon']}[/] [bold]{item_name}[/]")
                    table.add_row(f"[dim]└─ {item_desc}[/]")
                    table.add_row("")

                return Panel(
                    table,
                    title=f"[bold {feature['color']}]{feature['category']}[/]",
                    border_style=feature["color"],
                    box=box.ROUNDED,
                    padding=(1, 1),
                    width=panel_width,
                )

            grid = Table.grid(expand=True, padding=(0, 1))
            grid.add_column(ratio=1)
            grid.add_column(ratio=1)
            grid.add_row(create_feature_panel(left_feature), create_feature_panel(right_feature))

            self.console.print(grid)
            self.console.print()
            time.sleep(0.4)

    def _render_capabilities_panel(self, capabilities: list[tuple[str, str]]) -> None:
        """Render the panel showing comprehensive capabilities."""
        console_width = getattr(self.console, "width", 100)
        caps_grid = Table.grid(expand=True, padding=(0, 2))
        for _ in range(4):
            caps_grid.add_column(ratio=1)

        for i in range(0, len(capabilities), 4):
            row_items = capabilities[i : i + 4]
            caps_grid.add_row(*(item[0] for item in row_items))
            caps_grid.add_row(*(f"[dim]{item[1]}[/]" for item in row_items))
            if i + 4 < len(capabilities):
                caps_grid.add_row("", "", "", "")

        self.console.print(
            Panel(
                caps_grid,
                title="[bold white]◢◣ COMPREHENSIVE CAPABILITIES ◣◢[/]",
                border_style="bright_blue",
                box=box.ROUNDED,
                padding=(1, 2),
                width=console_width,
            )
        )
        self.console.print()
        time.sleep(0.4)

    def _render_power_features_panel(self, power_features: list[str]) -> None:
        """Render the panel showing power features."""
        console_width = getattr(self.console, "width", 100)
        power_grid = Table.grid(expand=True, padding=(0, 2))
        for _ in range(3):
            power_grid.add_column(ratio=1)

        for i in range(0, len(power_features), 3):
            cols = [
                f"[bold cyan]◆[/] {power_features[i + j]}" if i + j < len(power_features) else ""
                for j in range(3)
            ]
            power_grid.add_row(*cols)
            if i + 3 < len(power_features):
                power_grid.add_row("", "", "")

        self.console.print(
            Panel(
                power_grid,
                title="[bold white]◢◣ POWER FEATURES ◣◢[/]",
                border_style="magenta",
                box=box.HEAVY,
                padding=(1, 2),
                width=console_width,
            )
        )
        self.console.print()
        time.sleep(0.4)

    def _show_feature_overview_slow(self) -> None:
        """
        Display comprehensive overview of all SlowQL features and capabilities.
        Animated to scroll slowly with symmetrical layouts.
        """
        # Comprehensive feature list organized by category
        features = [
            {
                "category": "CORE ANALYSIS ENGINE",
                "items": [
                    (
                        "Multi-Dimensional Analysis",
                        "Security, Performance, Reliability, Compliance, Quality, & Cost",
                    ),
                    ("Advanced AST Parsing", "sqlglot-powered deep SQL analysis"),
                    ("Rule-Based Detection", "250+ detection patterns and anti-patterns"),
                    ("Heuristic Analysis", "AI-powered pattern recognition and estimation"),
                    ("Real-time Analysis", "Instant feedback on SQL queries"),
                    ("Batch Processing", "Analyze multiple queries simultaneously"),
                ],
                "icon": "🚀",
                "color": "bright_blue",
            },
            {
                "category": "SECURITY ANALYSIS",
                "items": [
                    (
                        "SQL Injection Detection",
                        "OWASP Top 10 coverage with advanced pattern matching",
                    ),
                    ("Hardcoded Secret Detection", "Passwords, tokens, and credentials scanning"),
                    ("Privilege Escalation", "Excessive GRANT and permission analysis"),
                    ("Sensitive Data Exposure", "PII, financial data, and compliance risks"),
                    ("Authentication Bypass", "Weak authentication pattern detection"),
                    ("Security Metadata", "CVE mapping and security standards compliance"),
                ],
                "icon": "🔒",
                "color": "red",
            },
            {
                "category": "PERFORMANCE OPTIMIZATION",
                "items": [
                    ("Index Usage Analysis", "SARGability and index optimization suggestions"),
                    ("Full Table Scan Detection", "Expensive scan pattern identification"),
                    ("Query Complexity Analysis", "JOIN, subquery, and CTE optimization"),
                    ("Resource Estimation", "CPU, memory, and I/O impact analysis"),
                    ("Execution Plan Simulation", "Predictive performance modeling"),
                    ("Cloud Cost Optimization", "Cost-effective query pattern recommendations"),
                ],
                "icon": "⚡",
                "color": "yellow",
            },
            {
                "category": "RELIABILITY & SAFETY",
                "items": [
                    ("Data Loss Prevention", "Destructive operation interception"),
                    ("Transaction Safety", "ACID compliance verification"),
                    ("Schema Integrity", "Safe schema modification patterns"),
                    ("Backup Validation", "Pre-change impact assessment"),
                    ("Rollback Planning", "Automatic recovery strategy generation"),
                    ("Disaster Recovery", "Catastrophic failure prevention"),
                ],
                "icon": "🛡️",
                "color": "blue",
            },
            {
                "category": "COMPLIANCE & GOVERNANCE",
                "items": [
                    ("GDPR Compliance", "Personal data protection verification"),
                    ("HIPAA Compliance", "Healthcare data security checks"),
                    ("PCI-DSS Compliance", "Payment data protection analysis"),
                    ("Data Residency", "Cross-border data transfer detection"),
                    ("Audit Trail", "Comprehensive analysis logging"),
                    ("Policy Enforcement", "Custom organizational rule compliance"),
                ],
                "icon": "📋",
                "color": "magenta",
            },
            {
                "category": "ADVANCED FEATURES",
                "items": [
                    ("Interactive Analysis Loop", "Continuous query refinement workflow"),
                    ("Query Comparison Mode", "Before/after optimization analysis"),
                    ("Smart Suggestions", "Context-aware improvement recommendations"),
                    ("Session Management", "Analysis history and progress tracking"),
                    ("Export Capabilities", "JSON, HTML, CSV report generation"),
                    ("CI/CD Integration", "Automated analysis in pipelines"),
                    ("Custom Rule Engine", "Extend with organization-specific rules"),
                    ("API Access", "Programmatic analysis integration"),
                ],
                "icon": "💡",
                "color": "cyan",
            },
        ]

        capabilities = [
            ("🔍 Detection Capabilities", "250+ SQL anti-patterns and best practices"),
            ("📊 Analysis Dimensions", "6 comprehensive analysis categories"),
            ("⚡ Performance Rules", "Advanced query optimization patterns"),
            ("🔒 Security Rules", "OWASP Top 10 and compliance coverage"),
            ("🛡️ Safety Checks", "Data loss and disaster prevention"),
            ("💡 Smart Features", "Context-aware recommendations and suggestions"),
            ("🔧 Customization", "Extendable rule engine and analyzers"),
            ("📈 Scalability", "Enterprise-grade performance and reliability"),
        ]

        power_features = [
            "🚀 Real-time SQL Analysis Engine",
            "🔍 250+ Detection Patterns and Anti-Patterns",
            "📊 Multi-Dimensional Issue Classification",
            "💡 Context-Aware Smart Recommendations",
            "⚡ Enterprise-Grade Performance",
            "🔒 Comprehensive Security Coverage",
            "🛡️ Data Loss Prevention System",
            "📋 Regulatory Compliance Verification",
        ]

        console_width = getattr(self.console, "width", 100)
        self.console.print(
            Panel(
                Align.center(
                    "[bold white]◢◣ SLOWQL ENTERPRISE FEATURES ◣◢[/]\n"
                    "[dim]Comprehensive SQL Analysis Platform[/]"
                ),
                style="bold cyan",
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(1, 2),
                width=console_width,
            )
        )
        self.console.print()
        time.sleep(0.3)

        self._render_feature_grid(features)
        self._render_capabilities_panel(capabilities)
        self._render_power_features_panel(power_features)

        # Final summary
        final_summary = Panel(
            Align.center(
                "[bold green]◆ SLOWQL: The Ultimate SQL Analysis Platform[/]\n"
                "[dim]Enterprise-grade analysis with 250+ detection patterns,[/]\n"
                "[dim]6 analysis dimensions, and comprehensive SQL optimization[/]"
            ),
            style="bold white on rgb(20,20,40)",
            border_style="green",
            box=box.DOUBLE,
            padding=(2, 4),
            width=console_width,
        )

        self.console.print(final_summary)
        self.console.print()


class CyberpunkSQLEditor:
    """Interactive SQL query editor."""

    def __init__(self) -> None:
        self.console: Console = Console()

    def get_queries(self) -> str | None:
        """
        Interactive query composition loop.
        """
        self.console.clear()
        self._show_header()

        queries: list[str] = []

        # FULL WIDTH HEADER FOR COMPOSITION AREA
        self.console.print()
        self.console.print(Rule("[bold magenta]QUERY COMPOSITION STARTED[/]", style="bold magenta"))
        self.console.print()

        while True:
            line_num: int = len(queries) + 1
            # Cleaner prompt style
            prompt_text: str = f"[cyan]SQL:{line_num:02d}[/] [bold magenta]▸[/] "

            try:
                query: str = Prompt.ask(prompt_text, default="")

                if query.strip() == "" and queries and queries[-1].strip() == "":
                    queries = queries[:-1]
                    break

                queries.append(query)

                if query.strip():
                    self._show_query_preview(query)

            except KeyboardInterrupt:
                return None

        # FULL WIDTH FOOTER
        self.console.print()
        self.console.print(
            Panel(
                Align.center("[bold green]BATCH CAPTURE COMPLETE[/]"),
                border_style="bold magenta",
                box=box.DOUBLE,
                expand=True,
            )
        )
        self._show_query_summary(queries)

        return "\n".join(queries)

    def _show_header(self) -> None:
        self.console.print(
            Panel(
                Align.center("[bold magenta]◆ SLOWQL QUERY TERMINAL v1.2 ◆[/]"),
                border_style="bold cyan",
                box=box.HEAVY,
                expand=True,
                padding=(1, 1),
            )
        )

    def _show_query_preview(self, query: str) -> None:
        syntax = Syntax(query, "sql", theme="monokai", line_numbers=False)
        self.console.print(Panel(syntax, border_style="dim cyan", box=box.MINIMAL))

    def _show_query_summary(self, queries: list[str]) -> None:
        valid_queries: list[str] = [q for q in queries if q.strip()]
        if valid_queries:
            self.console.print()
            self.console.print(
                Rule(
                    f"[bold green]◆ QUERIES CAPTURED: {len(valid_queries)} ◆[/]", style="bold green"
                )
            )
            self.console.print()
            time.sleep(1)


class AnimatedAnalyzer:
    """Animated SQL analysis results with cyberpunk effects."""

    def __init__(self) -> None:
        self.console: Console = Console()
        self.gradient_colors: list[str] = [
            "magenta",
            "hot_pink",
            "deep_pink4",
            "medium_purple",
            "cyan",
        ]

    def glitch_transition(self, duration: float = 0.2) -> None:
        """Glitch effect between sections."""
        chars: str = "░▒▓█▀▄━│─/╲"
        for _ in range(int(duration * 10)):
            glitch_line: str = "".join(random.choice(chars) for _ in range(80))
            self.console.print(f"[{random.choice(self.gradient_colors)}]{glitch_line}[/]", end="\r")
            time.sleep(0.02)
        self.console.print(" " * 80, end="\r")

    def particle_loading(self, message: str = "PROCESSING") -> None:
        """Particle effect loading animation (Full Width)."""
        particles: list[str] = ["◢", "◣", "◤", "◥", "◆", "◈", "▰", "▱", "▪", "▫"]

        # Calculate width dynamically
        width = shutil.get_terminal_size().columns - 4
        # Calculate how many particles fit
        particle_count = width // 2

        with Live(console=self.console, refresh_per_second=30) as live:
            for _ in range(40):  # Slightly longer duration
                particle_field: list[str] = []

                # Generate 3 rows of full-width particles
                for _ in range(3):
                    line_chars = []
                    # Create a density gradient
                    for _ in range(particle_count):
                        if random.random() > 0.7:  # 30% chance of particle
                            line_chars.append(random.choice(particles))
                        else:
                            line_chars.append(" ")

                    line_str = " ".join(line_chars)

                    # Apply random color to entire line
                    color = random.choice(self.gradient_colors)
                    particle_field.append(f"[{color}]{line_str}[/]")

                live.update(
                    Panel(
                        "\n".join(particle_field),
                        title=f"[bold white blink]◢ {message} ◣[/]",
                        border_style="cyan",
                        box=box.ROUNDED,
                        padding=(0, 1),
                        expand=True,
                    )
                )
                time.sleep(0.05)

    def reveal_section(self, content: str, title: str = "", style: str = "cyan") -> None:
        """
        Smooth reveal with gradient animation.
        """
        for opacity in ["dim", "", "bold"]:
            self.console.clear()
            self.console.print(
                Panel(
                    content,
                    title=f"[{opacity} {style}]{title}[/]",
                    border_style=f"{opacity} {style}",
                    box=box.HEAVY,
                )
            )
            time.sleep(0.1)

    def show_expandable_details(self, summary: str, details: str, expanded: bool = False) -> None:
        """
        Interactive expand/collapse view.
        """
        if not expanded:
            self.console.print(
                Panel(
                    summary + "\n\n[dim cyan]▼ Press ENTER to expand details ▼[/]",
                    border_style="cyan",
                )
            )
            with contextlib.suppress(Exception):
                input()
            self.glitch_transition()

        # Show expanded details with animation
        self.reveal_section(details, title="◢ DETAILED ANALYSIS ◣")
