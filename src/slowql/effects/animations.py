"""
SLOWQL Animations Module

Provides cinematic cyberpunk animations for CLI experience:
- MatrixRain intro
- Interactive SQL editor
- AnimatedAnalyzer effects
"""

import random
import time
import shutil
from typing import List, Optional

from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.syntax import Syntax
from rich.prompt import Prompt
from rich.console import Group


class MatrixRain:
    """Full-window Matrix rain intro animation with auto-clear."""

    def __init__(self) -> None:
        self.console: Console = Console()
        size = shutil.get_terminal_size()
        # use full terminal size, no artificial caps
        self.width: int = size.columns
        self.height: int = size.lines
        self.chars: str = (
            "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789"
        )

        self.logo: List[str] = [
            " █████   ██      █████   ██   ██  █████   ██     ",
            "██       ██     ██   ██  ██   ██ ██   ██  ██     ",
            " ████    ██     ██   ██  ██ █ ██ ██   ██  ██     ",
            "     ██  ██     ██   ██  ██ █ ██ ██  ███  ██     ",
            " █████   ██████  █████    █   █   ██████  ██████ ",
            "",
            "       ◆ DATABASE ANOMALY DETECTOR ◆       ",
            "         v2.0 CYBERPUNK EDITION         ",
        ]

        # Pre-generate columns sized to full width
        self.columns: List[dict] = [
            {
                "y": float(random.randint(-self.height, 0)),
                "speed": random.uniform(0.8, 1.2),
                "chars": [random.choice(self.chars) for _ in range(20)],
            }
            for _ in range(self.width)
        ]

    def run(self, duration: float = 3.0) -> None:
        """Run matrix rain for given duration (seconds)."""
        if duration < 0.3:
            self._final_reveal()
            return

        # refresh size at start of run, rebuild columns if needed
        size = shutil.get_terminal_size()
        if size.columns != self.width or size.lines != self.height:
            self.width = size.columns
            self.height = size.lines
            self.columns = [
                {
                    "y": float(random.randint(-self.height, 0)),
                    "speed": random.uniform(0.8, 1.2),
                    "chars": [random.choice(self.chars) for _ in range(20)],
                }
                for _ in range(self.width)
            ]

        frames: int = max(int(duration * 20), 20)  # 20fps
        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            for frame in range(frames):
                lines: List[Text] = []
                for y in range(self.height):
                    line = Text()
                    for x in range(self.width):
                        col = self.columns[x]
                        char_y = int(col["y"])
                        if char_y == y:
                            line.append(col["chars"][frame % 20], "bold magenta")
                        elif char_y - 3 < y < char_y:
                            line.append(col["chars"][(frame + y) % 20], "bold cyan")
                        else:
                            line.append(" ")
                    lines.append(line)

                # Update positions
                for col in self.columns:
                    col["y"] += col["speed"]
                    if col["y"] > self.height:
                        col["y"] = float(random.randint(-15, -5))

                # Logo in final frames
                if frame > frames - 20:
                    logo_y = (self.height - len(self.logo)) // 2
                    for i, logo_line in enumerate(self.logo):
                        if 0 <= logo_y + i < len(lines):
                            lines[logo_y + i] = Text.from_markup(
                                logo_line.center(self.width), style="bold magenta"
                            )

                live.update(
                    Panel(
                        Group(*lines), 
                        border_style="cyan",
                        box=box.SIMPLE,
                    )
                )
                time.sleep(1 / 20)

        self._final_reveal()

        

    def _final_reveal(self) -> None:
        """Glitch + logo reveal, then clear terminal."""
        self.console.clear()

        import shutil
        self.width = shutil.get_terminal_size().columns

        # Render logo line-by-line, preserving spacing and fidelity
        for line in self.logo:
            self.console.print(Text(line.center(self.width), style="bold magenta"))


        self.console.print("\n[bold cyan]► PRESS ENTER TO BEGIN ◄[/]", justify="center")
        try:
            input()
        except Exception:
            pass

        self.console.clear()












class CyberpunkSQLEditor:
    """Interactive SQL query editor."""

    def __init__(self) -> None:
        self.console: Console = Console()

    def get_queries(self) -> Optional[str]:
        """
        Interactive query composition loop.

        Returns:
            Concatenated SQL queries or None if cancelled
        """
        self.console.clear()
        self._show_header()

        queries: List[str] = []
        self.console.print(
            "\n[bold magenta]╔══ QUERY COMPOSITION ═════════════════════════╗[/]"
        )

        while True:
            line_num: int = len(queries) + 1
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

        self.console.print(
            "[bold magenta]╚══════════════════════════════════════════════╝[/]"
        )
        self._show_query_summary(queries)

        return "\n".join(queries)

    def _show_header(self) -> None:
        header_lines: List[str] = [
            "[bold cyan]╔═══════════════════════════════════════════════╗[/]",
            "[bold cyan]║[/]  [bold magenta]◆ SLOWQL QUERY TERMINAL v2.0 ◆[/]  [bold cyan]║[/]",
            "[bold cyan]╚═══════════════════════════════════════════════╝[/]",
        ]

        for line in header_lines:
            self.console.print(Align.center(line))
            time.sleep(0.1)

    def _show_query_preview(self, query: str) -> None:
        syntax = Syntax(query, "sql", theme="monokai", line_numbers=False)
        self.console.print(Panel(syntax, border_style="dim cyan", box=box.MINIMAL))

    def _show_query_summary(self, queries: List[str]) -> None:
        valid_queries: List[str] = [q for q in queries if q.strip()]
        if valid_queries:
            self.console.print(
                f"\n[bold green]◆ QUERIES CAPTURED: {len(valid_queries)}[/]"
            )
            time.sleep(1)


class AnimatedAnalyzer:
    """Animated SQL analysis results with cyberpunk effects."""

    def __init__(self) -> None:
        self.console: Console = Console()
        self.gradient_colors: List[str] = [
            "magenta",
            "hot_pink",
            "deep_pink4",
            "medium_purple",
            "cyan",
        ]

    def glitch_transition(self, duration: float = 0.2) -> None:
        """Glitch effect between sections."""
        chars: str = "░▒▓█▀▄━│─╱╲"
        for _ in range(int(duration * 10)):
            glitch_line: str = "".join(random.choice(chars) for _ in range(80))
            self.console.print(
                f"[{random.choice(self.gradient_colors)}]{glitch_line}[/]", end="\r"
            )
            time.sleep(0.02)
        self.console.print(" " * 80, end="\r")

    def particle_loading(self, message: str = "PROCESSING") -> None:
        """Particle effect loading animation."""
        particles: List[str] = ["◢", "◣", "◤", "◥", "◆", "◈", "▰", "▱"]
        with Live(console=self.console, refresh_per_second=30) as live:
            for _ in range(30):
                particle_field: List[str] = []
                for _ in range(5):
                    line: str = " ".join(random.choice(particles) for _ in range(20))
                    particle_field.append(
                        f"[{random.choice(self.gradient_colors)}]{line}[/]"
                    )

                live.update(
                    Panel(
                        "\n".join(particle_field),
                        title=f"[bold white blink]◢ {message} ◣[/]",
                        border_style="cyan",
                    )
                )
                time.sleep(0.03)

    def reveal_section(self, content: str, title: str = "", style: str = "cyan") -> None:
        """
        Smooth reveal with gradient animation.

        Args:
            content: Text content to display
            title: Optional panel title
            style: Border style color
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

        Args:
            summary: Summary text
            details: Detailed text
            expanded: Whether to show details immediately
        """
        if not expanded:
            self.console.print(
                Panel(
                    summary + "\n\n[dim cyan]▼ Press ENTER to expand details ▼[/]",
                    border_style="cyan",
                )
            )
            try:
                input()
            except Exception:
                pass
            self.glitch_transition()

        # Show expanded details with animation
        self.reveal_section(details, title="◢ DETAILED ANALYSIS ◣")


# -------------------------------
# Main execution flow
# -------------------------------

def run_slowql() -> None:
    """
    Complete SlowQL experience with animations.

    Runs MatrixRain intro, interactive SQL editor,
    and animated analyzer demo.
    """
    console: Console = Console()

    # 1. Matrix intro
    matrix = MatrixRain()
    matrix.run(duration=3)

    # 2. Get SQL queries
    editor = CyberpunkSQLEditor()
    sql_queries: Optional[str] = editor.get_queries()

    if not sql_queries:
        console.print("[bold red]◆ ANALYSIS CANCELLED[/]")
        return

    # 3. Animated analysis
    analyzer = AnimatedAnalyzer()

    # Loading animation
    analyzer.particle_loading("ANALYZING QUERIES")

    # 4. Show results with animations
    # (This is where you'd integrate with your actual analysis)
    analyzer.glitch_transition()

    results_summary: str = """[bold cyan]◆ ANALYSIS COMPLETE ◆[/]

[green]✓[/] 14 optimization opportunities detected
[yellow]![/] 3 critical issues found
[cyan]→[/] Performance improvement potential: 78%"""

    results_details: str = """[bold magenta]CRITICAL ISSUES:[/]
• Missing WHERE in UPDATE/DELETE statements
• Cartesian product detected
• NULL comparison errors

[bold cyan]OPTIMIZATIONS:[/]
• Replace SELECT * with specific columns
• Add proper indexing strategies
• Optimize JOIN conditions"""

    analyzer.show_expandable_details(results_summary, results_details)

    console.print("\n[bold cyan]◆ ANALYSIS COMPLETE ◆[/]")


if __name__ == "__main__":
    run_slowql()
