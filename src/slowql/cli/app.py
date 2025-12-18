# slowql/src/slowql/cli/app.py
"""
SLOWQL Enhanced CLI Entry Point

Advanced command-line interface with:
- Interactive analysis loop (continue or quit)
- Query history management
- Session statistics
- Smart suggestions
- Enhanced UX with progress indicators
- Comparison mode
- Auto-fix suggestions
"""

import argparse
import contextlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

try:
    import readchar  # cross-platform single-key reader

    HAVE_READCHAR = True
except ImportError:
    HAVE_READCHAR = False
from slowql.cli.ui.animations import AnimatedAnalyzer, CyberpunkSQLEditor, MatrixRain
from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.models import AnalysisResult, Severity
from slowql.reporters.console import ConsoleReporter
from slowql.reporters.json_reporter import CSVReporter, HTMLReporter, JSONReporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("slowql")

console = Console()


class SessionManager:
    """Manages analysis session state and history"""

    def __init__(self) -> None:
        self.queries_analyzed = 0
        self.total_issues = 0
        self.session_start = datetime.now()
        self.history: list[dict[str, Any]] = []
        self.severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def add_analysis(self, result: AnalysisResult) -> None:
        """Record an analysis run"""
        self.queries_analyzed += len(result.queries)
        self.total_issues += len(result.issues)

        # Update severity breakdown
        stats = result.statistics.by_severity
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            self.severity_breakdown[sev.value] += stats.get(sev, 0)

        self.history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "queries": len(result.queries),
                "issues": len(result.issues),
                "issues_data": [i.to_dict() for i in result.issues],
            }
        )

    def get_session_duration(self) -> str:
        """Get formatted session duration"""
        delta = datetime.now() - self.session_start
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    def display_summary(self) -> None:
        """Display session summary"""
        table = Table(title="📊 Session Summary", box=box.ROUNDED, border_style="cyan")
        table.add_column("Metric", style="cyan bold")
        table.add_column("Value", style="green")

        table.add_row("Duration", self.get_session_duration())
        table.add_row("Queries Analyzed", str(self.queries_analyzed))
        table.add_row("Total Issues Found", str(self.total_issues))
        table.add_row("Critical Issues", str(self.severity_breakdown["critical"]))
        table.add_row("High Issues", str(self.severity_breakdown["high"]))
        table.add_row("Medium Issues", str(self.severity_breakdown["medium"]))
        table.add_row("Low Issues", str(self.severity_breakdown["low"]))
        table.add_row("Analysis Runs", str(len(self.history)))

        console.print(table)

    def export_session(self, filename: Path | None = None) -> Path:
        """Export session history to JSON"""
        if filename is None:
            filename = Path(f"slowql_session_{self.session_start.strftime('%Y%m%d_%H%M%S')}.json")

        session_data = {
            "session_start": self.session_start.isoformat(),
            "session_end": datetime.now().isoformat(),
            "duration": self.get_session_duration(),
            "queries_analyzed": self.queries_analyzed,
            "total_issues": self.total_issues,
            "severity_breakdown": self.severity_breakdown,
            "history": self.history,
        }

        with filename.open("w") as f:
            json.dump(session_data, f, indent=2)

        return filename


class QueryCache:
    """Cache for previously analyzed queries"""

    def __init__(self) -> None:
        self.cache: dict[str, AnalysisResult] = {}

    def get(self, query: str) -> AnalysisResult | None:
        """Get cached result"""
        return self.cache.get(self._normalize(query))

    def set(self, query: str, result: AnalysisResult) -> None:
        """Cache a result"""
        self.cache[self._normalize(query)] = result

    def _normalize(self, query: str) -> str:
        """Normalize query for cache key"""
        return " ".join(query.split()).upper()

    def clear(self) -> None:
        """Clear cache"""
        self.cache.clear()


def init_cli() -> None:
    """Initialize CLI logging."""
    logger.info("SlowQL CLI started")


# -------------------------------
# Utility Functions
# -------------------------------


def ensure_reports_dir(path: Path) -> Path:
    """Ensure reports directory exists"""
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_path(path: Path | None) -> Path:
    """Sanitize and validate output directory path"""
    if path is None:
        return Path.cwd() / "reports"

    resolved = path.resolve()
    return resolved


def _run_exports(result: AnalysisResult, formats: list[str], out_dir: Path) -> None:
    """
    Run JSON / HTML / CSV exports for a given AnalysisResult.

    `formats` is a list like ["json", "html", "csv"].
    """
    out_dir = safe_path(out_dir)
    ensure_reports_dir(out_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in formats:
        try:
            if fmt == "json":
                path = out_dir / f"slowql_results_{timestamp}.json"
                with path.open("w", encoding="utf-8") as f:
                    JSONReporter(output_file=f).report(result)
                console.print(f"[green]✓ Exported JSON:[/green] {path}")

            elif fmt == "html":
                path = out_dir / f"slowql_report_{timestamp}.html"
                with path.open("w", encoding="utf-8") as f:
                    HTMLReporter(output_file=f).report(result)
                console.print(f"[green]✓ Exported HTML:[/green] {path}")

            elif fmt == "csv":
                path = out_dir / f"slowql_report_{timestamp}.csv"
                with path.open("w", encoding="utf-8", newline="") as f:
                    CSVReporter(output_file=f).report(result)
                console.print(f"[green]✓ Exported CSV:[/green] {path}")

        except Exception as e:
            console.print(f"[red]✗ Failed to export {fmt}:[/red] {e}")


def show_quick_actions_menu(
    result: AnalysisResult, _export_formats: list[str] | None, out_dir: Path
) -> bool:
    """
    Arrow-key Quick Actions menu (inline, not full-screen).
    - ↑/↓ to move, Enter to select, q/Esc to exit.
    - Options: Export Report • Analyze More Queries • Exit
    Returns:
      True  -> analyze more queries
      False -> exit
    """
    items: list[tuple[str, str]] = [
        ("💾 Export Report", "export"),
        ("🔄 Analyze More Queries", "continue"),
        ("❌ Exit", "exit"),
    ]
    index = 0  # current selection

    def render_menu() -> Panel:
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            expand=True,
            border_style="cyan",
            header_style="bold white on rgb(24,24,40)",
        )
        table.add_column("Action", no_wrap=True)

        for i, (label, _) in enumerate(items):
            pointer = "▸" if i == index else " "
            style = "bold deep_sky_blue1" if i == index else "white"
            table.add_row(f"[{style}]{pointer} {label}[/]")

        footer = "[dim]↑/↓ move • Enter select • q exit[/]"
        return Panel(
            table,
            title="[bold cyan]Quick Actions[/]",
            border_style="cyan",
            box=box.ROUNDED,
            subtitle=footer,
            subtitle_align="center",
        )

    # Fallback to numeric prompt if readchar isn't available
    if not HAVE_READCHAR or not sys.stdin.isatty():
        console.print(render_menu())
        choice = Prompt.ask("Select", choices=["1", "2", "3"], default="2")
        action = items[int(choice) - 1][1]
        if action == "export":
            export_interactive(result, out_dir)
            return True
        return action == "continue"

    # Interactive loop with inline re-rendering
    while True:
        selected_action: str | None = None
        # Render the menu and capture a single choice
        with Live(render_menu(), refresh_per_second=30, console=console, transient=True) as live:
            while True:
                key = readchar.readkey()
                if key == readchar.key.UP:
                    index = (index - 1) % len(items)
                    live.update(render_menu())
                elif key == readchar.key.DOWN:
                    index = (index + 1) % len(items)
                    live.update(render_menu())
                elif key in (readchar.key.ENTER, "\r", "\n"):
                    selected_action = items[index][1]
                    break
                elif key in ("q", "Q", readchar.key.ESC):
                    selected_action = "exit"
                    break

        # Handle the selected action outside Live (so output isn't garbled)
        if selected_action == "export":
            export_interactive(result, out_dir)
            # After exporting, return to the menu with "Analyze More Queries" preselected
            index = 1
            continue
        return selected_action == "continue"


def export_interactive(result: AnalysisResult, out_dir: Path) -> None:
    """
    Arrow-key Export Options menu (inline).
    - ↑/↓ to move, Enter to select, q/Esc to cancel.
    - Options: JSON • HTML • CSV • All
    """
    options: list[tuple[str, list[str]]] = [
        ("📄 JSON", ["json"]),
        ("🌐 HTML", ["html"]),
        ("📑 CSV", ["csv"]),
        ("🧰 All (JSON + HTML + CSV)", ["json", "html", "csv"]),
    ]
    index = 0

    def render_menu() -> Panel:
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            expand=True,
            border_style="cyan",
            header_style="bold white on rgb(24,24,40)",
        )
        table.add_column("Format", no_wrap=True)

        for i, (label, _) in enumerate(options):
            pointer = "▸" if i == index else " "
            style = "bold deep_sky_blue1" if i == index else "white"
            table.add_row(f"[{style}]{pointer} {label}[/]")

        footer = "[dim]↑/↓ move • Enter select • q cancel[/]"
        return Panel(
            table,
            title="[bold cyan]Export Options[/]",
            border_style="cyan",
            box=box.ROUNDED,
            subtitle=footer,
            subtitle_align="center",
        )

    # Fallback to numeric prompt if readchar isn't available
    if not HAVE_READCHAR or not sys.stdin.isatty():
        console.print(render_menu())
        choice = Prompt.ask("Select format [1/2/3/4]", choices=["1", "2", "3", "4"], default="1")
        _run_exports(result, options[int(choice) - 1][1], out_dir)
        return

    # Interactive single-selection loop (inline and transient)
    selected_formats: list[str] | None = None
    with Live(render_menu(), refresh_per_second=30, console=console, transient=True) as live:
        while True:
            key = readchar.readkey()
            if key == readchar.key.UP:
                index = (index - 1) % len(options)
                live.update(render_menu())
            elif key == readchar.key.DOWN:
                index = (index + 1) % len(options)
                live.update(render_menu())
            elif key in (readchar.key.ENTER, "\r", "\n"):
                selected_formats = options[index][1]
                break
            elif key in ("q", "Q", readchar.key.ESC):
                selected_formats = None
                break

    # Act on selection
    if selected_formats:
        _run_exports(result, selected_formats, out_dir)
    else:
        console.print("[dim]Export cancelled.[/dim]")


def compare_mode(engine: SlowQL) -> None:
    """Interactive query comparison mode"""
    console.print("\n[bold cyan]🔄 Query Comparison Mode[/bold cyan]\n")
    console.print("[yellow]Enter original query (press Enter twice to finish):[/yellow]")

    lines1: list[str] = []
    try:
        while True:
            line = input()
            if not line and lines1 and not lines1[-1]:
                break
            lines1.append(line)
    except EOFError:
        pass

    query1 = "\n".join(lines1).strip()

    console.print("\n[yellow]Enter optimized query (press Enter twice to finish):[/yellow]")

    lines2: list[str] = []
    try:
        while True:
            line = input()
            if not line and lines2 and not lines2[-1]:
                break
            lines2.append(line)
    except EOFError:
        pass

    query2 = "\n".join(lines2).strip()

    if not query1 or not query2:
        console.print("[red]Both queries are required for comparison[/red]")
        return

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        task = progress.add_task("[cyan]Comparing queries...", total=1)
        result1 = engine.analyze(query1)
        result2 = engine.analyze(query2)
        progress.update(task, advance=1)

    issues1 = len(result1.issues)
    issues2 = len(result2.issues)
    improvement = issues1 - issues2
    pct = (improvement / issues1 * 100) if issues1 > 0 else 0

    table = Table(title="📊 Comparison Results", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric", style="cyan bold")
    table.add_column("Value", style="green")

    table.add_row("Original Issues", str(issues1))
    table.add_row("Optimized Issues", str(issues2))
    table.add_row("Issues Resolved", str(improvement))
    table.add_row("Improvement", f"{pct:.1f}%")

    console.print("\n")
    console.print(table)


def _get_sql_input(
    mode: str, is_tty: bool, engine: SlowQL, enable_comparison: bool, first_run: bool
) -> str | None:
    """Handles getting SQL input from the user, either via editor or paste."""
    if enable_comparison and first_run:
        compare_mode(engine)
        return None  # Comparison mode is a one-off action

    chosen_mode = "compose" if mode == "auto" and is_tty else mode

    if chosen_mode == "compose":
        editor = CyberpunkSQLEditor()
        return editor.get_queries() or ""

    console.print(
        "\n[bold cyan]Enter SQL queries[/bold cyan] "
        "(Ctrl+D to finish, 'quit' to exit):"
    )
    lines: list[str] = []
    try:
        while True:
            line = input()
            if line.strip().lower() in ["quit", "exit", "q"]:
                raise KeyboardInterrupt
            if line.strip().lower() == "compare":
                compare_mode(engine)
                continue
            if not line and lines and not lines[-1]:
                break
            lines.append(line)
    except EOFError:
        pass
    return "\n".join(lines).strip()


def _run_analysis(
    sql_payload: str, engine: SlowQL, cache: QueryCache | None, fast: bool
) -> AnalysisResult | None:
    """Runs analysis, using cache if available, with animations."""
    result = None
    if cache:
        result = cache.get(sql_payload)
        if result is not None:
            console.print("[dim]Using cached results...[/dim]")

    if result is None:
        aa = AnimatedAnalyzer()
        with contextlib.suppress(Exception):
            if not fast:
                aa.particle_loading("ANALYZING QUERIES")
                aa.glitch_transition(duration=0.25)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Analyzing...", total=1)
            result = engine.analyze(sql_payload)
            progress.update(task, advance=1)

        if cache and result:
            cache.set(sql_payload, result)

    return result


def _show_intro(intro_enabled: bool, fast: bool, is_tty: bool, intro_duration: float) -> None:
    """Displays the intro animation and welcome banner."""
    if intro_enabled and not fast and is_tty:
        with contextlib.suppress(Exception):
            MatrixRain().run(duration=intro_duration)

    console.print(
        Panel(
            "[bold cyan]Welcome to SlowQL[/bold cyan]\n"
            "The Ultimate SQL Static Analyzer\n\n"
            "[dim]Type 'compare' for comparison mode | 'quit' to exit[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def _handle_sql_input(
    first_run: bool,
    input_file: Path | None,
    non_interactive: bool,
    mode: str,
    is_tty: bool,
    engine: SlowQL,
    enable_comparison: bool,
) -> tuple[str | None, bool]:
    """Get SQL payload from file or user input and update first_run status."""
    sql_payload: str | None = ""
    if input_file and first_run:
        sql_payload = input_file.read_text(encoding="utf-8")
        if not sql_payload.strip():
            console.print("[yellow]Input file is empty[/yellow]")
            return None, True  # Continue loop, but don't process
    else:
        if non_interactive:
            return None, False  # Break loop
        sql_payload = _get_sql_input(mode, is_tty, engine, enable_comparison, first_run)
        if sql_payload is None:  # Special action like 'compare' was run
            return None, False  # Break loop

    return sql_payload, False


def _handle_loop_end(
    non_interactive: bool, result: AnalysisResult, out_dir: Path, session: SessionManager
) -> bool:
    """Handle end-of-loop logic: interactive menu or session summary."""
    if not non_interactive:
        if not show_quick_actions_menu(result, None, out_dir):
            return False  # Break loop
    else:
        console.print("\n")
        session.display_summary()

        if Confirm.ask("\n[cyan]Export session history?[/cyan]", default=False):
            session_file = session.export_session()
            console.print(f"[green]✓ Session exported:[/green] {session_file}")

    return not non_interactive


# -------------------------------
# Core Runner with Loop
# -------------------------------


def run_analysis_loop(
    intro_enabled: bool = True,
    intro_duration: float = 3.0,
    mode: str = "auto",
    initial_input_file: Path | None = None,
    export_formats: list[str] | None = None,
    out_dir: Path | None = None,
    fast: bool = False,
    _verbose: bool = False,
    verbose: bool = False, non_interactive: bool = False,
    enable_cache: bool = True,
    enable_comparison: bool = False,
) -> None:
    """
    Main execution pipeline with interactive loop
    """
    session = SessionManager()
    cache = QueryCache() if enable_cache else None

    # Initialize Engine
    config = Config.find_and_load()
    engine = SlowQL(config=config.with_overrides(output={"verbose": verbose}))
    formatter = ConsoleReporter()
    out_dir = safe_path(out_dir)

    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    _show_intro(intro_enabled, fast, is_tty, intro_duration)

    first_run = True
    input_file = initial_input_file

    # Main analysis loop
    while True:
        try:
            sql_payload: str | None
            sql_payload, should_continue = _handle_sql_input(
                first_run, input_file, non_interactive, mode, is_tty, engine, enable_comparison
            )

            if should_continue:
                input_file = None
                continue
            if sql_payload is None:
                break

            if not sql_payload.strip():
                continue

            first_run = False
            result = _run_analysis(sql_payload, engine, cache, fast)
            if not result:
                continue

            session.add_analysis(result)
            console.print("\n")
            formatter.report(result)

            if export_formats:
                _run_exports(result, export_formats, out_dir)

            if not _handle_loop_end(non_interactive, result, out_dir, session):
                break

        except KeyboardInterrupt:
            console.print("\n[yellow]Analysis interrupted by user[/yellow]")
            break
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
            if not non_interactive:
                if not Confirm.ask("Continue with next analysis?", default=True):
                    break
            else:
                break

    # Final message
    console.print("\n")
    console.print(
        Panel(
            "[bold green]Thank you for using SlowQL![/bold green]\n"
            f"[dim]Analyzed {session.queries_analyzed} queries | "
            f"Found {session.total_issues} issues[/dim]",
            border_style="green",
            box=box.DOUBLE,
        )
    )


# -------------------------------
# Argument Parser
# -------------------------------


def build_argparser() -> argparse.ArgumentParser:
    """Build enhanced argument parser"""
    p = argparse.ArgumentParser(
        prog="slowql",
        description="SLOWQL CLI — The Ultimate SQL Static Analyzer",
        epilog="Examples:\n"
        "  slowql --input-file queries.sql\n"
        "  slowql --mode compose --export html csv\n"
        "  slowql --compare (for query comparison mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Input options
    input_group = p.add_argument_group("Input Options")
    input_group.add_argument(
        "file", nargs="?", type=Path, help="Input SQL file (optional positional)"
    )
    input_group.add_argument("--input-file", type=Path, help="Read SQL from file")
    input_group.add_argument(
        "--mode",
        choices=["auto", "paste", "compose"],
        default="auto",
        help="Editor mode (auto chooses compose on TTY)",
    )

    # Analysis options
    analysis_group = p.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--no-cache", action="store_true", help="Disable query result caching"
    )
    analysis_group.add_argument(
        "--compare", action="store_true", help="Enable query comparison mode"
    )

    # Output options
    output_group = p.add_argument_group("Output Options")
    output_group.add_argument(
        "--export",
        nargs="*",
        choices=["html", "csv", "json"],
        help="Auto-export formats after each analysis",
    )
    output_group.add_argument(
        "--out", type=Path, default=Path.cwd() / "reports", help="Output directory for exports"
    )
    output_group.add_argument(
        "--verbose", action="store_true", help="Enable verbose analyzer output"
    )

    # UI options
    ui_group = p.add_argument_group("UI Options")
    ui_group.add_argument("--no-intro", action="store_true", help="Skip intro animation")
    ui_group.add_argument("--fast", action="store_true", help="Fast mode: minimal animations")
    ui_group.add_argument(
        "--duration", type=float, default=3.0, help="Intro animation duration (seconds)"
    )
    ui_group.add_argument(
        "--non-interactive", action="store_true", help="Non-interactive mode for CI/CD"
    )

    return p


# -------------------------------
# Entry Point
# -------------------------------


def main(argv: list[str] | None = None) -> None:
    """
    Enhanced CLI entry point with analysis loop
    """
    init_cli()
    parser = build_argparser()
    args = parser.parse_args(argv)

    # Handle positional file arg compatibility
    input_file = args.file or args.input_file

    # Run analysis loop
    run_analysis_loop(
        intro_enabled=not args.no_intro,
        intro_duration=args.duration,
        mode=args.mode,
        initial_input_file=input_file,
        export_formats=args.export,
        out_dir=args.out,
        fast=args.fast,
        verbose=args.verbose,
        non_interactive=args.non_interactive,
        enable_cache=not args.no_cache,
        enable_comparison=args.compare,
    )


if __name__ == "__main__":
    main()
