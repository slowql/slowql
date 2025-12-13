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
import logging
import sys
import json
from pathlib import Path
from typing import Optional, Any, List, Dict, Callable, Tuple
from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import box
from rich.live import Live

from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.models import AnalysisResult, Severity
from slowql.reporters.console import ConsoleReporter
from slowql.reporters.json_reporter import JSONReporter, HTMLReporter, CSVReporter
from slowql.cli.ui.animations import AnimatedAnalyzer, CyberpunkSQLEditor, MatrixRain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("slowql")

console = Console()


class SessionManager:
    """Manages analysis session state and history"""
    
    def __init__(self):
        self.queries_analyzed = 0
        self.total_issues = 0
        self.session_start = datetime.now()
        self.history: List[dict[str, Any]] = []
        self.severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
    def add_analysis(self, result: AnalysisResult):
        """Record an analysis run"""
        self.queries_analyzed += len(result.queries)
        self.total_issues += len(result.issues)
        
        # Update severity breakdown
        stats = result.statistics.by_severity
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            self.severity_breakdown[sev.value] += stats.get(sev, 0)
        
        self.history.append({
            'timestamp': datetime.now().isoformat(),
            'queries': len(result.queries),
            'issues': len(result.issues),
            'issues_data': [i.to_dict() for i in result.issues]
        })
    
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
    
    def display_summary(self):
        """Display session summary"""
        table = Table(title="📊 Session Summary", box=box.ROUNDED, border_style="cyan")
        table.add_column("Metric", style="cyan bold")
        table.add_column("Value", style="green")
        
        table.add_row("Duration", self.get_session_duration())
        table.add_row("Queries Analyzed", str(self.queries_analyzed))
        table.add_row("Total Issues Found", str(self.total_issues))
        table.add_row("Critical Issues", str(self.severity_breakdown['critical']))
        table.add_row("High Issues", str(self.severity_breakdown['high']))
        table.add_row("Medium Issues", str(self.severity_breakdown['medium']))
        table.add_row("Low Issues", str(self.severity_breakdown['low']))
        table.add_row("Analysis Runs", str(len(self.history)))
        
        console.print(table)
    
    def export_session(self, filename: Optional[Path] = None) -> Path:
        """Export session history to JSON"""
        if filename is None:
            filename = Path(f"slowql_session_{self.session_start.strftime('%Y%m%d_%H%M%S')}.json")
        
        session_data = {
            'session_start': self.session_start.isoformat(),
            'session_end': datetime.now().isoformat(),
            'duration': self.get_session_duration(),
            'queries_analyzed': self.queries_analyzed,
            'total_issues': self.total_issues,
            'severity_breakdown': self.severity_breakdown,
            'history': self.history
        }
        
        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        return filename


class QueryCache:
    """Cache for previously analyzed queries"""
    
    def __init__(self):
        self.cache: dict[str, AnalysisResult] = {}
    
    def get(self, query: str) -> Optional[AnalysisResult]:
        """Get cached result"""
        return self.cache.get(self._normalize(query))
    
    def set(self, query: str, result: AnalysisResult):
        """Cache a result"""
        self.cache[self._normalize(query)] = result
    
    def _normalize(self, query: str) -> str:
        """Normalize query for cache key"""
        return ' '.join(query.split()).upper()
    
    def clear(self):
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


def safe_path(path: Optional[Path]) -> Path:
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

        except Exception as e:  # noqa: BLE001
            console.print(f"[red]✗ Failed to export {fmt}:[/red] {e}")



def show_quick_actions_menu(result: AnalysisResult, export_formats: Optional[list[str]], out_dir: Path) -> bool:
    """
    Arrow-key Quick Actions menu (inline, not full-screen).
    - ↑/↓ to move, Enter to select, q/Esc to exit.
    - Options: Export Report • Analyze More Queries • Exit
    Returns:
      True  -> analyze more queries
      False -> exit
    """
    try:
        import readchar  # cross-platform single-key reader
        HAVE_READCHAR = True
    except Exception:
        HAVE_READCHAR = False

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
    if not HAVE_READCHAR:
        console.print(render_menu())
        choice = Prompt.ask("Select", choices=["1", "2", "3"], default="2")
        action = items[int(choice) - 1][1]
        if action == "export":
            export_interactive(result, out_dir)
            return True
        return action == "continue"

    # Interactive loop with inline re-rendering
    while True:
        selected_action: Optional[str] = None
        # Render the menu and capture a single choice
        from rich.live import Live
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
        elif selected_action == "continue":
            return True
        else:  # "exit" or None
            return False

def export_interactive(result: AnalysisResult, out_dir: Path) -> None:
    """
    Arrow-key Export Options menu (inline).
    - ↑/↓ to move, Enter to select, q/Esc to cancel.
    - Options: JSON • HTML • CSV • All
    """
    try:
        import readchar
        HAVE_READCHAR = True
    except Exception:
        HAVE_READCHAR = False

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
    if not HAVE_READCHAR:
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


def compare_mode(engine: SlowQL):
    """Interactive query comparison mode"""
    console.print("\n[bold cyan]🔄 Query Comparison Mode[/bold cyan]\n")
    console.print("[yellow]Enter original query (press Enter twice to finish):[/yellow]")
    
    lines1 = []
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
    
    lines2 = []
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
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
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


# -------------------------------
# Core Runner with Loop
# -------------------------------

def run_analysis_loop(
    intro_enabled: bool = True,
    intro_duration: float = 3.0,
    mode: str = "auto",
    initial_input_file: Optional[Path] = None,
    export_formats: Optional[list[str]] = None,
    out_dir: Optional[Path] = None,
    fast: bool = False,
    verbose: bool = False,
    non_interactive: bool = False,
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
    engine = SlowQL(config=config)
    formatter = ConsoleReporter()
    out_dir = safe_path(out_dir)
    
    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    
    # Show intro only once
    # Now includes the new Matrix Rain + Feature Overview + Logo Reveal
    if intro_enabled and not fast and is_tty:
        try:
            MatrixRain().run(duration=intro_duration)
        except Exception:
            pass
    
    # Welcome message (Appears after the matrix clears)
    console.print(Panel(
        "[bold cyan]Welcome to SlowQL[/bold cyan]\n"
        "The Ultimate SQL Static Analyzer\n\n"
        "[dim]Type 'compare' for comparison mode | 'quit' to exit[/dim]",
        border_style="cyan",
        box=box.DOUBLE
    ))
    
    first_run = True
    input_file = initial_input_file
    
    # Main analysis loop
    while True:
        try:
            # Get SQL input
            sql_payload = ""
            
            if input_file and first_run:
                sql_payload = input_file.read_text(encoding="utf-8")
                if not sql_payload.strip():
                    console.print("[yellow]Input file is empty[/yellow]")
                    input_file = None
                    continue
            else:
                # Interactive input
                if non_interactive:
                    break
                
                # Comparison mode check via argument
                if enable_comparison and first_run:
                    compare_mode(engine)
                    break

                chosen_mode = (
                    "compose" if mode == "auto" and is_tty else mode
                )
                
                if chosen_mode == "compose":
                    # Uses the updated CyberpunkSQLEditor with full-width headers
                    editor = CyberpunkSQLEditor()
                    sql_payload = editor.get_queries() or ""
                else:
                    console.print("\n[bold cyan]Enter SQL queries[/bold cyan] (Ctrl+D to finish, 'quit' to exit):")
                    lines = []
                    try:
                        while True:
                            line = input()
                            if line.strip().lower() in ['quit', 'exit', 'q']:
                                raise KeyboardInterrupt
                            if line.strip().lower() == 'compare':
                                compare_mode(engine)
                                continue
                            if not line and lines and not lines[-1]:
                                break
                            lines.append(line)
                    except EOFError:
                        pass
                    sql_payload = "\n".join(lines).strip()
            
            if not sql_payload.strip():
                if non_interactive:
                    break
                continue
            
            first_run = False
            
            # Check cache
            result = None
            if cache:
                result = cache.get(sql_payload)
                if result is not None:
                    console.print("[dim]Using cached results...[/dim]")
            
            if not result:
                # Animated loading using the updated AnimatedAnalyzer
                aa = AnimatedAnalyzer()
                try:
                    if not fast:
                        aa.particle_loading("ANALYZING QUERIES")
                        aa.glitch_transition(duration=0.25)
                except Exception:
                    pass
                
                # Run analysis
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(f"[cyan]Analyzing...", total=1)
                    result = engine.analyze(sql_payload)
                    progress.update(task, advance=1)
                
                # Cache result
                if cache:
                    cache.set(sql_payload, result)
            
            # Update session
            session.add_analysis(result)
            
            # Display results
            console.print("\n")
            formatter.report(result)
            
            # Interactive prompt
            if not non_interactive:
                continue_analysis = show_quick_actions_menu(
                    result,
                    export_formats,
                    out_dir
                )
                if not continue_analysis:
                    break
            else:
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
    
    # Session summary
    if not non_interactive and session.queries_analyzed > 0:
        console.print("\n")
        session.display_summary()
        
        if Confirm.ask("\n[cyan]Export session history?[/cyan]", default=False):
            session_file = session.export_session()
            console.print(f"[green]✓ Session exported:[/green] {session_file}")
    
    # Final message
    console.print("\n")
    console.print(Panel(
        "[bold green]Thank you for using SlowQL![/bold green]\n"
        f"[dim]Analyzed {session.queries_analyzed} queries | Found {session.total_issues} issues[/dim]",
        border_style="green",
        box=box.DOUBLE
    ))


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
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input options
    input_group = p.add_argument_group('Input Options')
    input_group.add_argument("file", nargs="?", type=Path, help="Input SQL file (optional positional)")
    input_group.add_argument("--input-file", type=Path, help="Read SQL from file")
    input_group.add_argument("--mode", choices=["auto", "paste", "compose"], 
                            default="auto", help="Editor mode (auto chooses compose on TTY)")
    
    # Analysis options
    analysis_group = p.add_argument_group('Analysis Options')
    analysis_group.add_argument("--no-cache", action="store_true",
                               help="Disable query result caching")
    analysis_group.add_argument("--compare", action="store_true",
                               help="Enable query comparison mode")
    
    # Output options
    output_group = p.add_argument_group('Output Options')
    output_group.add_argument("--export", nargs="*", choices=["html", "csv", "json"],
                             help="Auto-export formats after each analysis")
    output_group.add_argument("--out", type=Path, default=Path.cwd() / "reports",
                             help="Output directory for exports")
    output_group.add_argument("--verbose", action="store_true",
                             help="Enable verbose analyzer output")
    
    # UI options
    ui_group = p.add_argument_group('UI Options')
    ui_group.add_argument("--no-intro", action="store_true", help="Skip intro animation")
    ui_group.add_argument("--fast", action="store_true", 
                         help="Fast mode: minimal animations")
    ui_group.add_argument("--duration", type=float, default=3.0,
                         help="Intro animation duration (seconds)")
    ui_group.add_argument("--non-interactive", action="store_true",
                         help="Non-interactive mode for CI/CD")
    
    return p


# -------------------------------
# Entry Point
# -------------------------------

def main(argv: Optional[list[str]] = None) -> None:
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