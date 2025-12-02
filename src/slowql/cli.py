"""
SLOWQL CLI Entry Point

This module provides the command-line interface for SLOWQL,
including argument parsing, interactive editor, animations,
and execution pipeline.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

import pandas as pd
from rich.console import Console

from slowql.effects.animations import MatrixRain, CyberpunkSQLEditor, AnimatedAnalyzer
from slowql.core.analyzer import QueryAnalyzer
from slowql.formatters.console import ConsoleFormatter

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("slowql")

def main():
    logger.info("SlowQL CLI started")


console: Console = Console()


# -------------------------------
# Utility Functions
# -------------------------------

def sql_split_statements(sql: str) -> List[str]:
    """
    Split SQL payload into individual statements, respecting quotes and comments.

    Args:
        sql: Raw SQL string

    Returns:
        List of SQL statements
    """
    if not sql:
        return []
    parts: List[str] = []
    cur: List[str] = []
    in_squote, in_dquote, escape = False, False, False
    for ch in sql:
        if ch == "\\" and not escape:
            escape = True
            cur.append(ch)
            continue
        if ch == "'" and not escape and not in_dquote:
            in_squote = not in_squote
        elif ch == '"' and not escape and not in_squote:
            in_dquote = not in_dquote
        if ch == ";" and not in_squote and not in_dquote:
            stmt = "".join(cur).strip()
            if stmt:
                parts.append(stmt)
            cur = []
        else:
            cur.append(ch)
        escape = False
    trailing = "".join(cur).strip()
    if trailing:
        parts.append(trailing)
    return parts


def ensure_reports_dir(path: Path) -> Path:
    """
    Ensure reports directory exists.

    Args:
        path: Path to reports directory

    Returns:
        Path object (ensured to exist)
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


# -------------------------------
# Core Runner
# -------------------------------

def run(
    intro_enabled: bool = True,
    intro_duration: float = 3.0,
    mode: str = "auto",
    input_file: Optional[Path] = None,
    export_formats: Optional[List[str]] = None,
    out_dir: Optional[Path] = None,
    fast: bool = False,
    verbose: bool = False,
    non_interactive: bool = False,
    parallel: bool = False,
    workers: Optional[int] = None,
) -> None:
    """
    Main execution pipeline for SLOWQL CLI.

    Args:
        intro_enabled: Whether to show intro animation
        intro_duration: Duration of intro animation
        mode: Editor mode ("auto", "paste", "compose")
        input_file: Optional SQL input file
        export_formats: Optional list of export formats
        out_dir: Optional output directory
        fast: Fast mode (reduced animations)
        verbose: Verbose analyzer output
        non_interactive: Non-interactive mode (CI)
        parallel: Enable parallel analysis
        workers: Number of worker processes
    """
    # Decide interactive default
    is_tty: bool = sys.stdin.isatty() and sys.stdout.isatty()
    chosen_mode: str = (
        "compose"
        if mode == "auto" and is_tty and not non_interactive and input_file is None
        else mode
    )

    # 1) Intro animation
    try:
        if intro_enabled and not fast:
            MatrixRain().run(duration=intro_duration)
        elif intro_enabled and fast:
            MatrixRain().run(duration=0.5)
    except Exception:
        pass

    # 2) Input handling
    sql_payload: str = ""
    if input_file:
        sql_payload = input_file.read_text(encoding="utf-8")
        if not sql_payload.strip():
            console.print("[bold yellow]Input file is empty. Exiting.[/]")
            return
    else:
        if chosen_mode == "compose" and not non_interactive:
            editor = CyberpunkSQLEditor()
            sql_payload = editor.get_queries() or ""
            if not sql_payload.strip():
                console.print("[bold yellow]No queries entered. Exiting.[/]")
                return
        else:
            if non_interactive:
                console.print(
                    "[bold yellow]Non-interactive mode: expecting input via --input-file or piped stdin[/]"
                )
                return
            console.print(
                "[bold cyan]Paste your SQL statements. End input with Ctrl+D (EOF) or two blank lines.[/]"
            )
            lines: List[str] = []
            try:
                while True:
                    line: str = input()
                    if not line and lines and not lines[-1]:
                        break
                    lines.append(line)
            except EOFError:
                pass
            sql_payload = "\n".join(lines).strip()
            if not sql_payload:
                console.print("[bold yellow]No SQL provided. Exiting.[/]")
                return

    # 3) Split into statements
    statements: List[str] = sql_split_statements(sql_payload)

    # 4) Animated analysis intro
    aa = AnimatedAnalyzer()
    try:
        if not fast:
            aa.particle_loading("ANALYZING QUERIES")
            aa.glitch_transition(duration=0.25)
        else:
            aa.glitch_transition(duration=0.05)
    except Exception:
        pass

    # 5) Run analyzer (parallel or sequential)
    analyzer = QueryAnalyzer(verbose=verbose)
    results_df: pd.DataFrame
    if parallel:
        results_df = analyzer.analyze_parallel(statements, return_dataframe=True, workers=workers)
    else:
        results_df = analyzer.analyze(statements, return_dataframe=True)

    # 6) Render formatted report
    formatter = ConsoleFormatter()
    formatter.format_analysis(results_df, title="SLOWQL Analysis")

    # 7) Animated summary
    try:
        summary: str = (
            f"[bold cyan]◆ ANALYSIS COMPLETE ◆[/]\n\n"
            f"[green]✓[/] {results_df['count'].sum() if 'count' in results_df else len(results_df)} issues detected"
        )
        details_lines: List[str] = []
        if not results_df.empty:
            for _, row in results_df.iterrows():
                details_lines.append(f"{row['issue']} [{row.get('count',1)}] - {row['impact']}")
        details: str = "\n".join(details_lines) or "[dim]No details available[/]"
        if not fast:
            aa.show_expandable_details(summary, details, expanded=False)
    except Exception:
        pass

    # 8) Export if requested
    if export_formats:
        out_dir = Path(out_dir) if out_dir else Path.cwd() / "reports"
        ensure_reports_dir(out_dir)
        for fmt in export_formats:
            fmt_lower: str = fmt.lower()
            try:
                if fmt_lower == "html":
                    out_path: Path = out_dir / f"slowql_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.html"
                    formatter.export_html_report(results_df, filename=str(out_path))
                    console.print(f"[bold green]Exported HTML report:[/] {out_path}")
                else:
                    exported_filename: str = analyzer.export_report(
                        results_df,
                        format=fmt_lower,
                        filename=str(out_dir / f"slowql_results_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.{fmt_lower}")
                    )
                    console.print(f"[bold green]Exported {fmt_lower}:[/] {exported_filename}")
            except Exception as e:
                console.print(f"[bold red]Failed to export {fmt}:[/] {e}")

    # 9) Final flourish
    try:
        if not fast:
            aa.glitch_transition(duration=0.35)
    except Exception:
        pass


# -------------------------------
# Argument Parser
# -------------------------------

def build_argparser() -> argparse.ArgumentParser:
    """
    Build argument parser for CLI.

    Returns:
        Configured ArgumentParser
    """
    p = argparse.ArgumentParser(
        prog="slowql",
        description="SLOWQL CLI — cyberpunk SQL static analyzer"
    )
    p.add_argument("--no-intro", dest="no_intro", action="store_true", help="Skip intro animation")
    p.add_argument("--fast", action="store_true", help="Fast mode: reduce animations and blocking prompts")
    p.add_argument("--parallel", action="store_true", help="Enable parallel query analysis across CPU cores")
    p.add_argument("--workers", type=int, help="Number of worker processes for parallel mode")
    p.add_argument("--input-file", type=Path, help="Read SQL from file")
    p.add_argument("--mode", choices=["auto", "paste", "compose"], default="auto", help="Editor mode (auto chooses compose on TTY)")
    p.add_argument("--export", nargs="*", choices=["html", "csv", "json"], help="Export formats")
    p.add_argument("--out", type=Path, default=Path.cwd() / "reports", help="Output directory for exports")
    p.add_argument("--duration", type=float, default=3.0, help="Intro duration seconds")
    p.add_argument("--verbose", action="store_true", help="Enable analyzer verbose output")
    p.add_argument("--non-interactive", action="store_true", help="Non-interactive mode (CI)")
    p.add_argument(
        "--help-art",
        "--help-visual",
        dest="help_art",
        action="store_true",
        help="Show animated cinematic help (TTY only)"
    )
    return p


# -------------------------------
# Entry Point
# -------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    """
    CLI entry point for SLOWQL.

    Args:
        argv: Optional list of command-line arguments
    """
    parser: argparse.ArgumentParser = build_argparser()
    args = parser.parse_args(argv)

    # Animated visual help
    if getattr(args, "help_art", False):
        from slowql.cli_help import show_animated_help
        show_animated_help(
            fast=args.fast,
            non_interactive=args.non_interactive,
            duration=args.duration
        )
        return

    run(
        intro_enabled=not args.no_intro,
        intro_duration=args.duration,
        mode=args.mode,
        input_file=args.input_file,
        export_formats=args.export,
        out_dir=args.out,
        fast=args.fast,
        verbose=args.verbose,
        non_interactive=args.non_interactive,
        parallel=args.parallel,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
