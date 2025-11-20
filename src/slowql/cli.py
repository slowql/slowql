# src/slowql/cli.py
import argparse
from pathlib import Path
from typing import List, Optional
import sys
import pandas as pd
from rich.console import Console
from slowql.effects.animations import MatrixRain, CyberpunkSQLEditor, AnimatedAnalyzer
from slowql.core.analyzer import QueryAnalyzer
from slowql.formatters.console import ConsoleFormatter
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
import time
from rich import box


console = Console()

def sql_split_statements(sql: str) -> List[str]:
    if not sql:
        return []
    parts = []
    cur = []
    in_squote = False
    in_dquote = False
    escape = False
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
    path.mkdir(parents=True, exist_ok=True)
    return path

def run(
    intro_enabled: bool = True,
    intro_duration: float = 3.0,
    mode: str = "auto",
    input_file: Optional[Path] = None,
    export_formats: Optional[List[str]] = None,
    out_dir: Optional[Path] = None,
    fast: bool = False,
    verbose: bool = False,
    non_interactive: bool = False
) -> None:
    # Decide interactive default: if TTY and mode auto -> compose (full UI)
    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    chosen_mode = mode
    if mode == "auto":
        chosen_mode = "compose" if is_tty and not non_interactive and input_file is None else "paste"

    # 1) Intro (full cinematic unless fast or disabled)
    try:
        if intro_enabled and not fast:
            MatrixRain().run(duration=intro_duration)
        elif intro_enabled and fast:
            MatrixRain().run(duration=0.9)
    except Exception:
        pass

    # 2) Input selection
    sql_payload = ""
    if input_file:
        sql_payload = input_file.read_text(encoding="utf-8")
        if not sql_payload.strip():
            console.print("[bold yellow]Input file is empty. Exiting.[/]")
            return
    else:
        if chosen_mode == "compose" and not non_interactive:
            # Use your full interactive editor (keeps the UI animation and previews)
            editor = CyberpunkSQLEditor()
            sql_payload = editor.get_queries() or ""
            if not sql_payload.strip():
                console.print("[bold yellow]No queries entered. Exiting.[/]")
                return
        else:
            if non_interactive:
                console.print("[bold yellow]Non-interactive mode: expecting input via --input-file or piped stdin[/]")
                return
            console.print("[bold cyan]Paste your SQL statements. End input with Ctrl+D (EOF) or two blank lines.[/]")
            lines = []
            try:
                while True:
                    line = input()
                    if not line and lines and not lines[-1]:
                        break
                    lines.append(line)
            except EOFError:
                pass
            sql_payload = "\n".join(lines).strip()
            if not sql_payload:
                console.print("[bold yellow]No SQL provided. Exiting.[/]")
                return

    # 3) Split into statements robustly
    statements = sql_split_statements(sql_payload)

    # 4) Animated analysis: particle loading (full) then glitch wipe
    aa = AnimatedAnalyzer()
    try:
        if not fast:
            aa.particle_loading("ANALYZING QUERIES")
            aa.glitch_transition(duration=0.25)
        else:
            aa.glitch_transition(duration=0.08)
    except Exception:
        pass

    # 5) Run analyzer
    analyzer = QueryAnalyzer(verbose=verbose)
    results_df = analyzer.analyze(statements, return_dataframe=True)

    # 6) Render formatted report with ConsoleFormatter
    formatter = ConsoleFormatter()
    # Ensure full reveal: use animated reveal_section around key formatter sections if desired
    formatter.format_analysis(results_df, title="SLOWQL Analysis")

    # 7) Show expandable detailed analysis with the AnimatedAnalyzer wrapper
    try:
        # Create brief summary and detailed text for animated expansion (leveraging existing formatter outputs)
        summary = f"[bold cyan]◆ ANALYSIS COMPLETE ◆[/]\n\n[green]✓[/] {results_df['count'].sum() if 'count' in results_df else len(results_df)} issues detected"
        details_lines = []
        if not results_df.empty:
            for _, row in results_df.iterrows():
                details_lines.append(f"{row['issue']} [{row.get('count',1)}] - {row['impact']}")
        details = "\n".join(details_lines) or "[dim]No details available[/]"
        aa.show_expandable_details(summary, details, expanded=False)
    except Exception:
        pass

    # 8) Export if requested
    if export_formats:
        out_dir = Path(out_dir) if out_dir else Path.cwd() / "reports"
        ensure_reports_dir(out_dir)
        for fmt in export_formats:
            fmt_lower = fmt.lower()
            try:
                if fmt_lower == "html":
                    filename = out_dir / f"slowql_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.html"
                    formatter.export_html_report(results_df, filename=str(filename))
                    console.print(f"[bold green]Exported HTML report:[/] {filename}")
                else:
                    filename = analyzer.export_report(results_df, format=fmt_lower,
                                                      filename=str(out_dir / f"slowql_results_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.{fmt_lower}"))
                    console.print(f"[bold green]Exported {fmt_lower}:[/] {filename}")
            except Exception as e:
                console.print(f"[bold red]Failed to export {fmt}:[/] {e}")

    # 9) Final flourish (full glitch)
    try:
        if not fast:
            aa.glitch_transition(duration=0.35)
    except Exception:
        pass

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="slowql", description="SLOWQL CLI — cyberpunk SQL static analyzer")
    p.add_argument("--no-intro", dest="no_intro", action="store_true", help="Skip intro animation")
    p.add_argument("--fast", action="store_true", help="Fast mode: reduce animations and blocking prompts")
    p.add_argument("--input-file", type=Path, help="Read SQL from file")
    p.add_argument("--mode", choices=["auto", "paste", "compose"], default="auto", help="Editor mode (auto chooses compose on TTY)")
    p.add_argument("--export", nargs="*", choices=["html", "csv", "json"], help="Export formats")
    p.add_argument("--out", type=Path, default=Path.cwd() / "reports", help="Output directory for exports")
    p.add_argument("--duration", type=float, default=3.0, help="Intro duration seconds")
    p.add_argument("--verbose", action="store_true", help="Enable analyzer verbose output")
    p.add_argument("--non-interactive", action="store_true", help="Non-interactive mode (CI)")
    p.add_argument("--help-art", "--help-visual", dest="help_art", action="store_true", help="Show animated cinematic help (TTY only)")
    return p

def main(argv: Optional[List[str]] = None) -> None:
    parser = build_argparser()
    args = parser.parse_args(argv)
    run(
        intro_enabled=not args.no_intro,
        intro_duration=args.duration,
        mode=args.mode,
        input_file=args.input_file,
        export_formats=args.export,
        out_dir=args.out,
        fast=args.fast,
        verbose=args.verbose,
        non_interactive=args.non_interactive
    )

def show_animated_help(fast: bool = False, non_interactive: bool = False, duration: float = 3.0) -> None:
    """
    Cinematic visual help. Opt-in only: call with --help-art.
    Uses MatrixRain, AnimatedAnalyzer and ConsoleFormatter aesthetics.
    """
    # Quick TTY safety
    import sys
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        # Non-tty fallback: print standard argparse help
        print("Visual help requires a TTY. Use --help for plain usage.")
        return

    m = MatrixRain()
    aa = AnimatedAnalyzer()
    console = Console()
    formatter = ConsoleFormatter()

    # Durations scaled down in fast mode
    intro_dur = 0.9 if fast else min(max(duration, 1.0), 4.0)
    reveal_delay = 0.06 if fast else 0.12
    particle_seconds = 0.6 if fast else 1.2

    # 1) quick intro (short)
    try:
        m.run(duration=intro_dur)
    except Exception:
        pass

    # 2) Title card
    title = "[bold magenta]SLOWQL[/bold magenta] — [cyan]Cinematic CLI[/cyan]"
    subtitle = "[dim white]Static SQL analysis with cyberpunk aesthetics[/dim white]"
    title_panel = Panel(Align.center(f"{title}\n\n{subtitle}", vertical="middle"),
                        border_style="bold magenta", box=box.DOUBLE, padding=(1, 4))
    console.clear()
    console.print(title_panel)
    time.sleep(reveal_delay * 6)

    # 3) Flags table (animated reveal)
    flags = Table.grid(expand=False)
    flags.add_column("Flag", no_wrap=True, style="bold cyan")
    flags.add_column("Meaning", style="white")

    flags.add_row("--no-intro", "Skip the Matrix intro")
    flags.add_row("--fast", "Shorten animations and prompts")
    flags.add_row("--input-file <path>", "Load SQL from file")
    flags.add_row("--mode {paste,compose}", "Interactive compose or paste mode")
    flags.add_row("--export [html,csv,json]", "Write results to disk")
    flags.add_row("--help-art", "Open this animated help")

    console.print(Panel(flags, title="[bold white]Commands[/]", border_style="cyan", padding=(1,2)))
    time.sleep(reveal_delay * 6)

    # 4) Animated particle reveal while printing short examples
    try:
        with Live(console=console, refresh_per_second=20) as live:
            for i in range(int(particle_seconds * 20)):
                sample_lines = []
                particles = ["◢", "◣", "◤", "◥", "◆", "▰", "▱"]
                for _ in range(3):
                    line = " ".join(random.choice(particles) for _ in range(12))
                    sample_lines.append(f"[magenta]{line}[/]")
                sample_block = "\n".join(sample_lines)
                live.update(Panel(sample_block, title="[bold white]Experience[/]", border_style="medium_purple"))
                time.sleep(0.05)
    except Exception:
        pass

    # 5) Show a small sample formatted report (no analysis call) — craft a small DataFrame
    import pandas as pd
    sample_df = pd.DataFrame([
        {"severity": "critical", "issue": "Missing WHERE in UPDATE/DELETE", "query": "DELETE FROM users", "fix": "Add WHERE", "impact": "Table wipe", "count": 1},
        {"severity": "high", "issue": "Non-SARGable WHERE", "query": "WHERE YEAR(created_at)=2024", "fix": "Use range", "impact": "Full scan", "count": 2},
        {"severity": "medium", "issue": "SELECT * Usage", "query": "SELECT * FROM orders", "fix": "Select columns", "impact": "Extra I/O", "count": 3},
    ])
    console.clear()
    console.print(Panel("[bold cyan]Live Sample[/bold cyan]\n\n[white]How your report will look — staged and readable[/white]",
                        border_style="cyan", padding=(1,2)))
    formatter.format_analysis(sample_df, title="Sample SQL Report")
    time.sleep(reveal_delay * 12)

    # 6) Legend + quick tips
    tips = "[bold magenta]Quick Tips[/bold magenta]\n\n" \
           "• Use --fast for demos\n" \
           "• Use --input-file to load many queries\n" \
           "• Compose mode shows inline query preview\n" \
           "• Exports: --export html,csv,json"
    console.print(Panel(tips, border_style="hot_pink", box=box.ROUNDED))
    time.sleep(reveal_delay * 8)

    # 7) Exit/Prompt
    if not non_interactive:
        console.print("\n[bold cyan]Press ENTER to return to shell[/bold cyan]", justify="center")
        try:
            input()
        except Exception:
            pass

    # 8) final glitch flourish
    try:
        aa.glitch_transition(duration=0.25 if not fast else 0.08)
    except Exception:
        pass

    console.clear()

def main(argv: Optional[List[str]] = None) -> None:
    parser = build_argparser()
    args = parser.parse_args(argv)

    # Animated visual help (TTY only) — handle and exit early
    if getattr(args, "help_art", False):
        show_animated_help(fast=args.fast, non_interactive=args.non_interactive, duration=args.duration)
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
        non_interactive=args.non_interactive
    )


if __name__ == "__main__":
    main()
