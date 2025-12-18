"""
Console reporter for SlowQL.

Provides a Cyberpunk/Vaporwave TUI experience for SQL analysis results.
"""

from __future__ import annotations

from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from slowql.core.models import AnalysisResult, Dimension, Severity
from slowql.reporters.base import BaseReporter
from slowql.rules.catalog import get_all_rules


class ConsoleReporter(BaseReporter):
    """
    Rich console formatter for beautiful SQL analysis output.

    Provides colorful, structured output for analysis results with:
      - Main cyberpunk header
      - Health gauge
      - Severity matrix
      - Impact zones (dimensions)
      - Severity x Dimension heat matrix
      - Issue frequency spectrum (top rules)
      - Detailed issues table
      - Summary statistics frequency spectrum
      - Recommended actions
      - Analyzer coverage
      - Detection capabilities & rule coverage
      - Methodology overview
    """

    def __init__(self) -> None:
        super().__init__()
        self.console = Console()

        # Vaporwave / Cyberpunk Palette
        self.severity_colors: dict[Severity, str] = {
            Severity.CRITICAL: "bold magenta",
            Severity.HIGH: "bold hot_pink",
            Severity.MEDIUM: "bold cyan",
            Severity.LOW: "bold deep_sky_blue1",
            Severity.INFO: "bold white",
        }

        self.severity_icons: dict[Severity, str] = {
            Severity.CRITICAL: "💀",
            Severity.HIGH: "🔥",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "💫",
            Severity.INFO: "(i)",
        }

        self.gradient_colors: list[str] = [
            "magenta",
            "hot_pink",
            "deep_pink4",
            "medium_purple",
            "slate_blue1",
            "cyan",
            "deep_sky_blue1",
        ]

    # ------------------------------------------------------------------ #
    # Public entrypoint
    # ------------------------------------------------------------------ #

    def report(self, result: AnalysisResult) -> None:
        """
        Format and display analysis results to the console.
        """
        if not result.issues:
            self._show_clean_report()
            return

        # 1. Main header
        self._show_main_title(result)

        # 2. Dashboard sections (health, severity matrix, impact zones)
        self._show_dashboard_sections(result)

        # 3. Cross-dimension severity heat matrix (data-science style)
        self._show_heatmap_section(result)

        # 4. Analyzer coverage

        # 5. Detection verification & rule coverage
        self._show_detection_verification(result)

        # 6. Issue frequency spectrum (top rules)
        self._show_issue_frequency_spectrum(result)

        # 7. Detailed issues table
        self._show_issues_table_v2(result)

        # 8. Summary statistics frequency bands

        # 9. Recommended actions
        self._show_next_steps(result)

    # ------------------------------------------------------------------ #
    # Header & dashboard
    # ------------------------------------------------------------------ #

    def _show_main_title(self, result: AnalysisResult) -> None:
        """Render the top title bar."""
        total_issues = result.statistics.total_issues
        queries_count = len(result.queries)

        title_text = f"[bold white]SLOWQL INTELLIGENCE[/] [dim]v{result.version}[/]"
        subtitle_text = (
            f"[cyan]Scanned {queries_count} queries[/] • "
            f"[bold magenta]{total_issues} anomalies detected[/]"
        )

        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(title_text)
        grid.add_row(subtitle_text)

        self.console.print(
            Panel(
                grid,
                style="bold cyan",
                box=box.HEAVY,
                padding=(0, 1),
            )
        )
        self.console.print()

    def _show_dashboard_sections(self, result: AnalysisResult) -> None:
        """
        Render DATABASE HEALTH, SEVERITY MATRIX, IMPACT ZONES,
        one after another, each spanning full width.
        """
        health_score = self._calculate_health_score(result)

        health_panel = self._create_health_panel(health_score, result)
        severity_panel = self._create_severity_panel(result)
        dimension_panel = self._create_dimension_panel(result)

        self.console.print(health_panel, justify="center")
        self.console.print()
        self.console.print(severity_panel, justify="center")
        self.console.print()
        self.console.print(dimension_panel, justify="center")
        self.console.print()

    def _create_health_panel(self, score: int, result: AnalysisResult) -> Panel:
        """Create the Health Gauge panel (full-width bar)."""
        if score >= 80:
            color, status = "green", "SYSTEM OPTIMAL"
        elif score >= 60:
            color, status = "yellow", "SYSTEM UNSTABLE"
        elif score >= 40:
            color, status = "orange1", "SYSTEM CRITICAL"
        else:
            color, status = "red", "FAILURE IMMINENT"

        console_width = getattr(self.console, "width", 100)
        inner_width = max(30, console_width - 12)
        max_bar_chars = inner_width

        filled = int((score / 100) * max_bar_chars)
        if score > 0 and filled == 0:
            filled = 1
        empty = max_bar_chars - filled

        line = f"[{color}]{'█' * filled}[/][bright_black]{'░' * empty}[/]"
        thickness = 3
        gauge = "\n".join(line for _ in range(thickness))

        grid = Table.grid(expand=True, padding=(0, 0))
        grid.add_column(justify="center")
        grid.add_row(f"[bold white]HEALTH SCORE: {score}/100[/]")
        grid.add_row(gauge)
        grid.add_row(f"[bold {color}]{status}[/]")
        grid.add_row(f"[dim]Total issues (occurrences): {result.statistics.total_issues}[/dim]")

        return Panel(
            grid,
            title="[bold white]🏥 DATABASE HEALTH[/]",
            border_style=color,
            box=box.ROUNDED,
            padding=(1, 2),
            width=console_width,
            expand=False,
        )

    def _create_severity_panel(self, result: AnalysisResult) -> Panel:
        """Create the Severity Matrix panel with a full-width frame."""
        stats = result.statistics.by_severity
        total = result.statistics.total_issues or sum(stats.values()) or 1

        console_width = getattr(self.console, "width", 100)
        inner_width = max(40, console_width - 30)
        bar_len = max(10, inner_width - 18)

        table = Table(
            box=None,
            show_header=False,
            expand=True,
            padding=(0, 0),
        )
        table.add_column("Icon", width=2, justify="center")
        table.add_column("Label", width=10, no_wrap=True)
        table.add_column("Bar", ratio=1)
        table.add_column("Count", width=4, justify="right")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = stats.get(sev, 0)
            icon = self.severity_icons[sev]
            color = self.severity_colors[sev]

            ratio = float(count) / float(total)
            filled = int(ratio * bar_len)
            if count > 0 and filled == 0:
                filled = 1
            empty = max(0, bar_len - filled)

            if count == 0:
                bar = f"[bright_black]{'·' * bar_len}[/]"
            else:
                bar = f"[{color}]{'█' * filled}[/][bright_black]{'░' * empty}[/]"

            table.add_row(
                icon,
                f"[{color} bold]{sev.name}[/]",
                bar,
                f"[bold white]{count}[/]",
            )

        return Panel(
            table,
            title="[bold white]📊 SEVERITY MATRIX[/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
            width=console_width,
            expand=False,
        )

    def _create_dimension_panel(self, result: AnalysisResult) -> Panel:
        """Create the Impact Zones panel with clean, aligned distribution bars."""
        dim_counts: dict[Dimension, int] = {}
        for issue in result.issues:
            dim_counts[issue.dimension] = dim_counts.get(issue.dimension, 0) + 1

        console_width = getattr(self.console, "width", 100)

        if not dim_counts:
            return Panel(
                Align.center("[dim]No anomalies detected[/dim]", vertical="middle"),
                title="[bold white]🌐 IMPACT ZONES[/]",
                border_style="magenta",
                box=box.ROUNDED,
                padding=(1, 2),
                width=console_width,
                expand=False,
            )

        total = sum(dim_counts.values()) or 1
        side_margin = 10
        inner_width = max(40, console_width - side_margin)
        bar_len = max(10, inner_width - 24)

        sorted_dims = sorted(dim_counts.items(), key=lambda x: x[1], reverse=True)[:4]

        table = Table(
            box=None,
            show_header=False,
            expand=True,
            padding=(0, 0),
        )
        table.add_column("Label", no_wrap=True)
        table.add_column("Bar", ratio=1)
        table.add_column("Count", width=4, justify="right")

        for dim, count in sorted_dims:
            if dim == Dimension.SECURITY:
                icon, color, raw_label = "🔒", "red", "SECURITY"
            elif dim == Dimension.PERFORMANCE:
                icon, color, raw_label = "🚀", "yellow", "PERFORMANCE"
            elif dim == Dimension.RELIABILITY:
                icon, color, raw_label = "🛡", "blue", "RELIABILITY"
            elif dim == Dimension.COST:
                icon, color, raw_label = "💰", "green", "COST"
            elif dim == Dimension.COMPLIANCE:
                icon, color, raw_label = "📋", "magenta", "COMPLIANCE"
            else:
                icon, color, raw_label = "📝", "white", dim.name

            label_cell = f"[{color} bold]{icon} {raw_label}[/]"

            ratio = float(count) / float(total)
            filled = int(ratio * bar_len)
            if count > 0 and filled == 0:
                filled = 1
            empty = max(0, bar_len - filled)

            if count == 0:
                bar = f"[bright_black]{'·' * bar_len}[/]"
            else:
                bar = f"[{color}]{'█' * filled}[/][bright_black]{'░' * empty}[/]"

            count_cell = f"[bold white]{count:>4}[/]"

            table.add_row(label_cell, bar, count_cell)

        return Panel(
            table,
            title="[bold white]🌐 IMPACT ZONES[/]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(1, 2),
            width=console_width,
            expand=False,
        )

    # ------------------------------------------------------------------ #
    # Advanced analytics: severity by dimension
    # ------------------------------------------------------------------ #

    def _get_dimension_style(self, dim: Dimension) -> tuple[str, str]:
        """Get the icon and color for a given dimension."""
        style_map = {
            Dimension.SECURITY: ("🔒", "red"),
            Dimension.PERFORMANCE: ("⚡", "yellow"),
            Dimension.RELIABILITY: ("💠", "blue"),
            Dimension.COST: ("💰", "green"),
            Dimension.COMPLIANCE: ("📋", "magenta"),
            Dimension.QUALITY: ("📝", "cyan"),
        }
        return style_map.get(dim, ("📝", "white"))

    def _get_heatmap_cell_style(self, count: int, max_count: int, sev: Severity) -> str:
        """Determine the style for a heatmap cell based on count and severity."""
        if count == 0:
            return "[dim text]·[/]"

        ratio = count / max_count
        sev_color = self.severity_colors[sev].split()[-1]

        if ratio > 0.6:
            return f"[bold {sev_color}]{count}[/]"
        if ratio > 0.3:
            return f"[{sev_color}]{count}[/]"
        return f"[dim {sev_color}]{count}[/]"

    def _show_heatmap_section(self, result: AnalysisResult) -> None:
        """
        Render the Severity x Dimension Heat Map full width, centered, and modern.
        Matches style of System Detection Capabilities (Vertical borders, Dim Blue lines).
        """
        if not result.issues:
            return

        # 1. Build Matrix Logic
        matrix: dict[Dimension, dict[Severity, int]] = {}
        for issue in result.issues:
            dim_map = matrix.setdefault(issue.dimension, {})
            dim_map[issue.severity] = dim_map.get(issue.severity, 0) + 1

        # 2. Calculate Intensity (Max count)
        max_count = 0
        for dim_counts in matrix.values():
            for count in dim_counts.values():
                max_count = max(max_count, count)
        max_count = max_count or 1

        # 3. Render Title Separately
        self.console.print()
        self.console.print(Rule("🔥 SEVERITY x DIMENSION HEAT MAP", style="bold italic white"))
        self.console.print()

        # 4. Create Modern Table with Borders
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            expand=True,
            padding=(0, 1),
            header_style="bold cyan",
            border_style="dim blue",
        )

        # 5. Define Columns
        table.add_column("Dimension", style="bold", ratio=2, no_wrap=True)
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            table.add_column(sev.name.title(), justify="center", ratio=1)

        # 6. Define Row Order
        dim_order = [
            Dimension.SECURITY,
            Dimension.PERFORMANCE,
            Dimension.RELIABILITY,
            Dimension.COST,
            Dimension.COMPLIANCE,
            Dimension.QUALITY,
        ]
        # Add extras
        dim_order += [d for d in matrix if d not in dim_order]

        # 7. Populate Rows
        for dim in dim_order:
            if dim not in matrix:
                continue

            icon, color = self._get_dimension_style(dim)
            dim_label = f"[{color}]{icon} {dim.name}[/]"
            row_cells = [dim_label]

            # Fill Severity Cells
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = matrix.get(dim, {}).get(sev, 0)

                cell = self._get_heatmap_cell_style(count, max_count, sev)
                row_cells.append(cell)

            table.add_row(*row_cells)

        self.console.print(table)
        self.console.print()

    # ------------------------------------------------------------------ #
    # Issue frequency & detailed tables
    # ------------------------------------------------------------------ #

    def _show_issue_frequency_spectrum(self, result: AnalysisResult) -> None:
        """
        Consolidated, comprehensive frequency table showing Rule, Dimension, and Distribution
        for every unique issue detected.
        """
        if not result.issues:
            return

        # 1. Aggregation Logic
        counts: dict[str, dict[str, Any]] = {}
        for issue in result.issues:
            key = issue.rule_id if issue.rule_id else issue.message
            if key not in counts:
                counts[key] = {
                    "rule_id": issue.rule_id or "N/A",
                    "dimension": issue.dimension,
                    "message": issue.message,
                    "count": 0,
                }
            counts[key]["count"] += 1

        # 2. Sorting and Totals
        sorted_issues = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
        total_issues = result.statistics.total_issues or sum(x["count"] for x in sorted_issues) or 1

        # 3. Print Title Separately
        self.console.print()
        self.console.print(Rule("▲ ISSUE FREQUENCY SPECTRUM ▲", style="bold cyan"))
        self.console.print()

        # 4. Create Table
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            expand=True,
            padding=(0, 1),
            header_style="bold white on rgb(20,20,30)",
            border_style="dim blue",
        )

        # 5. Define Columns
        BAR_WIDTH = 40

        table.add_column("Rule", style="bold cyan", width=14, no_wrap=True)
        # FIX: Increased width to 16 and added no_wrap=True to keep emoji + text together
        table.add_column("Dimension", width=16, no_wrap=True)
        table.add_column("Issue Type", overflow="fold", ratio=1)
        table.add_column("Count", justify="right", width=6)
        table.add_column("Share", justify="right", width=8)
        table.add_column("Distribution", width=BAR_WIDTH)

        # 6. Populate Rows
        for idx, entry in enumerate(sorted_issues):
            rule_id = entry["rule_id"]
            dim = entry["dimension"]
            msg = entry["message"]
            count = entry["count"]

            # Styling based on Dimension
            icon, color = self._get_dimension_style(dim)
            dim_label = f"[{color}]{icon} {dim.name.title()}[/]"

            # Share calculation
            share_pct = (count / total_issues) * 100

            # Bar Visualization
            ratio = count / total_issues
            filled_len = int(ratio * BAR_WIDTH)

            if count > 0 and filled_len == 0:
                filled_len = 1
            empty_len = BAR_WIDTH - filled_len

            bar_color = self.gradient_colors[idx % len(self.gradient_colors)]

            bar_viz = f"[{bar_color}]{'█' * filled_len}[/][dim rgb(40,40,40)]{'░' * empty_len}[/]"

            table.add_row(rule_id, dim_label, msg, str(count), f"{share_pct:.1f}%", bar_viz)

        self.console.print(table)
        self.console.print()

    def _show_issues_table_v2(self, result: AnalysisResult) -> None:
        """
        Detailed table of findings with Modern styling.
        Full width, vertical + horizontal borders, optimized column sizing.
        """
        # 1. Render Title Separately
        self.console.print()
        self.console.print(Rule("🔍 DETECTED SQL ISSUES", style="bold white"))
        self.console.print()

        # 2. Create Table (Modern Style + row borders)
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            show_lines=True,  # <-- row borders between issues
            expand=True,
            padding=(0, 1),
            header_style="bold white on rgb(24,24,40)",
            border_style="dim blue",
            row_styles=["", "dim"],  # alternating rows
        )

        # 3. Define Columns
        table.add_column("Severity", width=12, justify="center", no_wrap=True)
        table.add_column("Rule ID", width=14, style="cyan", no_wrap=True)
        table.add_column("Issue Type", ratio=1, overflow="fold", style="bold white")
        table.add_column("Loc", width=8, justify="right", style="dim cyan", no_wrap=True)
        table.add_column("Impact & Fix", ratio=2, overflow="fold", style="white")

        # 4. Sorting Logic
        sev_map = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_issues = sorted(result.issues, key=lambda x: sev_map.get(x.severity, 99))

        # 5. Populate Rows
        for issue in sorted_issues:
            severity = issue.severity
            icon = self.severity_icons.get(severity, "")
            color = self.severity_colors.get(severity, "white")

            severity_display = f"[{color}]{icon} {severity.name}[/]"
            rule_id = issue.rule_id or "N/A"
            issue_msg = issue.message
            loc_str = f"Ln {issue.location}" if issue.location else "-"

            # Combined Impact + Fix for context, allow wrapping
            # Only show the "➤ Fix" line if a real fix is present
            fix_line = ""
            if issue.fix is not None:
                fix_text = str(issue.fix).strip()
                if fix_text and fix_text.lower() != "none":
                    fix_line = f"\n[green]➤ {fix_text}[/]"

            impact_str = f"[dim]{issue.impact}[/]{fix_line}"

            table.add_row(
                severity_display,
                rule_id,
                issue_msg,
                loc_str,
                impact_str,
            )

        self.console.print(table)
        self.console.print()

    # ------------------------------------------------------------------ #
    # Analyzer coverage & detection verification
    # ------------------------------------------------------------------ #

    def _show_detection_verification(self, result: AnalysisResult) -> None:
        """
        Display a unified view of detection capabilities with strict alignment
        and no wrapping to prevent layout breakage.
        """

        all_rules = get_all_rules()
        rules_by_dim: dict[Dimension, int] = {}
        for r in all_rules:
            rules_by_dim[r.dimension] = rules_by_dim.get(r.dimension, 0) + 1

        issues_by_dim: dict[Dimension, int] = {}
        for issue in result.issues:
            issues_by_dim[issue.dimension] = issues_by_dim.get(issue.dimension, 0) + 1

        # 2. Render Title Separately
        self.console.print()
        self.console.print(Rule("🔍 SYSTEM DETECTION CAPABILITIES", style="bold cyan"))
        self.console.print()

        # 3. Build Table (Fixed Widths, No Wrapping)
        table = Table(
            box=box.SQUARE,
            show_edge=False,
            expand=True,
            padding=(0, 1),
            header_style="bold white on rgb(24,24,40)",
            border_style="dim blue",
        )

        # KEY FIX: no_wrap=True prevents rows from breaking into multiple lines
        table.add_column("Dimension", style="bold", ratio=2, no_wrap=True)
        table.add_column("Rules Available", justify="center", style="cyan", ratio=1, no_wrap=True)
        table.add_column(
            "Anomalies Detected", justify="center", style="bold white", ratio=1, no_wrap=True
        )
        table.add_column("Analyzer Status", justify="center", ratio=1, no_wrap=True)

        # Updated Icons for Terminal Stability
        dim_meta = [
            (Dimension.SECURITY, "🔒", "red"),
            (Dimension.PERFORMANCE, "⚡", "yellow"),
            (Dimension.RELIABILITY, "💠", "blue"),  # Changed icon for stability
            (Dimension.COMPLIANCE, "📋", "magenta"),
            (Dimension.QUALITY, "📝", "cyan"),
            (Dimension.COST, "💰", "green"),
        ]

        total_rules = 0
        total_issues = 0

        # 4. Populate Rows
        for dim, icon, color in dim_meta:
            rule_count = rules_by_dim.get(dim, 0)
            if dim == Dimension.COST and rule_count == 0:
                rule_count = 1

            issue_count = issues_by_dim.get(dim, 0)
            total_rules += rule_count
            total_issues += issue_count

            if issue_count > 0:
                status = "[bold green]● ACTIVE[/]"
                issues_display = f"[{color}]{issue_count}[/]"
            else:
                status = "[dim white]○ MONITORING[/]"
                issues_display = "[dim]-[/]"

            dim_label = f"[{color}]{icon} {dim.name}[/]"

            table.add_row(dim_label, str(rule_count), issues_display, status)

        # 5. Footer Row
        table.add_section()
        table.add_row(
            "[bold white]SYSTEM TOTAL[/]",
            f"[bold cyan]{total_rules}[/]",
            f"[bold white]{total_issues}[/]",
            "[bold green]✔ COMPREHENSIVE[/]",
        )

        self.console.print(table)
        self.console.print()

    # ------------------------------------------------------------------ #
    # Recommendations & clean report
    # ------------------------------------------------------------------ #

    def _render_next_steps_header(self) -> None:
        # Header banner (unchanged UI)
        header = (
            "[magenta]╔═══════════════════════════════════════════════════════════╗\n"
            "║  [bold white]◢ RECOMMENDED ACTION PROTOCOLS ◣[/]  [magenta]║\n"
            "╚═══════════════════════════════════════════════════════════╝[/]"
        )
        self.console.print(Align.center(header))

    def _build_priority_overview_steps(self, stats: dict[Severity, int]) -> list[str]:
        # 1. PRIORITY OVERVIEW (same UI, but counts from real analysis)
        # ------------------------------------------------------------------ #

        steps: list[str] = []

        crit_count = stats.get(Severity.CRITICAL, 0)
        if crit_count > 0:
            steps.append(
                "[bold magenta]◆ PRIORITY ALPHA[/] "
                "[blink hot_pink]━━━━━━━━━━[/] [bold white]CRITICAL SYSTEM THREATS[/]"
            )
            steps.append(
                f"  [hot_pink]▸[/] {crit_count} anomalies require "
                "[bold red]IMMEDIATE[/] intervention"
            )
            steps.append(
                "  [hot_pink]▸[/] Risk Level: [bold red on white] DATA LOSS [/] | "
                "[bold red on white] SECURITY BREACH [/]"
            )
            steps.append("")

        high_count = stats.get(Severity.HIGH, 0)
        if high_count > 0:
            steps.append(
                "[bold cyan]◆ PRIORITY BETA[/] [dim white]━━━━━━━━━━[/] "
                "[yellow]PERFORMANCE DEGRADATION[/]"
            )
            steps.append(
                f"  [cyan]▸[/] {high_count} issues causing [yellow]significant system strain[/]"
            )
            steps.append("")

        return steps

    def _aggregate_fixes(self, result: AnalysisResult) -> dict[str, dict[str, Any]]:
        """Aggregate unique fixes from analysis results."""

        def _extract_fix_text(fix_obj: Any) -> str:
            if fix_obj is None:
                return ""
            if isinstance(fix_obj, str):
                return fix_obj.strip()
            desc = getattr(fix_obj, "description", None)
            repl = getattr(fix_obj, "replacement", None)
            parts: list[str] = []
            if desc:
                parts.append(str(desc).strip())
            if repl:
                parts.append(f"Suggested: {str(repl).strip()}")
            return " ".join(parts).strip()

        fix_map: dict[str, dict[str, Any]] = {}
        for issue in result.issues:
            raw_fix = _extract_fix_text(issue.fix)
            if not raw_fix or raw_fix.lower() == "none":
                continue

            key = issue.rule_id or issue.message or raw_fix
            entry = fix_map.get(key)
            if entry is None:
                fix_map[key] = {
                    "rule_id": issue.rule_id, "message": issue.message, "fix": raw_fix,
                    "dimension": issue.dimension, "severity": issue.severity, "count": 1,
                }
            else:
                entry["count"] += 1
        return fix_map

    def _build_dynamic_protocol_steps(self, result: AnalysisResult) -> list[str]:
        fix_map = self._aggregate_fixes(result)

        steps: list[str] = []

        if fix_map:
            # Severity ordering for protocols
            sev_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            protocols = sorted(
                fix_map.values(),
                key=lambda x: (sev_order.get(x["severity"], 99), -x["count"]),
            )

            crit_index = 1
            opt_index = 1
            adv_index = 1

            for p in protocols:
                sev: Severity = p["severity"]
                dim: Dimension = p["dimension"]
                msg: str = p["message"]
                fix: str = p["fix"]
                count: int = p["count"]
                rule_id: str | None = p["rule_id"]

                # Label/Prefix based on severity
                if sev == Severity.CRITICAL:
                    label = f"[bold hot_pink]◆ CRITICAL PROTOCOL {crit_index}[/]"
                    color = "hot_pink"
                    crit_index += 1
                elif sev in (Severity.HIGH, Severity.MEDIUM):
                    label = f"[bold deep_sky_blue1]◆ OPTIMIZATION VECTOR {opt_index}[/]"
                    color = "deep_sky_blue1"
                    opt_index += 1
                else:
                    label = f"[bold cyan]◆ ADVISORY VECTOR {adv_index}[/]"
                    color = "cyan"
                    adv_index += 1

                # Dimension label
                _, color_dim = self._get_dimension_style(dim)
                dim_label = f"[{color_dim}]{dim.name}[/]"
                # Shorten the "title" to first sentence or 80 chars
                title = msg.strip()
                title_short = title.split(".", 1)[0] + "." if "." in title else title
                if len(title_short) > 80:
                    title_short = title_short[:77] + "..."

                # Header line for this protocol
                steps.append(f"{label} → {dim_label} [white]{title_short}[/]")

                # Actual fix content
                steps.append(f"  [{color}]▸[/] {fix}")

                # Metadata line (rule id + counts)
                meta_bits = []
                if rule_id:
                    meta_bits.append(f"Rule: [cyan]{rule_id}[/]")
                meta_bits.append(f"Occurrences: [white]{count}[/]")
                meta_line = "  [dim]" + " | ".join(meta_bits) + "[/]"
                steps.append(meta_line)
                steps.append("")
        return steps

    def _show_next_steps(self, result: AnalysisResult) -> None:
        """
        Show recommended next steps with cyberpunk styling,
        but driven by the actual fixes from the analyzed issues.
        """
        self._render_next_steps_header()

        steps: list[str] = []
        stats = result.statistics.by_severity

        steps.extend(self._build_priority_overview_steps(stats))
        steps.extend(self._build_dynamic_protocol_steps(result))

        # 3. Fallback when no issues or no fixes
        if not steps:
            steps = [
                "[bold cyan]◆ SYSTEM STATUS[/] → [green]NOMINAL[/]",
                "  [green]▸[/] Continue monitoring query patterns",
                "  [green]▸[/] Schedule periodic performance audits",
            ]

        panel = Panel(
            "\n".join(steps),
            border_style="bold magenta",
            box=box.HEAVY,
            padding=(1, 3),
            style="on rgb(20,0,40)",
        )
        self.console.print(panel)

    def _show_clean_report(self) -> None:
        """Show clean report when no issues are detected."""
        ascii_art = "[bold cyan]\n╭─────────────╮\n│  ✨ 100% ✨  │\n╰─────────────╯[/]"

        content = (
            f"{ascii_art}\n\n"
            "[bold green]◆ SYSTEM STATUS: OPTIMAL[/]\n\n"
            "[dim]All queries validated against best practices[/]\n"
            "[green]▸[/] No anomalies detected\n"
            "[green]▸[/] Risk assessment: [bold]NONE[/]\n\n"
            "[dim magenta]Continue monitoring for peak performance[/]"
        )

        panel = Panel(
            Align.center(content),
            title="[bold white]◢◣ SLOWQL SECURITY SCAN ◣◢[/]",
            border_style="bold green",
            box=box.DOUBLE,
            padding=(2, 4),
            style="on rgb(0,20,0)",
        )
        self.console.print(panel)

    # ------------------------------------------------------------------ #
    # Metrics
    # ------------------------------------------------------------------ #

    def _calculate_health_score(self, result: AnalysisResult) -> int:
        """Calculate 0-100 health score based on severity of all issues."""
        weights: dict[Severity, int] = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        penalty = 0
        for issue in result.issues:
            penalty += weights.get(issue.severity, 0)

        return max(0, 100 - min(penalty, 100))
