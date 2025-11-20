"""
Console Output Formatter

Beautiful terminal output for SQL analysis results using Rich.

Author: Mehdi Makroumi
license = { text = "All rights reserved. Copyright (c) 2025 El Mehdi Makroumi. All rights reserved." }
"""

from typing import List, Optional, Dict, Any
import pandas as pd
from rich.console import Console
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.text import Text
from rich import box
from ..core.detector import DetectedIssue, IssueSeverity
from rich.table import Table
from rich.console import Console
from rich.align import Align
from rich.panel import Panel





class ConsoleFormatter:
    """
    Rich console formatter for beautiful SQL analysis output
    
    Provides colorful, structured output for analysis results
    with tables, panels, and syntax highlighting.
    """
    
    def __init__(self):
        """Initialize console with vaporwave theme"""
        self.console = Console()
        
        # Update to vaporwave palette
        self.severity_colors = {
            IssueSeverity.CRITICAL: "bold magenta",
            IssueSeverity.HIGH: "bold hot_pink",
            IssueSeverity.MEDIUM: "bold cyan",
            IssueSeverity.LOW: "bold deep_sky_blue1"
        }
        
        self.severity_icons = {
            IssueSeverity.CRITICAL: "⚡",
            IssueSeverity.HIGH: "🔥",
            IssueSeverity.MEDIUM: "💫",
            IssueSeverity.LOW: "💠"
        }
        
        # ADD THIS
        self.gradient_colors = ["magenta", "hot_pink", "deep_pink4", "medium_purple", "slate_blue1", "cyan", "deep_sky_blue1"]

        
    def format_analysis(self, results: pd.DataFrame, title: str = "SQL Analysis Results") -> None:
        """
        Format and display analysis results
        
        Args:
            results: DataFrame with analysis results
            title: Report title
        """
        if results.empty:
            self._show_clean_report()
            return
        
        # Calculate health score
        health_score = self._calculate_health_score(results)
        
        # Header
        self._show_header(title, results)
        
        # Health gauge - NEW
        self._show_health_gauge(health_score, results)
        
        # Severity distribution chart - NEW
        self._show_severity_distribution(results)
        
        # Issues table v2 (symmetric version) - UPDATED
        self._show_issues_table_v2(results)
        
        # Summary stats
        self._show_summary_stats(results)
        
        # Next steps
        self._show_next_steps(results)

        
    def _show_clean_report(self) -> None:
        """Show report when no issues found"""
        panel = Panel(
            "[bold green]✅ Excellent! No SQL optimization issues detected.[/bold green]\n\n"
            "Your queries are following best practices.",
            title="[bold green]Clean SQL Report[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        self.console.print(panel)
        
    def _show_header(self, title: str, results: pd.DataFrame) -> None:
        """Display report header with summary"""
        total_issues = results['count'].sum() if 'count' in results else len(results)
        unique_issues = len(results['issue'].unique())
        
        severity_counts = results.groupby('severity').size().to_dict()
        
        # Build header content with proper alignment
        lines = [
            f"[bold white]Found {total_issues} optimization opportunities[/]",
            f"[dim]Across {unique_issues} different issue types[/]",
            ""  # Empty line for spacing
        ]
        
        # Add severity counts with consistent formatting
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_counts:
                icon = self.severity_icons.get(IssueSeverity(severity), "")
                color = self.severity_colors.get(IssueSeverity(severity), "white")
                lines.append(f"[{color}]{icon} {severity.upper():<8}: {severity_counts[severity]:>2}[/]")
        
        panel = Panel(
            "\n".join(lines),
            title=f"[bold white]{title}[/]",
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
        
    def _show_issues_table(self, results: pd.DataFrame) -> None:
        """Display issues in a formatted table"""
        table = Table(
            title="Detected Issues",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            title_style="bold",
            caption="Each issue includes actionable fixes and performance impact",
            caption_style="italic dim"
        )
        
        # Add columns
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Issue Type", style="cyan", width=28)
        table.add_column("Query Example", style="yellow", width=45)
        table.add_column("Fix", style="green", width=40)
        table.add_column("Impact", style="red", width=35)
        table.add_column("Count", justify="right", style="bold", width=8)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_results = results.sort_values(
            by='severity',
            key=lambda x: x.map(severity_order)
        )
        
        # Add rows
        for _, row in sorted_results.iterrows():
            severity = IssueSeverity(row['severity'])
            severity_display = Text(
                f"{self.severity_icons[severity]} {row['severity'].upper()}",
                style=self.severity_colors[severity]
            )
            
            # Truncate query if needed
            query = row['query']
            if len(query) > 45:
                query = query[:42] + "..."
                
            table.add_row(
                severity_display,
                row['issue'],
                query,
                row['fix'],
                row['impact'],
                str(row.get('count', 1))
            )
            
        self.console.print(table)
        self.console.print()
        
    def _show_summary_stats(self, results: pd.DataFrame) -> None:
        """Show analysis summary statistics - VAPORWAVE EDITION"""
        issue_counts = results.groupby('issue')['count'].sum().sort_values(ascending=False)
        
        table = Table(
            show_header=True,
            header_style="bold white on rgb(75,0,130)",
            box=box.HEAVY_EDGE,
            title="[bold cyan]◢◣[/] [bold white]ISSUE FREQUENCY SPECTRUM[/] [bold cyan]◣◢[/]",
            row_styles=["rgb(20,20,40)", ""],
            expand=True,
            border_style="bright_blue"
        )
        
        table.add_column("◆ Issue Type", style="cyan", width=40)
        table.add_column("◈ Count", justify="center", style="bold magenta", width=10)
        table.add_column("▶ Frequency Visualization", width=40)
        
        max_count = issue_counts.max()
        for idx, (issue, count) in enumerate(issue_counts.items()):
            # Gradient bar with different colors per row
            bar_length = int((count / max_count) * 30)
            color = self.gradient_colors[idx % len(self.gradient_colors)]
            bar = f"[{color}]{'█' * bar_length}[/][dim rgb(40,40,40)]{'░' * (30 - bar_length)}[/]"
            
            table.add_row(
                f"[bold cyan]{issue}[/]",
                f"[bold magenta]{count}×[/]",
                bar
            )
            
        self.console.print(table)
        self.console.print()
        
    def _show_next_steps(self, results: pd.DataFrame) -> None:
        """Show recommended next steps - CYBERPUNK EDITION"""
        # Futuristic header
        header = """[magenta]╔═══════════════════════════════════════════════════════════╗
    ║  [bold white]◢ RECOMMENDED ACTION PROTOCOLS ◣[/]  [magenta]║
    ╚═══════════════════════════════════════════════════════════╝[/]"""
        
        self.console.print(Align.center(header))
        
        steps = []
        
        # Check for critical issues
        critical_count = len(results[results['severity'] == 'critical'])
        if critical_count > 0:
            steps.append("[bold magenta]◆ PRIORITY ALPHA[/] [blink hot_pink]━━━━━━━━━━[/] [bold white]CRITICAL SYSTEM THREATS[/]")
            steps.append(f"  [hot_pink]▸[/] {critical_count} anomalies require [bold red]IMMEDIATE[/] intervention")
            steps.append("  [hot_pink]▸[/] Risk Level: [bold red on white] DATA LOSS [/] | [bold red on white] SYSTEM FAILURE [/]")
            steps.append("")
        
        # High severity issues
        high_count = len(results[results['severity'] == 'high'])
        if high_count > 0:
            steps.append(f"[bold cyan]◆ PRIORITY BETA[/] [dim white]━━━━━━━━━━[/] [yellow]PERFORMANCE DEGRADATION[/]")
            steps.append(f"  [cyan]▸[/] {high_count} issues causing [yellow]significant system strain[/]")
            steps.append("  [cyan]▸[/] Impact: [yellow]50-90% slower queries[/]")
            steps.append("")
        
        # Specific action items with futuristic styling
        issue_types = set(results['issue'].unique())
        action_num = 1
        
        if 'SELECT * Usage' in issue_types:
            steps.append(f"[bold deep_sky_blue1]◆ OPTIMIZATION VECTOR {action_num}[/] → Column Specificity Protocol")
            steps.append("  [deep_sky_blue1]▸[/] Replace SELECT * with explicit column lists")
            steps.append("  [dim]└─ Efficiency gain: [green]+40-60%[/] | Difficulty: [green]LOW[/][/]")
            steps.append("")
            action_num += 1
        
        if 'Missing WHERE in UPDATE/DELETE' in issue_types:
            steps.append(f"[bold hot_pink]◆ CRITICAL PROTOCOL {action_num}[/] → [blink]SAFETY LOCKDOWN[/]")
            steps.append("  [hot_pink]▸[/] [bold]ENGAGE WHERE CLAUSES ON ALL MUTATIONS![/]")
            steps.append("  [dim]└─ Risk mitigation: [red]PREVENT TABLE WIPES[/][/]")
            steps.append("")
            action_num += 1
        
        if 'Non-SARGable WHERE' in issue_types or 'Function on Indexed Column' in issue_types:
            steps.append(f"[bold medium_purple]◆ INDEX OPTIMIZATION {action_num}[/] → Query Rewrite Protocol")
            steps.append("  [medium_purple]▸[/] Restructure WHERE clauses for index utilization")
            steps.append("  [dim]└─ Performance boost: [yellow]+70-95%[/] on large datasets[/]")
            steps.append("")
            action_num += 1
        
        if 'Massive IN List' in issue_types:
            steps.append(f"[bold slate_blue1]◆ MEMORY OPTIMIZATION {action_num}[/] → Batch Processing Mode")
            steps.append("  [slate_blue1]▸[/] Convert IN lists to temporary table JOINs")
            steps.append("  [dim]└─ Cache efficiency: [green]+80%[/] | Parse time: [green]-90%[/][/]")
            steps.append("")
            action_num += 1
        
        # If no specific issues, show general optimization
        if not steps:
            steps = [
                "[bold cyan]◆ SYSTEM STATUS[/] → [green]NOMINAL[/]",
                "  [green]▸[/] Continue monitoring query patterns",
                "  [green]▸[/] Implement proactive index strategy",
                "  [green]▸[/] Schedule periodic performance audits"
            ]
        
        # Final panel with gradient border
        panel = Panel(
            "\n".join(steps),
            border_style="bold magenta",
            box=box.HEAVY,
            padding=(1, 3),
            style="on rgb(20,0,40)"
        )
        self.console.print(panel)

        
    def show_single_issue(self, issue: DetectedIssue) -> None:
        """
        Display a single issue with syntax highlighting
        
        Args:
            issue: Single detected issue
        """
        severity = issue.severity
        icon = self.severity_icons[severity]
        color = self.severity_colors[severity]
        
        # Issue header
        self.console.print(
            Panel(
                f"{icon} [bold]{issue.issue_type}[/bold]",
                style=color,
                box=box.HEAVY
            )
        )
        
        # SQL with syntax highlighting
        syntax = Syntax(
            issue.query,
            "sql",
            theme="monokai",
            line_numbers=True,
            word_wrap=True
        )
        self.console.print(Panel(syntax, title="Query", border_style="yellow"))
        
        # Details table
        details = Table(show_header=False, box=box.SIMPLE)
        details.add_column("Property", style="cyan")
        details.add_column("Value", style="white")
        
        details.add_row("Description", issue.description)
        details.add_row("Fix", f"[green]{issue.fix}[/green]")
        details.add_row("Impact", f"[red]{issue.impact}[/red]")
        details.add_row("Severity", severity.value.upper())
        
        self.console.print(details)
        self.console.print()
        
    def show_progress(self, message: str) -> Progress:
        """
        Show progress indicator for analysis
        
        Args:
            message: Progress message
            
        Returns:
            Progress context manager
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
        
    def format_comparison(self, before_count: int, after_count: int) -> None:
        """
        Show before/after comparison
        
        Args:
            before_count: Issues before optimization
            after_count: Issues after optimization
        """
        improvement = before_count - after_count
        percentage = (improvement / before_count * 100) if before_count > 0 else 0
        
        comparison_text = f"""
[bold]Query Optimization Results[/bold]

Before: [red]{before_count} issues[/red]
After:  [green]{after_count} issues[/green]

✨ [bold green]Improved by {improvement} issues ({percentage:.1f}%)[/bold green]
        """
        
        style = "green" if improvement > 0 else "yellow"
        panel = Panel(
            comparison_text.strip(),
            title="[bold]Optimization Impact[/bold]",
            border_style=style,
            padding=(1, 2)
        )
        
        self.console.print(panel)
        
    def export_html_report(self, results: pd.DataFrame, filename: str = "sql_analysis.html") -> str:
        """
        Export results as HTML report
        
        Args:
            results: Analysis results
            filename: Output filename
            
        Returns:
            Path to HTML file
        """
        with open(filename, 'w') as f:
            # Start capturing console output
            self.console.record = True
            
            # Generate report
            self.format_analysis(results, "SQL Analysis Report")
            
            # Export captured output
            f.write(self.console.export_html(
                theme="monokai",
                inline_styles=True
            ))
            
            self.console.record = False
            
        return filename
    
    def _calculate_health_score(self, results: pd.DataFrame) -> int:
        """Calculate 0-100 score based on severity and count"""
        severity_weights = {'critical': 25, 'high': 15, 'medium': 5, 'low': 2}
        total_penalty = 0
        
        for _, row in results.iterrows():
            penalty = severity_weights.get(row['severity'], 0) * row.get('count', 1)
            total_penalty += penalty
            
        # Convert to 0-100 score (100 = perfect, 0 = disaster)
        score = max(0, 100 - min(total_penalty, 100))
        return score

    def _show_health_gauge(self, score: int, results: pd.DataFrame) -> None:
        """Show visual health score gauge"""
        if score >= 80:
            color, status = "green", "✅ Healthy"
        elif score >= 60:
            color, status = "yellow", "⚠️  Needs Attention"
        elif score >= 40:
            color, status = "orange1", "⚠️  Poor Health"
        else:
            color, status = "red", "🚨 Critical Issues!"
        
        # Create proportional gauge
        filled = int(score / 4)  # 25 blocks total
        gauge = f"[{color}]{'█' * filled}[/][dim white]{'░' * (25 - filled)}[/]"
        
        content = [
            f"[bold white]SQL Health Score: {score}/100[/]",
            "",
            gauge + f" [bold {color}]{status}[/]",
            "",
            f"[dim]Analyzing {len(results)} unique issues across your queries[/]"
        ]
        
        panel = Panel(
            "\n".join(content),
            title="[bold white]📊 Database Query Health[/]",
            border_style="bright_blue",
            box=box.HEAVY,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()

    def _show_severity_distribution(self, results: pd.DataFrame) -> None:
        """Visual severity breakdown with proportional bars"""
        severity_counts = results.groupby('severity')['count'].sum()
        total = severity_counts.sum()
        
        lines = []
        max_bar_width = 30
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_counts:
                count = severity_counts[severity]
                pct = (count / total) * 100
                bar_width = max(1, int((pct / 100) * max_bar_width))
                
                icon = self.severity_icons[IssueSeverity(severity)]
                color = self.severity_colors[IssueSeverity(severity)]
                
                # Format: Icon Severity    ████████░░░░  3 (21.4%)
                severity_text = f"{icon} {severity.capitalize()}"
                bar = f"[{color}]{'█' * bar_width}[/][dim white]{'░' * (max_bar_width - bar_width)}[/]"
                stats = f"{count:>2} ({pct:>5.1f}%)"
                
                # Use proper spacing
                lines.append(f"{severity_text:<15} {bar} {stats}")
        
        panel = Panel(
            "\n".join(lines),
            title="[bold white]Severity Distribution[/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()

    def _show_issues_table_v2(self, results: pd.DataFrame) -> None:
        """Ultra-clean symmetric table design"""
        table = Table(
            show_header=True,
            header_style="bold white on rgb(24,24,40)",
            box=box.ROUNDED,
            title="[bold white]🔍 Detected SQL Issues[/]",
            row_styles=["", "dim"],
            expand=True,
            show_lines=False,
            padding=(0, 1)
        )
        
        table.add_column("Severity", width=15, no_wrap=True, style="bold")
        table.add_column("Issue Type", width=36)
        table.add_column("Count", width=8, justify="center", style="cyan")
        table.add_column("Impact", width=56)
        
        sorted_results = results.sort_values(
            by=['severity', 'count'], 
            ascending=[True, False]
        )
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_results['severity_order'] = sorted_results['severity'].map(severity_order)
        sorted_results = sorted_results.sort_values(['severity_order', 'count'], ascending=[True, False])
        
        for _, row in sorted_results.iterrows():
            severity = IssueSeverity(row['severity'])
            icon = self.severity_icons[severity]
            color = self.severity_colors[severity]
            
            severity_display = f"[{color}]{icon} {row['severity'].upper()}[/]"
            count_display = f"[bold cyan]{row.get('count', 1)}×[/]"
            
            impact = row['impact']
            if len(impact) > 53:
                impact = impact[:50] + "..."
            
            table.add_row(
                severity_display,
                row['issue'],
                count_display,
                f"[dim]{impact}[/]"
            )
        
        self.console.print(table)
        self.console.print()

    def _create_stats_panel(self, results: pd.DataFrame) -> Panel:
        """Create quick stats panel"""
        total_issues = results['count'].sum()
        unique_types = len(results['issue'].unique())
        critical_count = len(results[results['severity'] == 'critical'])
        
        # ASCII art gauge
        gauge = """[cyan]╭─────╮[/]
[cyan]│[/][bold white]{:^5}[/][cyan]│[/]
[cyan]╰─────╯[/]""".format(total_issues)
        
        content = f"""{gauge}
[dim]ISSUES DETECTED[/]

[magenta]►[/] [bold]{unique_types}[/] [dim]types[/]
[hot_pink]►[/] [bold red]{critical_count}[/] [dim]critical[/]
[cyan]►[/] [bold white]{total_issues}[/] [dim]total[/]"""
        
        return Panel(
            Align.center(content, vertical="middle"),
            border_style="bold deep_sky_blue1",
            box=box.HEAVY,
            title="[bold white]◢ SCAN RESULTS ◣[/]",
            height=9
        )
        
    def _show_issues_table_future(self, results: pd.DataFrame) -> None:
        """Futuristic issues table with neon styling"""
        table = Table(
            show_header=True,
            header_style="bold white on rgb(75,0,130)",
            box=box.HEAVY_EDGE,
            title="[bold cyan]◢◣◢◣[/] [bold white]DETECTED ANOMALIES[/] [bold cyan]◣◢◣◢[/]",
            title_style="bold",
            row_styles=["rgb(20,20,40)", ""],
            expand=True,
            show_lines=True,
            border_style="bright_blue"
        )
        
        # Futuristic column headers
        table.add_column("⚡ SEVERITY", width=16, style="bold", no_wrap=True)
        table.add_column("◆ ANOMALY TYPE", width=38, style="cyan")
        table.add_column("◈ FREQ", width=8, justify="center", style="bold magenta")
        table.add_column("▶ SYSTEM IMPACT", width=58, style="yellow")
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_results = results.copy()
        sorted_results['severity_order'] = sorted_results['severity'].map(severity_order)
        sorted_results = sorted_results.sort_values(['severity_order', 'count'], ascending=[True, False])
        
        for idx, row in sorted_results.iterrows():
            severity = IssueSeverity(row['severity'])
            icon = self.severity_icons[severity]
            color = self.severity_colors[severity]
            
            # Glowing severity indicator
            severity_text = f"[{color}]{icon} {row['severity'].upper()}[/]"
            
            # Frequency with neon effect
            count_text = f"[bold magenta]×{row.get('count', 1)}[/]"
            
            # Impact with warning levels
            impact = row['impact']
            if len(impact) > 55:
                impact = impact[:52] + "..."
            
            impact_text = f"[dim yellow]▸[/] {impact}"
            
            table.add_row(
                severity_text,
                f"[bold cyan]{row['issue']}[/]",
                count_text,
                impact_text
            )
        
        self.console.print(table)
        self.console.print()
        
    def _show_frequency_viz(self, results: pd.DataFrame) -> None:
        """Show frequency visualization with cyberpunk bars"""
        issue_counts = results.groupby('issue')['count'].sum().sort_values(ascending=False).head(8)
        
        if issue_counts.empty:
            return
            
        max_count = issue_counts.max()
        
        lines = ["[bold white]◢ FREQUENCY SPECTRUM ◣[/]", ""]
        
        for idx, (issue, count) in enumerate(issue_counts.items()):
            # Truncate long issue names
            issue_display = issue[:35] + "..." if len(issue) > 38 else issue
            
            # Create gradient bar
            bar_width = int((count / max_count) * 25)
            bar_chars = []
            
            for i in range(25):
                if i < bar_width:
                    # Gradient effect
                    color_idx = (i + idx) % len(self.gradient_colors)
                    bar_chars.append(f"[{self.gradient_colors[color_idx]}]▰[/]")
                else:
                    bar_chars.append("[dim rgb(40,40,40)]▱[/]")
            
            bar = "".join(bar_chars)
            
            lines.append(f"[cyan]{issue_display:<38}[/] {bar} [bold magenta]{count:>2}[/]")
        
        panel = Panel(
            "\n".join(lines),
            border_style="bold medium_purple",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
        
    def _show_recommendations_panel(self, results: pd.DataFrame) -> None:
        """Show recommendations with futuristic styling"""
        steps = []
        
        critical_count = len(results[results['severity'] == 'critical'])
        if critical_count > 0:
            steps.append(f"[bold magenta]◆ PRIORITY ALPHA[/] [blink hot_pink]━━━[/] [bold white]CRITICAL SYSTEM THREATS[/]")
            steps.append(f"  [hot_pink]▸[/] {critical_count} anomalies require [bold red]IMMEDIATE[/] intervention")
            steps.append("")
        
        high_count = len(results[results['severity'] == 'high'])
        if high_count > 0:
            steps.append(f"[bold cyan]◆ PRIORITY BETA[/] [dim white]━━━[/] [bold white]PERFORMANCE DEGRADATION[/]")
            steps.append(f"  [cyan]▸[/] {high_count} issues causing [yellow]significant[/] system strain")
            steps.append("")
        
        # Specific action items
        issue_types = set(results['issue'].unique())
        
        if 'SELECT * Usage' in issue_types:
            steps.append(f"[bold deep_sky_blue1]◆ OPTIMIZATION VECTOR 1[/]")
            steps.append(f"  [deep_sky_blue1]▸[/] Deploy column-specific retrieval protocols")
            steps.append("")
            
        if 'Missing WHERE in UPDATE/DELETE' in issue_types:
            steps.append(f"[bold hot_pink]◆ CRITICAL SAFETY PROTOCOL[/]")
            steps.append(f"  [hot_pink]▸[/] [blink]ENGAGE WHERE CLAUSES[/] - Data loss prevention")
            steps.append("")
        
        # Wrap in futuristic panel
                # Continue _show_recommendations_panel
        content = "\n".join(steps) if steps else "[dim]All systems operating within normal parameters[/]"
        
        # ASCII art border
        border_art = """[magenta]╔═══════════════════════════════════════════════════════╗
║  [bold white]◢ RECOMMENDED ACTION PROTOCOLS ◣[/]  [magenta]║
╚═══════════════════════════════════════════════════════╝[/]"""
        
        self.console.print(Align.center(border_art))
        
        panel = Panel(
            content,
            border_style="bold magenta",
            box=box.HEAVY,
            padding=(1, 3),
            style="on rgb(20,0,40)"
        )
        self.console.print(panel)
        
    def _calculate_health_score(self, results: pd.DataFrame) -> int:
        """Calculate 0-100 score with weighted penalties"""
        severity_weights = {'critical': 30, 'high': 15, 'medium': 5, 'low': 2}
        total_penalty = 0
        
        for _, row in results.iterrows():
            penalty = severity_weights.get(row['severity'], 0) * row.get('count', 1)
            total_penalty += penalty
            
        score = max(0, 100 - min(total_penalty, 100))
        return score
        
    def _show_clean_report(self) -> None:
        """Show clean report with celebration"""
        ascii_art = """[bold cyan]
    ╭─────────────╮
    │  ✨ 100% ✨  │
    ╰─────────────╯[/]"""
        
        content = f"""{ascii_art}

[bold green]◆ SYSTEM STATUS: OPTIMAL[/]

[dim]All queries validated against best practices[/]
[green]▸[/] No performance anomalies detected
[green]▸[/] Index usage: [bold]OPTIMAL[/]
[green]▸[/] Query patterns: [bold]EFFICIENT[/]
[green]▸[/] Risk assessment: [bold]NONE[/]

[dim magenta]Continue monitoring for peak performance[/]"""
        
        panel = Panel(
            Align.center(content),
            title="[bold white]◢◣ SQLGUARD SECURITY SCAN ◣◢[/]",
            border_style="bold green",
            box=box.DOUBLE,
            padding=(2, 4),
            style="on rgb(0,20,0)"
        )
        self.console.print(panel)
        
    def show_single_issue(self, issue: DetectedIssue) -> None:
        """Display single issue with cyberpunk styling"""
        severity = issue.severity
        icon = self.severity_icons[severity]
        color = self.severity_colors[severity]
        
        # Futuristic header
        header = f"""[{color}]╔{'═' * 60}╗
║ {icon} ANOMALY DETECTED: {issue.issue_type:<35} ║
╚{'═' * 60}╝[/]"""
        
        self.console.print(header)
        
        # SQL with syntax highlighting
        syntax = Syntax(
            issue.query,
            "sql",
            theme="monokai",
            line_numbers=True,
            background_color="rgb(20,20,40)"
        )
        
        syntax_panel = Panel(
            syntax,
            title="[bold cyan]◢ QUERY ANALYSIS ◣[/]",
            border_style="cyan",
            box=box.HEAVY
        )
        self.console.print(syntax_panel)
        
        # Details grid
        details = Table(show_header=False, box=None, padding=(0, 2))
        details.add_column("", style="bold magenta", width=20)
        details.add_column("", style="white")
        
        details.add_row("◆ DESCRIPTION", issue.description)
        details.add_row("◆ REMEDIATION", f"[bold green]{issue.fix}[/]")
        details.add_row("◆ IMPACT", f"[bold yellow]{issue.impact}[/]")
        details.add_row("◆ SEVERITY", f"[{color}]{severity.value.upper()}[/]")
        
        self.console.print(Panel(details, border_style="magenta", box=box.HEAVY))
        self.console.print()
        
    def show_progress(self, message: str) -> Progress:
        """Show cyberpunk progress indicator"""
        return Progress(
            SpinnerColumn(spinner_name="dots12", style="bold cyan"),
            TextColumn("[bold white]{task.description}[/]"),
            console=self.console
        )


# Convenience function
def print_analysis(results: pd.DataFrame) -> None:
    """Quick function to print formatted results"""
    formatter = ConsoleFormatter()
    formatter.format_analysis(results)

