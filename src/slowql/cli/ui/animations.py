# slowql/src/slowql/cli/ui/animations.py
"""
SLOWQL Animations Module

Provides cinematic cyberpunk animations for CLI experience:
- MatrixRain intro (Gemini-style 3D Pixel Logo)
- Cinematic Scrolling Features
- Interactive SQL editor
- AnimatedAnalyzer effects
"""

import contextlib
import random
import shutil
import time
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.text import Text
from rich.table import Table

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
            "    ╚═════╝ ╚══════╝ ╚═════╝  ╚══╝╚══╝  ╚══▀▀═╝ ╚══════╝"
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
        
        if ratio < 0.1: # The Arrow area
            return "bold cyan"
        elif ratio < 0.35: # S-L
            return "bold deep_sky_blue1"
        elif ratio < 0.6: # O-W
            return "bold medium_purple1"
        elif ratio < 0.8: # Q
            return "bold magenta"
        else: # L
            return "bold hot_pink"

    def run(self, duration: float = 4.0) -> None:
        """
        Run the animation loop.
        Phase 1: Matrix Rain.
        Phase 2: Logo glitches into existence.
        """
        frames = int(duration * 20)
        
        # Calculate Logo Position (Center)
        logo_height = len(self.logo_ascii)
        logo_width = max(len(line) for line in self.logo_ascii)
        start_y = (self.height // 2) - (logo_height // 2) - 2
        start_x = (self.width // 2) - (logo_width // 2)

        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            for frame in range(frames):
                # 1. Update Rain Positions
                for col in self.columns:
                    col["y"] += col["speed"]
                    if col["y"] > self.height:
                        col["y"] = float(random.randint(-10, -2))

                # 2. Build the Matrix Frame
                lines = []
                for y in range(self.height):
                    line_text = Text()
                    for x in range(self.width):
                        col = self.columns[x]
                        cy = int(col["y"])
                        
                        # Logic to determine character at (x,y)
                        char_idx = (y + frame) % len(col["chars"])
                        char = col["chars"][char_idx]

                        # Rain Colors
                        if cy == y:
                            style = "bold white" 
                        elif cy - 6 < y < cy:
                            style = "bold green"
                        else:
                            style = "dim green"

                        # === LOGO GLITCH INTEGRATION ===
                        # Determine if we are in the Logo Box
                        in_logo_y = start_y <= y < start_y + logo_height
                        in_logo_x = start_x <= x < start_x + logo_width
                        
                        is_logo_pixel = False
                        logo_char = " "
                        
                        if in_logo_y and in_logo_x:
                            ly = y - start_y
                            lx = x - start_x
                            if ly < len(self.logo_ascii) and lx < len(self.logo_ascii[ly]):
                                logo_char = self.logo_ascii[ly][lx]
                                if logo_char != " ":
                                    is_logo_pixel = True

                        # Show logo based on progress
                        progress = frame / frames
                        show_logo = False
                        
                        if is_logo_pixel and progress > 0.35:
                            # Glitch effect
                            glitch_threshold = (progress - 0.35) * 2.0
                            if random.random() < glitch_threshold:
                                show_logo = True

                        if show_logo:
                            # Override with Gradient Color
                            logo_color = self._get_logo_color(x - start_x, logo_width)
                            
                            # If it's the arrow part (first few chars), keep it pixelated
                            # If it's the 3D shadow (▒), use a dimmer color
                            if "▒" in logo_char or "░" in logo_char or "▓" in logo_char:
                                line_text.append(logo_char, style=logo_color.replace("bold", "dim"))
                            else:
                                line_text.append(logo_char, style=logo_color)

                        elif is_logo_pixel and progress > 0.25:
                            # Hint at logo with dim chars
                            line_text.append(char, style="dim purple")
                        elif cy - 6 < y < cy:
                            # Normal Rain
                            line_text.append(char, style=style)
                        else:
                            # Empty space
                            line_text.append(" ")

                    lines.append(line_text)
                
                # Add Subtitle in last 10% frames
                if frame > frames * 0.9:
                    sub_y = start_y + logo_height + 1
                    if 0 <= sub_y < len(lines):
                        lines[sub_y] = Align.center(Text(self.subtitle, style="bold cyan"))

                live.update(
                    Panel(
                        Group(*lines),
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

        # 3. Final Prompt
        self.console.print()
        self.console.print(Align.center("[bold green blink]► PRESS ENTER TO ACTIVATE CONSOLE ◄[/]"))

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
                    ("Multi-Dimensional Analysis", "6 dimensions: Security, Performance, Reliability, Compliance, Quality, Cost"),
                    ("Advanced AST Parsing", "sqlglot-powered deep SQL analysis"),
                    ("Rule-Based Detection", "250+ detection patterns and anti-patterns"),
                    ("Heuristic Analysis", "AI-powered pattern recognition and estimation"),
                    ("Real-time Analysis", "Instant feedback on SQL queries"),
                    ("Batch Processing", "Analyze multiple queries simultaneously")
                ],
                "icon": "🚀",
                "color": "bright_blue"
            },
            {
                "category": "SECURITY ANALYSIS",
                "items": [
                    ("SQL Injection Detection", "OWASP Top 10 coverage with advanced pattern matching"),
                    ("Hardcoded Secret Detection", "Passwords, tokens, and credentials scanning"),
                    ("Privilege Escalation", "Excessive GRANT and permission analysis"),
                    ("Sensitive Data Exposure", "PII, financial data, and compliance risks"),
                    ("Authentication Bypass", "Weak authentication pattern detection"),
                    ("Security Metadata", "CVE mapping and security standards compliance")
                ],
                "icon": "🔒",
                "color": "red"
            },
            {
                "category": "PERFORMANCE OPTIMIZATION",
                "items": [
                    ("Index Usage Analysis", "SARGability and index optimization suggestions"),
                    ("Full Table Scan Detection", "Expensive scan pattern identification"),
                    ("Query Complexity Analysis", "JOIN, subquery, and CTE optimization"),
                    ("Resource Estimation", "CPU, memory, and I/O impact analysis"),
                    ("Execution Plan Simulation", "Predictive performance modeling"),
                    ("Cloud Cost Optimization", "Cost-effective query pattern recommendations")
                ],
                "icon": "⚡",
                "color": "yellow"
            },
            {
                "category": "RELIABILITY & SAFETY",
                "items": [
                    ("Data Loss Prevention", "Destructive operation interception"),
                    ("Transaction Safety", "ACID compliance verification"),
                    ("Schema Integrity", "Safe schema modification patterns"),
                    ("Backup Validation", "Pre-change impact assessment"),
                    ("Rollback Planning", "Automatic recovery strategy generation"),
                    ("Disaster Recovery", "Catastrophic failure prevention")
                ],
                "icon": "🛡️",
                "color": "blue"
            },
            {
                "category": "COMPLIANCE & GOVERNANCE",
                "items": [
                    ("GDPR Compliance", "Personal data protection verification"),
                    ("HIPAA Compliance", "Healthcare data security checks"),
                    ("PCI-DSS Compliance", "Payment data protection analysis"),
                    ("Data Residency", "Cross-border data transfer detection"),
                    ("Audit Trail", "Comprehensive analysis logging"),
                    ("Policy Enforcement", "Custom organizational rule compliance")
                ],
                "icon": "📋",
                "color": "magenta"
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
                    ("API Access", "Programmatic analysis integration")
                ],
                "icon": "💡",
                "color": "cyan"
            }
        ]

        # Create a grid layout for feature categories
        console_width = getattr(self.console, "width", 100)

        # Main title
        title_panel = Panel(
            Align.center(
                "[bold white]◢◣ SLOWQL ENTERPRISE FEATURES ◣◢[/]\n"
                "[dim]Comprehensive SQL Analysis Platform[/]"
            ),
            style="bold cyan",
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(1, 2),
            width=console_width
        )
        self.console.print(title_panel)
        self.console.print()
        
        # SCROLL EFFECT: Short pause
        time.sleep(0.3)

        # Create two-column grid for features
        for i in range(0, len(features), 2):
            left_feature = features[i]
            right_feature = features[i+1] if i+1 < len(features) else None

            # Left panel
            left_table = Table(box=None, padding=(0, 1), show_header=False, expand=True)
            left_table.add_column(ratio=1)

            for item_name, item_desc in left_feature["items"]:
                left_table.add_row(f"[{left_feature['color']}]{left_feature['icon']}[/] [bold]{item_name}[/]")
                left_table.add_row(f"[dim]└─ {item_desc}[/]")
                left_table.add_row("")  # spacing

            # Calculate roughly half width (accounting for grid padding)
            panel_width = (console_width // 2) - 2

            left_panel = Panel(
                left_table,
                title=f"[bold {left_feature['color']}]{left_feature['category']}[/]",
                border_style=left_feature['color'],
                box=box.ROUNDED,
                padding=(1, 1),
                width=panel_width
            )

            # Right panel (if exists)
            if right_feature:
                right_table = Table(box=None, padding=(0, 1), show_header=False, expand=True)
                right_table.add_column(ratio=1)

                for item_name, item_desc in right_feature["items"]:
                    right_table.add_row(f"[{right_feature['color']}]{right_feature['icon']}[/] [bold]{item_name}[/]")
                    right_table.add_row(f"[dim]└─ {item_desc}[/]")
                    right_table.add_row("")  # spacing

                right_panel = Panel(
                    right_table,
                    title=f"[bold {right_feature['color']}]{right_feature['category']}[/]",
                    border_style=right_feature['color'],
                    box=box.ROUNDED,
                    padding=(1, 1),
                    width=panel_width
                )
            else:
                # Empty panel for balance
                right_panel = Panel(
                    "",
                    border_style="dim",
                    box=box.ROUNDED,
                    padding=(1, 1),
                    width=panel_width
                )

            # Create grid and add panels
            grid = Table.grid(expand=True, padding=(0, 1))
            grid.add_column(ratio=1)
            grid.add_column(ratio=1)
            grid.add_row(left_panel, right_panel)

            self.console.print(grid)
            self.console.print()
            
            # SCROLL EFFECT: Pause between rows
            time.sleep(0.4)

        # ------------------------------------------------------------------
        # CAPABILITIES: 4 COLUMNS x 2 ROWS
        # ------------------------------------------------------------------
        capabilities = [
            ("🔍 Detection Capabilities", ""
            "250+ SQL anti-patterns and best practices"),
            ("📊 Analysis Dimensions", ""
            "6 comprehensive analysis categories"),
            ("⚡ Performance Rules", "Advanced query optimization patterns"),
            ("🔒 Security Rules", "OWASP Top 10 and compliance coverage"),
            ("🛡️ Safety Checks", "Data loss and disaster prevention"),
            ("💡 Smart Features", "Context-aware recommendations and suggestions"),
            ("🔧 Customization", "Extendable rule engine and analyzers"),
            ("📈 Scalability", "Enterprise-grade performance and reliability")
        ]

        # 4 Columns
        caps_grid = Table.grid(expand=True, padding=(0, 2))
        caps_grid.add_column(ratio=1)
        caps_grid.add_column(ratio=1)
        caps_grid.add_column(ratio=1)
        caps_grid.add_column(ratio=1)

        # --- Row 1 (Items 0, 1, 2, 3) ---
        row1_titles = []
        row1_descs = []
        for i in range(4):
            item = capabilities[i]
            row1_titles.append(item[0])
            row1_descs.append(f"[dim]{item[1]}[/]")
        
        caps_grid.add_row(*row1_titles)
        caps_grid.add_row(*row1_descs)
        
        # --- Spacer Row (Unified Empty Line) ---
        caps_grid.add_row("", "", "", "")

        # --- Row 2 (Items 4, 5, 6, 7) ---
        row2_titles = []
        row2_descs = []
        for i in range(4, 8):
            item = capabilities[i]
            row2_titles.append(item[0])
            row2_descs.append(f"[dim]{item[1]}[/]")
        
        caps_grid.add_row(*row2_titles)
        caps_grid.add_row(*row2_descs)

        caps_panel = Panel(
            caps_grid,
            title="[bold white]◢◣ COMPREHENSIVE CAPABILITIES ◣◢[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2),
            width=console_width
        )

        self.console.print(caps_panel)
        self.console.print()
        
        # SCROLL EFFECT: Pause
        time.sleep(0.4)


        # ------------------------------------------------------------------
        # POWER FEATURES: 3-COLUMN LAYOUT
        # ------------------------------------------------------------------
        power_features = [
            "🚀 Real-time SQL Analysis Engine",
            "🔍 250+ Detection Patterns and Anti-Patterns",
            "📊 Multi-Dimensional Issue Classification",
            "💡 Context-Aware Smart Recommendations",
            "⚡ Enterprise-Grade Performance",
            "🔒 Comprehensive Security Coverage",
            "🛡️ Data Loss Prevention System",
            "📋 Regulatory Compliance Verification"
        ]

        # 3 Columns
        power_grid = Table.grid(expand=True, padding=(0, 2))
        power_grid.add_column(ratio=1)
        power_grid.add_column(ratio=1)
        power_grid.add_column(ratio=1)

        # Iterate in chunks of 3
        for i in range(0, len(power_features), 3):
            cols = []
            for j in range(3):
                if i + j < len(power_features):
                    cols.append(f"[bold cyan]◆[/] {power_features[i+j]}")
                else:
                    cols.append("")
            
            power_grid.add_row(*cols)
            # Add spacer row between lines if not the last line
            if i + 3 < len(power_features):
                 power_grid.add_row("", "", "")

        power_panel = Panel(
            power_grid,
            title="[bold white]◢◣ POWER FEATURES ◣◢[/]",
            border_style="magenta",
            box=box.HEAVY,
            padding=(1, 2),
            width=console_width
        )

        self.console.print(power_panel)
        self.console.print()
        
        # SCROLL EFFECT: Pause
        time.sleep(0.4)

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
            width=console_width
        )

        self.console.print(final_summary)
        self.console.print()


class CyberpunkSQLEditor:
    """Interactive SQL query editor."""

    def __init__(self) -> None:
        self.console: Console = Console()

    def get_queries(self) -> Optional[str]:
        """
        Interactive query composition loop.
        """
        self.console.clear()
        self._show_header()

        queries: list[str] = []
        
        # FULL WIDTH HEADER FOR COMPOSITION AREA
        from rich.rule import Rule
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
                padding=(1, 1)
            )
        )

    def _show_query_preview(self, query: str) -> None:
        syntax = Syntax(query, "sql", theme="monokai", line_numbers=False)
        self.console.print(Panel(syntax, border_style="dim cyan", box=box.MINIMAL))

    def _show_query_summary(self, queries: list[str]) -> None:
        valid_queries: list[str] = [q for q in queries if q.strip()]
        if valid_queries:
            from rich.rule import Rule
            self.console.print()
            self.console.print(
                Rule(
                    f"[bold green]◆ QUERIES CAPTURED: {len(valid_queries)} ◆[/]", 
                    style="bold green"
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
        chars: str = "░▒▓█▀▄━│─╱╲"
        for _ in range(int(duration * 10)):
            glitch_line: str = "".join(random.choice(chars) for _ in range(80))
            self.console.print(
                f"[{random.choice(self.gradient_colors)}]{glitch_line}[/]", end="\r"
            )
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
                        expand=True
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