# animations.py - COMPLETE ANIMATED EXPERIENCE
import random
import time
import shutil
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.syntax import Syntax
from rich.prompt import Prompt
from rich.table import Table
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

class MatrixRain:
    """Matrix rain intro animation"""
    def __init__(self):
        self.console = Console()
        self.width = min(shutil.get_terminal_size().columns, 140)
        self.height = min(shutil.get_terminal_size().lines - 5, 40)
        self.chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789!@#$%^&*()"
        
        self.logo = [
            "  ▄▄▄▄▄  ▄▄▄▄▄  ▄      ▄▄▄▄▄  ▄   ▄  ▄▄▄▄▄  ▄▄▄▄▄  ▄▄▄▄▄  ",
            "  █      █   █  █      █      █   █  █   █  █   █  █   █  ",
            "  ▀▀▀▀▀  █ ▀ █  █      █  ▀█  █   █  █▀▀▀█  █▀▀▀▄  █   █  ",
            "  ▄▄▄▄▄  ▀▄▄▄█  ▀▄▄▄▄  ▀▄▄▄▀  ▀▄▄▄▀  ▀   ▀  ▀   ▀  ▀▄▄▄▀  ",
            "",
            "       ◆ DATABASE ANOMALY DETECTOR ◆       ",
            "         v2.0 CYBERPUNK EDITION         "
        ]
        
        self.columns = []
        for x in range(self.width):
            self.columns.append({
                'y': float(random.randint(-self.height, 0)),
                'speed': random.uniform(0.5, 1.5),
                'length': random.randint(5, 15),
                'chars': [random.choice(self.chars) for _ in range(30)]
            })
    
    def run(self, duration=3):
        frames = int(duration * 30)
        
        with Live(console=self.console, refresh_per_second=30) as live:
            for frame in range(frames):
                lines = []
                for y in range(self.height):
                    line = Text()
                    for x in range(self.width):
                        col = self.columns[x]
                        char_y = int(col['y'])
                        
                        if char_y == y:
                            line.append(col['chars'][frame % 30], "bold green")
                        elif char_y - 5 < y < char_y:
                            line.append(col['chars'][(frame + y) % 30], "dim cyan")
                        else:
                            line.append(" ")
                    lines.append(line)
                
                for col in self.columns:
                    col['y'] += col['speed']
                    if col['y'] > self.height:
                        col['y'] = float(random.randint(-20, -5))
                
                # Show logo in final second
                if frame > frames - 30:
                    logo_y = (self.height - len(self.logo)) // 2
                    for i, logo_line in enumerate(self.logo):
                        if logo_y + i < len(lines):
                            lines[logo_y + i] = Text.from_markup(
                                logo_line.center(self.width), 
                                style="bold magenta"
                            )
                
                full_display = "\n".join(str(line) for line in lines)
                
                progress = frame / frames
                border_color = "cyan" if progress < 0.8 else "bold magenta"
                
                live.update(Panel(
                    full_display,
                    border_style=border_color,
                    box=box.HEAVY if progress > 0.5 else None
                ))
                
                time.sleep(1/30)
        
        # Final reveal
        self._final_reveal()
    
    def _final_reveal(self):
        # Quick glitch
        for _ in range(3):
            self.console.print(Panel(
                "\n".join("".join(random.choice("░▒▓█") for _ in range(60)) for _ in range(5)),
                style=random.choice(["magenta", "cyan"]),
                box=box.DOUBLE
            ))
            time.sleep(0.05)
            self.console.clear()
        
        # Final logo
        self.console.clear()
        self.console.print(Panel(
            Align.center("\n".join(self.logo), vertical="middle"),
            border_style="bold magenta",
            box=box.DOUBLE_EDGE,
            padding=(2, 4),
            title="[bold white]◢◣◢◣ SYSTEM ONLINE ◣◢◣◢[/]"
        ), justify="center")
        
        self.console.print("\n[bold cyan blink]► PRESS ENTER TO BEGIN ANALYSIS ◄[/]", justify="center")
        input()


class CyberpunkSQLEditor:
    """Interactive SQL query editor"""
    def __init__(self):
        self.console = Console()
        
    def get_queries(self):
        self.console.clear()
        self._show_header()
        
        queries = []
        self.console.print("\n[bold magenta]╔══ QUERY COMPOSITION ═════════════════════════╗[/]")
        
        while True:
            line_num = len(queries) + 1
            prompt_text = f"[cyan]SQL:{line_num:02d}[/] [bold magenta]▸[/] "
            
            try:
                query = Prompt.ask(prompt_text, default="")
                
                if query.strip() == "" and queries and queries[-1].strip() == "":
                    queries = queries[:-1]
                    break
                
                queries.append(query)
                
                if query.strip():
                    self._show_query_preview(query)
                    
            except KeyboardInterrupt:
                return None
        
        self.console.print("[bold magenta]╚══════════════════════════════════════════════╝[/]")
        self._show_query_summary(queries)
        
        return "\n".join(queries)
    
    def _show_header(self):
        header_lines = [
            "[bold cyan]╔═══════════════════════════════════════════════╗[/]",
            "[bold cyan]║[/]  [bold magenta]◆ SQLGUARD QUERY TERMINAL v2.0 ◆[/]  [bold cyan]║[/]",
            "[bold cyan]╚═══════════════════════════════════════════════╝[/]"
        ]
        
        for line in header_lines:
            self.console.print(Align.center(line))
            time.sleep(0.1)
    
    def _show_query_preview(self, query):
        syntax = Syntax(query, "sql", theme="monokai", line_numbers=False)
        self.console.print(Panel(syntax, border_style="dim cyan", box=box.MINIMAL))
    
    def _show_query_summary(self, queries):
        valid_queries = [q for q in queries if q.strip()]
        if valid_queries:
            self.console.print(f"\n[bold green]◆ QUERIES CAPTURED: {len(valid_queries)}[/]")
            time.sleep(1)


class AnimatedAnalyzer:
    """Animated SQL analysis results with cyberpunk effects"""
    def __init__(self):
        self.console = Console()
        self.gradient_colors = ["magenta", "hot_pink", "deep_pink4", "medium_purple", "cyan"]
    
    def glitch_transition(self, duration=0.2):
        """Glitch effect between sections"""
        chars = "░▒▓█▀▄━│─╱╲"
        for _ in range(int(duration * 10)):
            glitch_line = "".join(random.choice(chars) for _ in range(80))
            self.console.print(f"[{random.choice(self.gradient_colors)}]{glitch_line}[/]", end="\r")
            time.sleep(0.02)
        self.console.print(" " * 80, end="\r")
    
    def particle_loading(self, message="PROCESSING"):
        """Particle effect loading animation"""
        particles = ["◢", "◣", "◤", "◥", "◆", "◈", "▰", "▱"]
        with Live(console=self.console, refresh_per_second=30) as live:
            for i in range(30):
                particle_field = []
                for _ in range(5):
                    line = " ".join(random.choice(particles) for _ in range(20))
                    particle_field.append(f"[{random.choice(self.gradient_colors)}]{line}[/]")
                
                live.update(Panel(
                    "\n".join(particle_field),
                    title=f"[bold white blink]◢ {message} ◣[/]",
                    border_style="cyan"
                ))
                time.sleep(0.03)
    
    def reveal_section(self, content, title="", style="cyan"):
        """Smooth reveal with gradient animation"""
        # Fade in effect
        for opacity in ["dim", "", "bold"]:
            self.console.clear()
            self.console.print(Panel(
                content,
                title=f"[{opacity} {style}]{title}[/]",
                border_style=f"{opacity} {style}",
                box=box.HEAVY
            ))
            time.sleep(0.1)
    
    def show_expandable_details(self, summary, details, expanded=False):
        """Interactive expand/collapse view"""
        if not expanded:
            self.console.print(Panel(
                summary + "\n\n[dim cyan]▼ Press ENTER to expand details ▼[/]",
                border_style="cyan"
            ))
            input()
            self.glitch_transition()
        
        # Show expanded details with animation
        self.reveal_section(details, title="◢ DETAILED ANALYSIS ◣")


# Main execution flow
def run_slowql():
    """Complete SQLGuard experience with animations"""
    console = Console()
    
    # 1. Matrix intro
    matrix = MatrixRain()
    matrix.run(duration=3)
    
    # 2. Get SQL queries
    editor = CyberpunkSQLEditor()
    sql_queries = editor.get_queries()
    
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
    
    results_summary = """[bold cyan]◆ ANALYSIS COMPLETE ◆[/]
    
[green]✓[/] 14 optimization opportunities detected
[yellow]![/] 3 critical issues found
[cyan]→[/] Performance improvement potential: 78%"""
    
    results_details = """[bold magenta]CRITICAL ISSUES:[/]
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
