"""
ui.py — Rich CLI dashboard.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

console = Console()

SEV_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
SEV_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


class ScannerUI:
    def __init__(self):
        self._progress = None
        self._task = None

    def print_banner(self, domain_count: int, pattern_count: int = 151):
        t = Text()
        t.append("\n  SECRET SCANNER\n", style="bold white")
        t.append(f"  {pattern_count}+ detection signatures · deobfuscation · entropy filtering\n", style="dim white")
        t.append("\n  Targets loaded: ", style="white")
        t.append(str(domain_count), style="bold green")
        t.append("\n  Authorized use on infrastructure you own only.\n", style="dim yellow")
        console.print(Panel(t, border_style="dim white", padding=(0, 1)))

    def subdomain_start(self, domain):
        console.print(f"  [cyan]🔍 Enumerating subdomains for[/cyan] [bold]{domain}[/bold]...")

    def subdomain_done(self, domain, subs):
        console.print(f"  [green]✔[/green] [bold]{domain}[/bold] → [bold white]{len(subs)}[/bold white] subdomains")

    def start_progress(self, total):
        self._progress = Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40), TextColumn("[bold white]{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console,
        )
        self._task = self._progress.add_task("[cyan]Scanning...", total=total)
        self._progress.start()

    def domain_done(self, domain, result):
        if self._progress:
            self._progress.advance(self._task)
        count = len(result.findings)
        if count > 0:
            worst = max(result.findings, key=lambda f: ["LOW","MEDIUM","HIGH","CRITICAL"].index(f.severity))
            color = SEV_COLOR.get(worst.severity, "white")
            icon  = SEV_ICON.get(worst.severity, "•")
            self._progress.console.print(f"  {icon} [bold]{domain}[/bold]  [{color}]{count} finding(s)[/{color}]")
        elif result.status == "error":
            self._progress.console.print(f"  ⚪ [dim]{domain}  {result.error}[/dim]")

    def print_summary(self, results, elapsed, show_raw=False):
        if self._progress:
            self._progress.stop()

        all_findings = [f for r in results for f in r.findings]
        ok = sum(1 for r in results if r.status == "ok")
        err = sum(1 for r in results if r.status == "error")
        paths = sum(r.paths_scanned for r in results)
        js = sum(r.js_files_scanned for r in results)

        stats = (
            f"\n  Domains scanned : [bold white]{ok}[/bold white]  Unreachable: [dim]{err}[/dim]\n"
            f"  Paths probed    : [dim]{paths}[/dim]   JS files: [dim]{js}[/dim]\n"
            f"  Total findings  : [bold {'red' if all_findings else 'green'}]{len(all_findings)}[/bold {'red' if all_findings else 'green'}]\n"
            f"  Elapsed         : [dim]{elapsed:.1f}s[/dim]\n"
        )
        console.print(Panel(stats, title="[bold]Scan Complete[/bold]", border_style="dim white"))

        if not all_findings:
            console.print("\n  [bold green]✅ No secrets found.[/bold green]\n")
            return

        table = Table(
            title=f"[bold red]⚠  {len(all_findings)} Secret(s) Found[/bold red]",
            box=box.SIMPLE_HEAD, header_style="bold white", border_style="dim white",
        )
        table.add_column("Sev", width=4)
        table.add_column("Conf", width=5)
        table.add_column("Pattern", width=30)
        table.add_column("Domain", width=24)
        table.add_column("Value", width=26)
        table.add_column("Source", width=10)
        table.add_column("URL", width=40, no_wrap=True)

        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        for f in sorted(all_findings, key=lambda x: (sev_order.get(x.severity,9), -x.confidence)):
            color = SEV_COLOR.get(f.severity, "white")
            icon  = SEV_ICON.get(f.severity, "•")
            val = f.value_raw if show_raw else f.value_masked
            table.add_row(
                icon, f"{f.confidence:.2f}",
                f"[{color}]{f.pattern_name}[/{color}]",
                f.domain,
                f"[bold yellow]{val}[/bold yellow]" if show_raw else f"[dim]{val}[/dim]",
                f.source_type,
                f"[dim]{f.source_url[:55]}[/dim]",
            )
        console.print(); console.print(table)
        if show_raw:
            console.print("  [bold red]⚠  RAW VALUES SHOWN — handle this output securely, rotate any real secrets immediately.[/bold red]\n")

    def print_report_paths(self, paths: dict):
        lines = "\n".join(f"     [cyan]{p}[/cyan]" for p in paths.values())
        console.print(f"\n  [bold green]📄 Reports saved:[/bold green]\n{lines}\n")
