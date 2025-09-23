# src/osint_miner/formatter.py
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from datetime import datetime 
console = Console()
TRUNCATE_LEN = 200
def print_banner():
    ascii_art = r"""
   ██████╗ ███████╗██╗███╗   ██╗████████╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗ 
  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
  ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
  ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
  ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    #console.print(ascii_art, style="bold cyan")
    #console.print(Panel.fit(Text("Designed by PRATHAM", style="bold green")))
    panel = Panel(
        Text(ascii_art, style="bold bright_cyan"),
        box=box.DOUBLE,
        padding=(1, 2),
        border_style="bright_blue",
        expand=False,
    )
    console.print(panel, justify="left")

    # Hacker-style badge/footer - monospace look with neon green
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    badge = Text.assemble(
        ("┏ ", "dim bright_black"),
        (" Designed by ", "bold white"),
        ("PRATHAM ", "bold bright_green on black"),
        (" • ", "dim bright_black"),
        (timestamp, "dim white"),
        (" ┓", "dim bright_black"),
    )
    badge_panel = Panel(badge, box=box.SQUARE, padding=(0, 1), border_style="bright_green", expand=False)
    console.print(badge_panel, justify="left")
    console.print()  # spacer
def _truncate(v: str) -> str:
    """Truncate long values for display."""
    s = str(v)
    if len(s) > TRUNCATE_LEN:
        return s[:TRUNCATE_LEN].rstrip() + " ...[truncated]"
    return s


def _print_email_sources(data: dict):
    """Special handler: Show each email once with deduplicated sources (skip 'crawl_site')."""
    table = Table(
        title="[bold green]EMAILS & SOURCES[/bold green]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Email", style="cyan", no_wrap=True)
    table.add_column("Sources", style="white")

    for email, details in data.items():
        sources = details.get("sources", [])
        clean_sources = {
            s.replace("mailto:", "").strip()
            for s in sources
            if s.lower() != "crawl_site"
        }
        sources_text = "\n".join(_truncate(s) for s in sorted(clean_sources))
        table.add_row(email, sources_text or "")

    console.print(table)


def _print_kv_table(data: dict, title: str = None):
    """Render simple key-value dict as a table."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    for k, v in data.items():
        table.add_row(str(k), _truncate(v))

    if title:
        console.print(Panel.fit(f"[bold yellow]{title}[/bold yellow]"))
    console.print(table)


def print_section(title, data, is_root=True):
    """Pretty print with Rich, showing dicts as tables, lists as tables, emails special."""
    if not data:
        return  # skip empty blocks

    if is_root and title:
        console.print(Panel.fit(f"[bold yellow]{title}[/bold yellow]"))

    # Special case: emails dict
    if isinstance(data, dict) and all(
        isinstance(v, dict) and "sources" in v for v in data.values()
    ):
        _print_email_sources(data)
        return

    # Dict with simple values
    if isinstance(data, dict) and all(
        not isinstance(v, (dict, list, dict)) for v in data.values()
    ):
        _print_kv_table(data)
        return

    # Dict with mixed/nested values
        # Dict with mixed/nested values
    if isinstance(data, dict):
        for k, v in data.items():
            console.print(Panel.fit(f"[bold cyan]{k}[/bold cyan]"))
            print_section(k, v, is_root=False)
        return

    # List of dicts → make table with keys as columns
    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        keys = sorted({k for d in data for k in d.keys()})
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan", width=4)

        for k in keys:
            table.add_column(str(k), style="white", overflow="fold")

        for idx, row in enumerate(data, 1):
            values = []
            for k in keys:
                v = row.get(k, "")
                if isinstance(v, (dict, list)):
                    v = str(v)[:TRUNCATE_LEN] + (" ...[truncated]" if len(str(v)) > TRUNCATE_LEN else "")
                values.append(str(v))
            table.add_row(str(idx), *values)

        console.print(table)
        return

    # List of items
    if isinstance(data, list):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Value", style="white")
        for idx, val in enumerate(data, 1):
            table.add_row(str(idx), _truncate(val))
        console.print(table)
        return

    # Single value
    console.print(_truncate(data))


# alias
print_table = print_section
