# report.py - Module for displaying results
from rich.table import Table
from rich.console import Console
from rich import print as rprint

def display_results(title, data):
    """Display results in a formatted table."""
    console = Console()
    
    if data:
        table = Table(title=title, show_header=True, header_style="bold red")
        table.add_column("Key", style="bold blue")
        table.add_column("Value", style="bold green" )
        
        for key, value in data.items():
            table.add_row(str(key), str(value))
        
        console.print(table)
    else:
        rprint(f"[bold red]{title}: Not Available[/bold red]")
