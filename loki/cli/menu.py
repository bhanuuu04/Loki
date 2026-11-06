"""
Cross-platform interactive arrow-key selection menu for Loki CLI.
Uses Rich Live display to prevent terminal scrolling/flicker and supports Windows & Linux.
"""

import sys
import os
import time
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

console = Console(force_terminal=True)


def _get_key_windows() -> str:
    import msvcrt
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):
        ch2 = msvcrt.getch()
        if ch2 == b"H":
            return "UP"
        elif ch2 == b"P":
            return "DOWN"
        elif ch2 == b"K":
            return "LEFT"
        elif ch2 == b"M":
            return "RIGHT"
    elif ch in (b"\r", b"\n"):
        return "ENTER"
    elif ch in (b"\x03", b"\x1b"):  # Ctrl+C or ESC
        return "EXIT"
    elif ch == b"k":
        return "UP"
    elif ch == b"j":
        return "DOWN"
    return ""


def _get_key_unix() -> str:
    import termios
    import tty
    import select

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            # Check if more characters are available immediately (escape sequence)
            r, _, _ = select.select([sys.stdin], [], [], 0.05)
            if r:
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    r2, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r2:
                        ch3 = sys.stdin.read(1)
                        if ch3 == "A":
                            return "UP"
                        elif ch3 == "B":
                            return "DOWN"
                        elif ch3 == "C":
                            return "RIGHT"
                        elif ch3 == "D":
                            return "LEFT"
            return "EXIT"
        elif ch in ("\r", "\n"):
            return "ENTER"
        elif ch in ("\x03", "\x04"):  # Ctrl+C / Ctrl+D
            return "EXIT"
        elif ch == "k":
            return "UP"
        elif ch == "j":
            return "DOWN"
        return ""
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def get_key() -> str:
    """Reads a single keypress cross-platform."""
    if sys.platform == "win32":
        return _get_key_windows()
    else:
        return _get_key_unix()


def _render_menu_panel(
    title: str,
    options: List[str],
    current_idx: int,
    descriptions: Optional[List[str]] = None,
    max_visible: int = 12,
) -> Panel:
    """Creates a scrollable table panel for the menu."""
    table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    table.add_column("Indicator", style="bold green", width=3)
    table.add_column("Option", style="white", ratio=2)
    if descriptions:
        table.add_column("Description", style="dim", ratio=3)

    # Calculate sliding window if options list is long
    total = len(options)
    half = max_visible // 2
    if total <= max_visible:
        start_idx = 0
        end_idx = total
    else:
        start_idx = max(0, min(current_idx - half, total - max_visible))
        end_idx = min(total, start_idx + max_visible)

    for idx in range(start_idx, end_idx):
        opt = options[idx]
        desc = descriptions[idx] if descriptions and idx < len(descriptions) else ""
        if idx == current_idx:
            row = ["[bold green]►[/bold green]", f"[bold green]{opt}[/bold green]"]
            if descriptions:
                row.append(f"[green]{desc}[/green]")
            table.add_row(*row)
        else:
            row = [" ", f"[dim]{opt}[/dim]"]
            if descriptions:
                row.append(f"[dim]{desc}[/dim]")
            table.add_row(*row)

    scroll_hint = f" ({current_idx + 1}/{total})" if total > max_visible else ""
    return Panel(
        table,
        title=f"[bold cyan]{title}{scroll_hint}[/bold cyan]",
        subtitle="[dim]Use [bold]↑/↓[/bold] arrows (or j/k) to navigate, [bold]Enter[/bold] to select[/dim]",
        border_style="cyan",
    )


def select_from_menu(
    title: str,
    options: List[str],
    default_index: int = 0,
    descriptions: Optional[List[str]] = None,
) -> int:
    """
    Renders an interactive terminal menu using Rich Live display.
    Guarantees in-place rendering without scrolling up/flicker.
    """
    if not options:
        raise ValueError("Menu options cannot be empty.")

    current_idx = max(0, min(default_index, len(options) - 1))

    # Use Rich Live context manager to control the terminal buffer cleanly
    with Live(
        _render_menu_panel(title, options, current_idx, descriptions),
        console=console,
        auto_refresh=False,
        transient=False,
    ) as live:
        while True:
            live.update(_render_menu_panel(title, options, current_idx, descriptions))
            live.refresh()

            key = get_key()
            if key == "UP":
                current_idx = (current_idx - 1) % len(options)
            elif key == "DOWN":
                current_idx = (current_idx + 1) % len(options)
            elif key == "ENTER":
                break
            elif key == "EXIT":
                console.print("\n[dim]Selection cancelled.[/dim]")
                sys.exit(0)

    return current_idx
