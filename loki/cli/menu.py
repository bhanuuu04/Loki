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
    try:
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            ch2 = msvcrt.getch()
            if ch2 in (b"H", b"\x48"):
                return "UP"
            elif ch2 in (b"P", b"\x50"):
                return "DOWN"
            elif ch2 in (b"K", b"\x4b"):
                return "LEFT"
            elif ch2 in (b"M", b"\x4d"):
                return "RIGHT"
        elif ch in (b"\r", b"\n"):
            return "ENTER"
        elif ch == b"\x03":  # Ctrl+C
            raise KeyboardInterrupt
        elif ch in (b"k", b"w", b"K", b"W"):
            return "UP"
        elif ch in (b"j", b"s", b"J", b"S"):
            return "DOWN"
        elif ch.isdigit():
            return f"NUM_{ch.decode('ascii', errors='ignore')}"
    except KeyboardInterrupt:
        raise
    except Exception:
        pass
    return ""


def _get_key_unix() -> str:
    import termios
    import tty
    import select

    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except Exception:
        return "ENTER"

    try:
        tty.setraw(fd)
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            # Read subsequent bytes of escape sequence with timeout
            seq = b""
            while True:
                r, _, _ = select.select([fd], [], [], 0.15)
                if not r:
                    break
                part = os.read(fd, 1)
                if not part:
                    break
                seq += part
                if part.isalpha() or part == b"~":
                    break

            if seq in (b"[A", b"OA", b"[1;5A", b"[1;2A") or seq.endswith(b"A"):
                return "UP"
            elif seq in (b"[B", b"OB", b"[1;5B", b"[1;2B") or seq.endswith(b"B"):
                return "DOWN"
            elif seq in (b"[C", b"OC"):
                return "RIGHT"
            elif seq in (b"[D", b"OD"):
                return "LEFT"
            return ""

        elif ch in (b"\r", b"\n"):
            return "ENTER"
        elif ch == b"\x03":  # Ctrl+C
            raise KeyboardInterrupt
        elif ch == b"\x04":  # Ctrl+D
            return "ENTER"
        elif ch in (b"k", b"w", b"K", b"W"):
            return "UP"
        elif ch in (b"j", b"s", b"J", b"S"):
            return "DOWN"
        elif ch.isdigit():
            return f"NUM_{ch.decode('ascii', errors='ignore')}"
        return ""
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            pass


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
        subtitle="[dim]Use [bold]↑/↓[/bold] arrows (or j/k, 1-9) to navigate, [bold]Enter[/bold] to select[/dim]",
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

    # Guard against non-interactive stdin (CI, pipes, redirects)
    if not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        return current_idx

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

            try:
                key = get_key()
            except (KeyboardInterrupt, EOFError):
                break

            if key == "UP":
                current_idx = (current_idx - 1) % len(options)
            elif key == "DOWN":
                current_idx = (current_idx + 1) % len(options)
            elif key.startswith("NUM_"):
                num = int(key.split("_")[1])
                if 1 <= num <= len(options):
                    current_idx = num - 1
            elif key == "ENTER":
                break

    return current_idx
