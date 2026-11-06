"""
Cross-platform interactive arrow-key selection menu for Loki CLI.
Works on Windows (msvcrt) and Linux/macOS (termios/tty) with zero external dependencies.
"""

import sys
import os
from typing import List, Optional
from rich.console import Console

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

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            # Escape sequence (e.g. \x1b[A for UP)
            ch2 = sys.stdin.read(1)
            if ch2 == "[":
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
        elif ch in ("\x03", "\x04"):  # Ctrl+C or Ctrl+D
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


def select_from_menu(
    title: str,
    options: List[str],
    default_index: int = 0,
    descriptions: Optional[List[str]] = None,
) -> int:
    """
    Renders an interactive terminal menu navigable with Up/Down arrow keys.
    Returns the selected option's index (0-based).
    """
    if not options:
        raise ValueError("Menu options cannot be empty.")

    current_idx = max(0, min(default_index, len(options) - 1))

    # Hide cursor
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    try:
        first_render = True
        num_lines_rendered = 0

        while True:
            # Clear previous render lines
            if not first_render:
                sys.stdout.write(f"\033[{num_lines_rendered}A\033[J")
                sys.stdout.flush()

            first_render = False

            # Render title and menu options
            output_lines = [
                f"\n[bold cyan]{title}[/bold cyan]",
                "[dim](Use [bold]↑/↓[/bold] arrows or j/k to navigate, [bold]Enter[/bold] to select)[/dim]\n"
            ]

            for idx, opt in enumerate(options):
                desc_text = f" [dim]- {descriptions[idx]}[/dim]" if descriptions and idx < len(descriptions) else ""
                if idx == current_idx:
                    output_lines.append(f"  [bold green]► {opt}[/bold green]{desc_text}")
                else:
                    output_lines.append(f"    [dim]{opt}[/dim]{desc_text}")

            output_lines.append("")

            # Render using Rich console
            rendered_text = "\n".join(output_lines)
            console.print(rendered_text)

            # Calculate lines rendered for clean cursor movement
            # Add linebreaks + title lines
            num_lines_rendered = len(options) + 4

            # Read user keypress
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

    finally:
        # Show cursor again
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    return current_idx
