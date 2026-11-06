"""
Built-in filesystem tools with workspace sandboxing.
"""

import os
from pathlib import Path
from loki.tools.base import tool
from loki.config import settings


def _resolve_safe_path(filepath: str) -> Path:
    base = Path(settings.workspace_root).resolve()
    target = (base / filepath).resolve()
    # Ensure target is within base directory (or allow relative within workspace)
    try:
        target.relative_to(base)
    except ValueError:
        # If outside workspace, raise security error
        raise PermissionError(f"Access denied: path '{filepath}' is outside workspace root '{base}'")
    return target


@tool(name="read_file", description="Read text contents of a file within the workspace.")
def read_file(filepath: str) -> str:
    """Read the content of a file."""
    path = _resolve_safe_path(filepath)
    if not path.exists():
        return f"File not found: {filepath}"
    if not path.is_file():
        return f"Path is not a regular file: {filepath}"
    return path.read_text(encoding="utf-8", errors="replace")


@tool(name="write_file", description="Write text content to a file in the workspace, creating parent directories if needed.")
def write_file(filepath: str, content: str) -> str:
    """Write text content to a file."""
    path = _resolve_safe_path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"Successfully wrote {len(content)} characters to {filepath}."


@tool(name="list_dir", description="List files and directories within a given directory path.")
def list_dir(path: str = ".") -> str:
    """List entries in a directory."""
    target = _resolve_safe_path(path)
    if not target.exists():
        return f"Directory not found: {path}"
    entries = []
    for item in target.iterdir():
        kind = "[DIR]" if item.is_dir() else "[FILE]"
        entries.append(f"{kind} {item.name}")
    return "\n".join(entries) if entries else "(empty directory)"
