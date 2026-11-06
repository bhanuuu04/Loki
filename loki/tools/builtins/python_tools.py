"""
Built-in Python execution tool for running scripts, calculations, and analysis.
Executes in an isolated subprocess to prevent CLI stdout collision and hangs.
"""

import subprocess
import sys
import re
from loki.tools.base import tool


@tool(name="python_exec", description="Execute Python code in an isolated subprocess and capture stdout, stderr, and results.")
def python_exec(code: str, timeout_seconds: int = 15) -> str:
    """Execute Python code in a dedicated subprocess."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
        )
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        # Strip any stray terminal escape codes
        stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)
        stderr = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stderr)

        parts = []
        if stdout:
            parts.append(f"Output:\n{stdout}")
        if stderr:
            parts.append(f"Errors:\n{stderr}")
        if proc.returncode != 0 and not stderr:
            parts.append(f"Process exited with code: {proc.returncode}")

        if not parts:
            return "Code executed successfully with no output."
        return "\n".join(parts)
    except subprocess.TimeoutExpired:
        return f"Python execution timed out after {timeout_seconds} seconds."
    except Exception as e:
        return f"Python execution error: {type(e).__name__}: {str(e)}"
