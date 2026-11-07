"""
Built-in Python execution tool for running scripts, calculations, and analysis.
Uses IsolatedExecutionEngine for real Docker or restricted subprocess (-I, sanitized env,
isolated workspace, process-tree termination) sandboxing.
"""

from loki.tools.base import tool, ToolCapability
from loki.executor.isolation import IsolatedExecutionEngine


@tool(
    name="python_exec",
    description="Execute Python code inside a no-network Docker sandbox with resource limits and bounded output. Refuses execution when Docker isolation is unavailable.",
    capabilities=[ToolCapability.SYSTEM, ToolCapability.PYTHON],
)
def python_exec(code: str, timeout_seconds: int = 15) -> str:
    """Execute Python code in an isolated sandbox."""
    result = IsolatedExecutionEngine.execute_python_sync(
        code=code,
        timeout_seconds=float(timeout_seconds),
    )

    parts = []
    if result.stdout.strip():
        parts.append(f"Output:\n{result.stdout.strip()}")
    if result.stderr.strip():
        parts.append(f"Errors:\n{result.stderr.strip()}")
    if result.timed_out:
        parts.append(f"Python execution timed out after {timeout_seconds} seconds.")
    elif result.exit_code != 0 and not result.stderr.strip():
        parts.append(f"Process exited with code: {result.exit_code}")

    if not parts:
        return "Code executed successfully with no output."
    return "\n".join(parts)
