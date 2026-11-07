"""
Built-in shell command execution tool.
Uses IsolatedExecutionEngine for real Docker/restricted subprocess sandboxing.
"""

from loki.tools.base import tool, ToolCapability
from loki.config import settings
from loki.executor.isolation import IsolatedExecutionEngine


@tool(
    name="run_command",
    description="Execute a shell command with strict sandbox isolation (Docker or restricted subprocess) and return stdout, stderr, and exit code.",
    capabilities=[ToolCapability.SYSTEM, ToolCapability.SHELL],
)
async def run_command(command: str, timeout_seconds: int = 30) -> str:
    """Run a shell command within isolated sandbox."""
    if not settings.enable_shell_execution:
        return "Error: Shell execution is disabled by configuration."

    result = await IsolatedExecutionEngine.execute_shell(
        command=command,
        timeout_seconds=float(timeout_seconds),
    )

    output_parts = [
        f"Exit code: {result.exit_code} (Sandbox: {result.backend.value})",
    ]
    if result.timed_out:
        output_parts.append(f"WARNING: Execution timed out after {timeout_seconds}s and process tree was terminated.")
    if result.stdout.strip():
        output_parts.append(f"STDOUT:\n{result.stdout.strip()}")
    if result.stderr.strip():
        output_parts.append(f"STDERR:\n{result.stderr.strip()}")
    if not result.stdout.strip() and not result.stderr.strip() and result.exit_code == 0:
        output_parts.append("Command completed successfully with no output.")

    return "\n\n".join(output_parts)
