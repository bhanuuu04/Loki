"""
Built-in shell command execution tool.
"""

import asyncio
import subprocess
from loki.tools.base import tool
from loki.config import settings


@tool(name="run_command", description="Execute a shell command asynchronously and return stdout, stderr, and exit code.")
async def run_command(command: str, timeout_seconds: int = 30) -> str:
    """Run a shell command."""
    if not settings.enable_shell_execution:
        return "Error: Shell execution is disabled by configuration."

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout_seconds)
            )
        except asyncio.TimeoutError:
            proc.kill()
            return f"Command timed out after {timeout_seconds} seconds."

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        code = proc.returncode

        output_parts = [f"Exit code: {code}"]
        if stdout:
            output_parts.append(f"STDOUT:\n{stdout.strip()}")
        if stderr:
            output_parts.append(f"STDERR:\n{stderr.strip()}")

        return "\n\n".join(output_parts)
    except Exception as e:
        return f"Shell execution error: {type(e).__name__}: {str(e)}"
