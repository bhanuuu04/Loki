"""
Built-in Python execution tool for running scripts and math.
"""

import sys
import io
import contextlib
from loki.tools.base import tool


@tool(name="python_exec", description="Execute arbitrary Python code and capture printed stdout and variable outputs.")
def python_exec(code: str) -> str:
    """Execute Python code in an isolated dictionary scope."""
    stdout_capture = io.StringIO()
    local_scope: dict = {}

    try:
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stdout_capture):
            exec(code, {"__builtins__": __builtins__}, local_scope)

        output = stdout_capture.getvalue().strip()
        result_val = local_scope.get("result")
        
        response_parts = []
        if output:
            response_parts.append(f"Output:\n{output}")
        if result_val is not None:
            response_parts.append(f"Result variable: {result_val}")

        if not response_parts:
            return "Code executed successfully with no output."
        return "\n".join(response_parts)
    except Exception as e:
        return f"Python execution error: {type(e).__name__}: {str(e)}"
