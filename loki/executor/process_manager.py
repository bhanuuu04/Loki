"""
Secure Subprocess and Process Execution Engine.
Uses argument arrays to prevent shell injection, enforces timeouts and handles cancellation.
"""

from typing import List, Optional
import asyncio
import time
from pydantic import BaseModel, Field


class ExecutionRecord(BaseModel):
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    timestamp: float = Field(default_factory=time.time)


class SecureProcessExecutor:
    """Manages subprocess lifecycles with argument-array safety and timeouts."""

    def __init__(self, default_timeout_seconds: float = 60.0):
        self.default_timeout = default_timeout_seconds
        self.history: List[ExecutionRecord] = []
        self._active_processes: List[asyncio.subprocess.Process] = []

    async def execute(
        self,
        command_args: List[str],
        timeout_seconds: Optional[float] = None,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        """
        Execute command using argument list directly without invoking shell.
        Prevents shell injection and parameter tampering.
        """
        timeout = timeout_seconds or self.default_timeout
        start_time = time.perf_counter()
        timed_out = False

        if not command_args:
            raise ValueError("Command arguments list cannot be empty.")

        try:
            # Execute directly with args array, NOT shell=True
            proc = await asyncio.create_subprocess_exec(
                command_args[0],
                *command_args[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            self._active_processes.append(proc)

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                timed_out = True
                proc.kill()
                stdout_bytes, stderr_bytes = await proc.communicate()
            finally:
                if proc in self._active_processes:
                    self._active_processes.remove(proc)

            duration_ms = (time.perf_counter() - start_time) * 1000
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode if proc.returncode is not None else -1

            record = ExecutionRecord(
                command=command_args,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=round(duration_ms, 2),
                timed_out=timed_out,
            )
            self.history.append(record)
            return record

        except FileNotFoundError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"Executable '{command_args[0]}' not found on system PATH."
            record = ExecutionRecord(
                command=command_args,
                exit_code=127,
                stdout="",
                stderr=err_msg,
                duration_ms=round(duration_ms, 2),
                timed_out=False,
            )
            self.history.append(record)
            return record

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"Execution exception: {type(e).__name__}: {str(e)}"
            record = ExecutionRecord(
                command=command_args,
                exit_code=-1,
                stdout="",
                stderr=err_msg,
                duration_ms=round(duration_ms, 2),
                timed_out=False,
            )
            self.history.append(record)
            return record

    def cancel_all(self) -> int:
        """Cancel and terminate any currently running subprocesses."""
        count = 0
        for proc in list(self._active_processes):
            try:
                proc.kill()
                count += 1
            except Exception:
                pass
        self._active_processes.clear()
        return count
