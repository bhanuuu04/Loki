"""
Isolated Execution Backend for Loki 2.0.1.
Enforces real execution isolation using:
Docker-only execution with read-only root filesystems, resource limits, network controls,
dropped capabilities, no-new-privileges, and bounded output streaming. Host execution
is refused when Docker is missing or fails.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum
import asyncio
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from pydantic import BaseModel, Field


class IsolationBackend(str, Enum):
    DOCKER = "docker"
    RESTRICTED_PROCESS = "restricted_process"  # Legacy label; no longer used for host execution
    UNAVAILABLE = "unavailable"


class ExecutionIsolationResult(BaseModel):
    command: Union[str, List[str]]
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    duration_ms: float = 0.0
    backend: IsolationBackend
    workspace_path: str = ""
    details: str = ""


class IsolatedExecutionEngine:
    """Manages Docker-isolated execution for shell and Python tasks; fails closed otherwise."""

    MAX_OUTPUT_BYTES: int = 1024 * 1024  # 1 MB maximum output to prevent memory exhaustion
    _docker_checked: Optional[bool] = None

    @classmethod
    def _truncate_output(cls, data: Union[str, bytes]) -> str:
        """Safely decode and bound output buffer to MAX_OUTPUT_BYTES."""
        if isinstance(data, bytes):
            if len(data) > cls.MAX_OUTPUT_BYTES:
                return data[:cls.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace") + "\n[WARNING: Output truncated - exceeded 1MB limit]"
            return data.decode("utf-8", errors="replace")
        elif isinstance(data, str):
            if len(data.encode("utf-8", errors="replace")) > cls.MAX_OUTPUT_BYTES:
                return data[:cls.MAX_OUTPUT_BYTES] + "\n[WARNING: Output truncated - exceeded 1MB limit]"
            return data
        return str(data)


    @classmethod
    async def _kill_container(cls, container_name: str) -> None:
        """Best-effort termination of a Docker container by its unique name."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "kill", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except Exception:
            pass

    @classmethod
    async def _bounded_communicate(
        cls,
        proc: asyncio.subprocess.Process,
        timeout: float,
        container_name: str,
    ) -> Tuple[bytes, bytes, bool, bool]:
        """
        Drain stdout/stderr concurrently with a hard per-stream byte ceiling.
        Kill the container immediately when either stream crosses the limit.
        Returns (stdout, stderr, timed_out, output_limited).
        """
        terminated = False
        output_limited = False

        async def terminate() -> None:
            nonlocal terminated
            if not terminated:
                terminated = True
                await cls._kill_container(container_name)
                if proc.returncode is None:
                    await cls.kill_process_tree(proc.pid)

        async def read_limited(stream: asyncio.StreamReader) -> bytes:
            nonlocal output_limited
            chunks = bytearray()
            while len(chunks) <= cls.MAX_OUTPUT_BYTES:
                remaining = cls.MAX_OUTPUT_BYTES + 1 - len(chunks)
                chunk = await stream.read(min(65536, remaining))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) > cls.MAX_OUTPUT_BYTES:
                output_limited = True
                await terminate()
            return bytes(chunks[:cls.MAX_OUTPUT_BYTES])

        stdout_task = asyncio.create_task(read_limited(proc.stdout))
        stderr_task = asyncio.create_task(read_limited(proc.stderr))
        wait_task = asyncio.create_task(proc.wait())
        completion = asyncio.gather(stdout_task, stderr_task, wait_task)

        try:
            stdout, stderr, _ = await asyncio.wait_for(
                asyncio.shield(completion), timeout=timeout
            )
            return stdout, stderr, False, output_limited
        except asyncio.TimeoutError:
            await terminate()
            try:
                stdout, stderr, _ = await asyncio.wait_for(completion, timeout=5.0)
            except Exception:
                for task in (stdout_task, stderr_task, wait_task):
                    if not task.done():
                        task.cancel()
                stdout = stdout_task.result() if stdout_task.done() and not stdout_task.cancelled() else b""
                stderr = stderr_task.result() if stderr_task.done() and not stderr_task.cancelled() else b""
            return stdout, stderr, True, output_limited

    @classmethod
    def is_docker_available(cls) -> bool:
        """Determines if Docker daemon is accessible and responding."""
        if cls._docker_checked is not None:
            return cls._docker_checked

        docker_bin = shutil.which("docker")
        if not docker_bin:
            cls._docker_checked = False
            return False

        try:
            res = subprocess.run(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            cls._docker_checked = (res.returncode == 0)
        except Exception:
            cls._docker_checked = False

        return cls._docker_checked

    @classmethod
    def get_sanitized_env(cls, workspace_path: str) -> Dict[str, str]:
        """
        Legacy environment helper retained for compatibility; never used to execute model code.
        """
        forbidden_substrings = [
            "KEY", "TOKEN", "SECRET", "AUTH", "PASS", "CRED",
            "NVIDIA", "OPENAI", "GEMINI", "ANTHROPIC", "AWS", "GITHUB",
        ]

        safe_env = {}
        # Keep basic system execution paths
        for k in ["PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP"]:
            if k in os.environ:
                safe_env[k] = os.environ[k]

        for k, v in os.environ.items():
            if not any(f in k.upper() for f in forbidden_substrings):
                if k not in safe_env:
                    safe_env[k] = v

        # Set sandbox specific paths
        safe_env["HOME"] = workspace_path
        safe_env["TMPDIR"] = workspace_path
        safe_env["TEMP"] = workspace_path
        safe_env["PYTHONPATH"] = ""
        safe_env["PYTHONIOENCODING"] = "utf-8"
        safe_env["LOKI_ISOLATION"] = "restricted_host_sandbox"

        return safe_env

    @classmethod
    async def kill_process_tree(cls, pid: int) -> None:
        """Terminate an entire process tree including all spawned children."""
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "taskkill", "/F", "/T", "/PID", str(pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            except Exception:
                pass
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    @classmethod
    def kill_process_tree_sync(cls, pid: int) -> None:
        """Synchronously terminate an entire process tree including all spawned children."""
        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    @classmethod
    async def execute_shell(
        cls,
        command: str,
        timeout_seconds: float = 30.0,
        workspace_dir: Optional[str] = None,
        allow_network: bool = False,
    ) -> ExecutionIsolationResult:
        """Execute shell code only inside Docker; refuse unsafe host fallback."""
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 60.0)
        temp_dir = tempfile.mkdtemp(prefix="loki_shell_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())

        try:
            if not cls.is_docker_available():
                return ExecutionIsolationResult(
                    command=command,
                    stdout="",
                    stderr="Execution refused: Docker isolation is unavailable. Loki will not execute LLM-requested shell commands directly on the host.",
                    exit_code=-1,
                    timed_out=False,
                    duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                    backend=IsolationBackend.UNAVAILABLE,
                    workspace_path="",
                    details="Fail-closed: no isolated execution backend is available.",
                )

            container_name = f"loki_sandbox_{os.getpid()}_{uuid.uuid4().hex[:12]}"
            net_flag = "--network=bridge" if allow_network else "--network=none"
            docker_cmd = [
                "docker", "run", "--rm",
                "--name", container_name,
                "--read-only",
                net_flag,
                "--memory=256m",
                "--cpus=1.0",
                "--pids-limit=64",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "-v", f"{ws_path}:/workspace:rw",
                "-w", "/workspace",
                "alpine:latest",
                "sh", "-c", command,
            ]
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **({"start_new_session": True} if sys.platform != "win32" else {}),
            )
            stdout_b, stderr_b, timed_out, output_limited = await cls._bounded_communicate(
                proc, timeout, container_name
            )
            if timed_out:
                stderr_b = b"Execution timed out; Docker container was terminated."
            elif output_limited:
                stderr_b = b"Output limit exceeded; Docker container was terminated."
            return ExecutionIsolationResult(
                command=command,
                stdout=cls._truncate_output(stdout_b),
                stderr=cls._truncate_output(stderr_b),
                exit_code=proc.returncode if proc.returncode is not None else -1,
                timed_out=timed_out,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.DOCKER,
                workspace_path=ws_path if workspace_dir else "",
                details="Docker isolation: read-only root, no-new-privileges, dropped capabilities, resource limits.",
            )
        except Exception as exc:
            return ExecutionIsolationResult(
                command=command,
                stdout="",
                stderr=f"Docker isolated execution failed: {type(exc).__name__}: {exc}. Host fallback is disabled.",
                exit_code=-1,
                timed_out=False,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.UNAVAILABLE,
                workspace_path="",
                details="Fail-closed: Docker execution failed; no host fallback is permitted.",
            )
        finally:
            if not workspace_dir:
                shutil.rmtree(ws_path, ignore_errors=True)

    @classmethod
    async def execute_python(
        cls,
        code: str,
        timeout_seconds: float = 15.0,
        workspace_dir: Optional[str] = None,
    ) -> ExecutionIsolationResult:
        """Execute generated Python only in a no-network Docker container."""
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 30.0)
        temp_dir = tempfile.mkdtemp(prefix="loki_py_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())
        script_file = Path(ws_path) / "script.py"

        try:
            if not cls.is_docker_available():
                return ExecutionIsolationResult(
                    command=["python", "-I", str(script_file)],
                    stdout="",
                    stderr="Execution refused: Docker isolation is unavailable. Loki will not execute generated Python directly on the host.",
                    exit_code=-1,
                    timed_out=False,
                    duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                    backend=IsolationBackend.UNAVAILABLE,
                    workspace_path="",
                    details="Fail-closed: no isolated execution backend is available.",
                )

            script_file.write_text(code, encoding="utf-8")
            container_name = f"loki_python_{os.getpid()}_{uuid.uuid4().hex[:12]}"
            docker_cmd = [
                "docker", "run", "--rm",
                "--name", container_name,
                "--read-only",
                "--network=none",
                "--memory=256m",
                "--cpus=1.0",
                "--pids-limit=64",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "-v", f"{ws_path}:/workspace:rw",
                "-w", "/workspace",
                "python:3-alpine",
                "python", "-I", "/workspace/script.py",
            ]
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **({"start_new_session": True} if sys.platform != "win32" else {}),
            )
            stdout_b, stderr_b, timed_out, output_limited = await cls._bounded_communicate(
                proc, timeout, container_name
            )
            if timed_out:
                stderr_b = b"Python execution timed out; Docker container was terminated."
            elif output_limited:
                stderr_b = b"Output limit exceeded; Docker container was terminated."
            return ExecutionIsolationResult(
                command=["python", "-I", "/workspace/script.py"],
                stdout=cls._truncate_output(stdout_b),
                stderr=cls._truncate_output(stderr_b),
                exit_code=proc.returncode if proc.returncode is not None else -1,
                timed_out=timed_out,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.DOCKER,
                workspace_path=ws_path if workspace_dir else "",
                details="Docker isolation: no network, read-only root, no-new-privileges, resource limits.",
            )
        except Exception as exc:
            return ExecutionIsolationResult(
                command=["python", "-I", str(script_file)],
                stdout="",
                stderr=f"Docker isolated Python execution failed: {type(exc).__name__}: {exc}. Host fallback is disabled.",
                exit_code=-1,
                timed_out=False,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.UNAVAILABLE,
                workspace_path="",
                details="Fail-closed: Docker execution failed; no host fallback is permitted.",
            )
        finally:
            if not workspace_dir:
                shutil.rmtree(ws_path, ignore_errors=True)

    @classmethod
    def execute_python_sync(
        cls,
        code: str,
        timeout_seconds: float = 15.0,
        workspace_dir: Optional[str] = None,
    ) -> ExecutionIsolationResult:
        """
        Synchronously execute Python inside Docker only.
        Host interpreter fallback is deliberately disabled.
        Stdout and stderr are drained by bounded reader threads.
        """
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 30.0)
        temp_dir = tempfile.mkdtemp(prefix="loki_py_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())
        script_file = Path(ws_path) / "script.py"

        try:
            if not cls.is_docker_available():
                return ExecutionIsolationResult(
                    command=["python", "-I", str(script_file)],
                    stdout="",
                    stderr="Execution refused: Docker isolation is unavailable. Loki will not execute generated Python directly on the host.",
                    exit_code=-1,
                    timed_out=False,
                    duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                    backend=IsolationBackend.UNAVAILABLE,
                    workspace_path="",
                    details="Fail-closed: no isolated execution backend is available.",
                )

            script_file.write_text(code, encoding="utf-8")
            container_name = f"loki_py_sync_{os.getpid()}_{uuid.uuid4().hex[:12]}"
            docker_cmd = [
                "docker", "run", "--rm",
                "--name", container_name,
                "--read-only",
                "--network=none",
                "--memory=256m",
                "--cpus=1.0",
                "--pids-limit=64",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "-v", f"{ws_path}:/workspace:rw",
                "-w", "/workspace",
                "python:3-alpine",
                "python", "-I", "/workspace/script.py",
            ]

            proc = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output_limited = threading.Event()
            termination_started = threading.Event()
            termination_lock = threading.Lock()

            def terminate_container() -> None:
                with termination_lock:
                    if termination_started.is_set():
                        return
                    termination_started.set()
                try:
                    subprocess.run(
                        ["docker", "kill", container_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=3.0,
                        check=False,
                    )
                except Exception:
                    pass
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass

            def read_bounded(pipe) -> bytes:
                data = bytearray()
                try:
                    while len(data) <= cls.MAX_OUTPUT_BYTES:
                        remaining = cls.MAX_OUTPUT_BYTES + 1 - len(data)
                        chunk = pipe.read(min(65536, remaining))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) > cls.MAX_OUTPUT_BYTES:
                        output_limited.set()
                        terminate_container()
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass
                return bytes(data[:cls.MAX_OUTPUT_BYTES])

            stdout_result: Dict[str, bytes] = {}
            stderr_result: Dict[str, bytes] = {}

            def capture_stdout() -> None:
                stdout_result["data"] = read_bounded(proc.stdout)

            def capture_stderr() -> None:
                stderr_result["data"] = read_bounded(proc.stderr)

            stdout_thread = threading.Thread(target=capture_stdout, daemon=True)
            stderr_thread = threading.Thread(target=capture_stderr, daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_container()
                try:
                    proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)

            stdout_thread.join(timeout=5.0)
            stderr_thread.join(timeout=5.0)
            stdout_b = stdout_result.get("data", b"")
            stderr_b = stderr_result.get("data", b"")

            if timed_out:
                stderr_b = b"Python execution timed out; Docker container was terminated."
            elif output_limited.is_set():
                stderr_b = b"Output limit exceeded; Docker container was terminated."

            return ExecutionIsolationResult(
                command=["python", "-I", "/workspace/script.py"],
                stdout=cls._truncate_output(stdout_b),
                stderr=cls._truncate_output(stderr_b),
                exit_code=proc.returncode if proc.returncode is not None else -1,
                timed_out=timed_out,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.DOCKER,
                workspace_path=ws_path if workspace_dir else "",
                details="Docker isolation: no network, read-only root, no-new-privileges, resource limits and bounded output.",
            )
        except Exception as exc:
            return ExecutionIsolationResult(
                command=["python", "-I", str(script_file)],
                stdout="",
                stderr=f"Docker isolated Python execution failed: {type(exc).__name__}: {exc}. Host fallback is disabled.",
                exit_code=-1,
                timed_out=False,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                backend=IsolationBackend.UNAVAILABLE,
                workspace_path="",
                details="Fail-closed: Docker execution failed; no host fallback is permitted.",
            )
        finally:
            if not workspace_dir:
                shutil.rmtree(ws_path, ignore_errors=True)

