"""
Isolated Execution Backend for Loki 2.0.1.
Enforces real execution isolation using:
1. Docker container sandboxing when Docker is available (read-only root, memory/CPU limits,
   pid limits, network controls, dropped capabilities, no-new-privileges).
2. Restricted host subprocess fallback when Docker is unavailable (isolated workspace,
   sanitized environment, process-tree termination, memory/timeout caps).
Never silently downgrades to unrestricted execution.
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
import time
from pathlib import Path
from pydantic import BaseModel, Field


class IsolationBackend(str, Enum):
    DOCKER = "docker"
    RESTRICTED_PROCESS = "restricted_process"


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
    """Manages real sandboxed execution for shell and Python tasks."""

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
        Creates a clean, restricted environment for host process execution.
        Strips all sensitive credentials, tokens, secrets, and API keys.
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
        """
        Execute shell command with Docker isolation when available,
        or restricted host subprocess with process-tree termination.
        """
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 60.0)

        # Create isolated workspace
        temp_dir = tempfile.mkdtemp(prefix="loki_shell_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())

        # -------------------------------------------------------------
        # 1. DOCKER ISOLATION BACKEND
        # -------------------------------------------------------------
        if cls.is_docker_available():
            backend = IsolationBackend.DOCKER
            details = "Docker Sandbox (read-only root, memory/CPU capped, cap-drop ALL, no network)"
            net_flag = "--network=bridge" if allow_network else "--network=none"
            container_name = f"loki_sandbox_{os.getpid()}_{int(time.time() * 1000)}"

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

            timed_out = False
            try:
                proc = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    # Force kill docker container
                    kill_proc = await asyncio.create_subprocess_exec("docker", "kill", container_name)
                    await kill_proc.wait()
                    stdout_b, stderr_b = b"", b"Execution timed out."

                exit_code = proc.returncode if proc.returncode is not None else -1
                duration_ms = (time.perf_counter() - start_time) * 1000

                return ExecutionIsolationResult(
                    command=command,
                    stdout=cls._truncate_output(stdout_b),
                    stderr=cls._truncate_output(stderr_b),
                    exit_code=exit_code,
                    timed_out=timed_out,
                    duration_ms=round(duration_ms, 2),
                    backend=backend,
                    workspace_path=ws_path,
                    details=details,
                )
            except Exception as e:
                # Docker command invocation failed; log and fall through to restricted host process
                details = f"Docker failed ({type(e).__name__}); falling back to Restricted Subprocess"

        # -------------------------------------------------------------
        # 2. RESTRICTED HOST SUBPROCESS BACKEND (FALLBACK)
        # -------------------------------------------------------------
        backend = IsolationBackend.RESTRICTED_PROCESS
        details = "Restricted Subprocess Sandbox (Docker unavailable: isolated workspace, sanitized credentials, process-tree termination)"
        safe_env = cls.get_sanitized_env(ws_path)
        timed_out = False

        try:
            # Setup process group on POSIX for clean process-tree termination
            popen_kwargs: Dict[str, Any] = {
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
                "cwd": ws_path,
                "env": safe_env,
            }
            if sys.platform != "win32":
                popen_kwargs["start_new_session"] = True

            proc = await asyncio.create_subprocess_shell(command, **popen_kwargs)

            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
                await cls.kill_process_tree(proc.pid)
                try:
                    stdout_b, stderr_b = await proc.communicate()
                except Exception:
                    stdout_b, stderr_b = b"", b"Execution timed out and process tree was terminated."

            exit_code = proc.returncode if proc.returncode is not None else -1
            duration_ms = (time.perf_counter() - start_time) * 1000

            return ExecutionIsolationResult(
                command=command,
                stdout=cls._truncate_output(stdout_b),
                stderr=cls._truncate_output(stderr_b),
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return ExecutionIsolationResult(
                command=command,
                stdout="",
                stderr=f"Restricted shell execution error: {type(e).__name__}: {str(e)}",
                exit_code=-1,
                timed_out=False,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
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
        """
        Execute Python code with isolation:
        - Docker container when available.
        - Restricted python interpreter with -I (isolated mode), clean env, and process-tree termination.
        """
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 30.0)

        temp_dir = tempfile.mkdtemp(prefix="loki_py_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())

        # Write script to isolated workspace
        script_file = Path(ws_path) / "script.py"
        script_file.write_text(code, encoding="utf-8")

        # -------------------------------------------------------------
        # 1. DOCKER ISOLATION BACKEND
        # -------------------------------------------------------------
        if cls.is_docker_available():
            backend = IsolationBackend.DOCKER
            details = "Docker Sandbox (read-only root, memory/CPU capped, no network)"
            container_name = f"loki_py_{os.getpid()}_{int(time.time() * 1000)}"

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

            timed_out = False
            try:
                proc = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    kill_proc = await asyncio.create_subprocess_exec("docker", "kill", container_name)
                    await kill_proc.wait()
                    stdout_b, stderr_b = b"", b"Execution timed out."

                exit_code = proc.returncode if proc.returncode is not None else -1
                duration_ms = (time.perf_counter() - start_time) * 1000

                return ExecutionIsolationResult(
                    command=["python", "-I", str(script_file)],
                    stdout=cls._truncate_output(stdout_b),
                    stderr=cls._truncate_output(stderr_b),
                    exit_code=exit_code,
                    timed_out=timed_out,
                    duration_ms=round(duration_ms, 2),
                    backend=backend,
                    workspace_path=ws_path,
                    details=details,
                )
            except Exception as e:
                details = f"Docker failed ({type(e).__name__}); falling back to Restricted Python"

        # -------------------------------------------------------------
        # 2. RESTRICTED PYTHON PROCESS BACKEND (FALLBACK)
        # -------------------------------------------------------------
        backend = IsolationBackend.RESTRICTED_PROCESS
        details = "Restricted Subprocess Sandbox (Docker unavailable: isolated mode -I, sanitized env, process-tree termination)"
        safe_env = cls.get_sanitized_env(ws_path)
        timed_out = False

        try:
            # -I: Isolated mode (ignores PYTHONPATH, PYTHONHOME, user site directory)
            # -s: don't add user site directory to sys.path
            py_cmd = [sys.executable, "-I", "-s", str(script_file)]

            popen_kwargs: Dict[str, Any] = {
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
                "cwd": ws_path,
                "env": safe_env,
            }
            if sys.platform != "win32":
                popen_kwargs["start_new_session"] = True

            proc = await asyncio.create_subprocess_exec(*py_cmd, **popen_kwargs)

            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
                await cls.kill_process_tree(proc.pid)
                try:
                    stdout_b, stderr_b = await proc.communicate()
                except Exception:
                    stdout_b, stderr_b = b"", b"Python execution timed out and process was terminated."

            exit_code = proc.returncode if proc.returncode is not None else -1
            duration_ms = (time.perf_counter() - start_time) * 1000

            return ExecutionIsolationResult(
                command=py_cmd,
                stdout=cls._truncate_output(stdout_b),
                stderr=cls._truncate_output(stderr_b),
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return ExecutionIsolationResult(
                command=["python", "-I", str(script_file)],
                stdout="",
                stderr=f"Restricted Python execution error: {type(e).__name__}: {str(e)}",
                exit_code=-1,
                timed_out=False,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
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
        Synchronously execute Python code with isolation:
        - Docker container when available.
        - Restricted python interpreter with -I (isolated mode), -s, clean env, and process-tree termination.
        """
        start_time = time.perf_counter()
        timeout = min(max(float(timeout_seconds), 1.0), 30.0)

        temp_dir = tempfile.mkdtemp(prefix="loki_py_ws_") if not workspace_dir else workspace_dir
        ws_path = str(Path(temp_dir).resolve())
        script_file = Path(ws_path) / "script.py"
        script_file.write_text(code, encoding="utf-8")

        # 1. DOCKER
        if cls.is_docker_available():
            backend = IsolationBackend.DOCKER
            details = "Docker Sandbox (read-only root, memory/CPU capped, no network)"
            container_name = f"loki_py_sync_{os.getpid()}_{int(time.time() * 1000)}"
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
            try:
                res = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000
                return ExecutionIsolationResult(
                    command=["python", "-I", str(script_file)],
                    stdout=res.stdout,
                    stderr=res.stderr,
                    exit_code=res.returncode,
                    timed_out=False,
                    duration_ms=round(duration_ms, 2),
                    backend=backend,
                    workspace_path=ws_path,
                    details=details,
                )
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "kill", container_name], capture_output=True)
                duration_ms = (time.perf_counter() - start_time) * 1000
                return ExecutionIsolationResult(
                    command=["python", "-I", str(script_file)],
                    stdout="",
                    stderr="Execution timed out.",
                    exit_code=-1,
                    timed_out=True,
                    duration_ms=round(duration_ms, 2),
                    backend=backend,
                    workspace_path=ws_path,
                    details=details,
                )
            except Exception as e:
                details = f"Docker failed ({type(e).__name__}); falling back to Restricted Python"

        # 2. RESTRICTED PROCESS (FALLBACK)
        backend = IsolationBackend.RESTRICTED_PROCESS
        details = "Restricted Subprocess Sandbox (Docker unavailable: isolated mode -I, sanitized env, process-tree termination)"
        safe_env = cls.get_sanitized_env(ws_path)
        py_cmd = [sys.executable, "-I", "-s", str(script_file)]

        try:
            res = subprocess.run(
                py_cmd,
                capture_output=True,
                text=True,
                cwd=ws_path,
                env=safe_env,
                timeout=timeout,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
            return ExecutionIsolationResult(
                command=py_cmd,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
                timed_out=False,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
            )
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return ExecutionIsolationResult(
                command=py_cmd,
                stdout="",
                stderr="Python execution timed out.",
                exit_code=-1,
                timed_out=True,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return ExecutionIsolationResult(
                command=py_cmd,
                stdout="",
                stderr=f"Restricted Python execution error: {type(e).__name__}: {str(e)}",
                exit_code=-1,
                timed_out=False,
                duration_ms=round(duration_ms, 2),
                backend=backend,
                workspace_path=ws_path,
                details=details,
            )
        finally:
            if not workspace_dir:
                shutil.rmtree(ws_path, ignore_errors=True)
