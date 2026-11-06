"""
Windows platform adapter with native process handling and WSL2 integration.
"""

from typing import List, Optional
import os
import shutil
import asyncio
from pathlib import Path

from loki.platform.adapters.base import BasePlatformAdapter
from loki.executor.process_manager import SecureProcessExecutor, ExecutionRecord
from loki.platform.detector import PlatformDetector


class WindowsPlatformAdapter(BasePlatformAdapter):
    """Execution adapter for Windows 10/11 environments with optional WSL2 bridging."""

    def __init__(self, enable_wsl_bridge: bool = True):
        super().__init__(name="windows_native")
        self.enable_wsl = enable_wsl_bridge
        self.executor = SecureProcessExecutor()
        self.wsl_available = PlatformDetector.check_wsl_available()

    def is_available(self) -> bool:
        return PlatformDetector.get_os_type() == "windows"

    def find_tool_binary(self, binary_name: str) -> Optional[str]:
        # 1. Native Windows PATH lookup
        path = shutil.which(binary_name)
        if path:
            return path

        # Try with common Windows extensions if not present
        if not binary_name.lower().endswith((".exe", ".cmd", ".bat")):
            for ext in (".exe", ".cmd", ".bat"):
                path_ext = shutil.which(f"{binary_name}{ext}")
                if path_ext:
                    return path_ext

        # 2. Check WSL2 if available and enabled
        if self.enable_wsl and self.wsl_available:
            try:
                # Run `wsl which <binary_name>`
                res = subprocess_sync(["wsl", "which", binary_name])
                if res and res.strip().startswith("/"):
                    return f"wsl:{res.strip()}"
            except Exception:
                pass

        return None

    async def execute_command(
        self,
        command_args: List[str],
        timeout_seconds: float = 60.0,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        if not command_args:
            raise ValueError("Command cannot be empty.")

        first_token = command_args[0]
        # Check if delegated to WSL
        if first_token.startswith("wsl:") or (self.enable_wsl and self.wsl_available and not self.find_native_binary(first_token)):
            wsl_bin = first_token.replace("wsl:", "")
            wsl_command = ["wsl", "-e", wsl_bin] + command_args[1:]
            return await self.executor.execute(wsl_command, timeout_seconds=timeout_seconds, cwd=cwd)

        # Standard Windows native execution
        return await self.executor.execute(command_args, timeout_seconds=timeout_seconds, cwd=cwd)

    def find_native_binary(self, binary_name: str) -> Optional[str]:
        return shutil.which(binary_name)

    def get_install_instruction(self, tool_name: str, pkg_name: Optional[str] = None) -> str:
        pkg = pkg_name or tool_name
        return (
            f"winget install {pkg}   # Or in WSL2: sudo apt update && sudo apt install -y {pkg}"
        )


def subprocess_sync(cmd: List[str]) -> Optional[str]:
    import subprocess
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None
