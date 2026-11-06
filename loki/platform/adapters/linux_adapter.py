"""
Linux & Kali Linux platform adapter.
"""

from typing import List, Optional
import os
import shutil

from loki.platform.adapters.base import BasePlatformAdapter
from loki.executor.process_manager import SecureProcessExecutor, ExecutionRecord
from loki.platform.detector import PlatformDetector


class LinuxPlatformAdapter(BasePlatformAdapter):
    """Native POSIX execution adapter for Kali Linux, Ubuntu, Debian, etc."""

    def __init__(self):
        super().__init__(name="linux_native")
        self.executor = SecureProcessExecutor()
        self.is_kali = PlatformDetector.is_kali_linux()

    def is_available(self) -> bool:
        return PlatformDetector.get_os_type() == "linux"

    def find_tool_binary(self, binary_name: str) -> Optional[str]:
        # Search PATH
        path = shutil.which(binary_name)
        if path:
            return path

        # Common Kali / security tool paths that might not be in user $PATH
        extra_paths = [
            f"/usr/sbin/{binary_name}",
            f"/sbin/{binary_name}",
            f"/usr/local/bin/{binary_name}",
            f"/opt/{binary_name}/{binary_name}",
        ]
        for ep in extra_paths:
            if os.path.exists(ep) and os.access(ep, os.X_OK):
                return ep

        return None

    async def execute_command(
        self,
        command_args: List[str],
        timeout_seconds: float = 60.0,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        resolved = command_args.copy()
        bin_path = self.find_tool_binary(command_args[0])
        if bin_path:
            resolved[0] = bin_path
        return await self.executor.execute(resolved, timeout_seconds=timeout_seconds, cwd=cwd)

    def get_install_instruction(self, tool_name: str, pkg_name: Optional[str] = None) -> str:
        pkg = pkg_name or tool_name
        return f"sudo apt update && sudo apt install -y {pkg}"
