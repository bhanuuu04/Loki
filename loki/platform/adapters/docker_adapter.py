"""
Docker-based isolated execution adapter for security tools.
"""

from typing import List, Optional
import shutil

from loki.platform.adapters.base import BasePlatformAdapter
from loki.executor.process_manager import SecureProcessExecutor, ExecutionRecord
from loki.platform.detector import PlatformDetector


class DockerPlatformAdapter(BasePlatformAdapter):
    """Executes tools inside an isolated container (e.g. kalilinux/kali-rolling)."""

    def __init__(self, image: str = "kalilinux/kali-rolling"):
        super().__init__(name="docker_isolated")
        self.image = image
        self.executor = SecureProcessExecutor()

    def is_available(self) -> bool:
        return PlatformDetector.check_docker_available()

    def find_tool_binary(self, binary_name: str) -> Optional[str]:
        # Within docker, tools are referenced by name inside the container
        return f"docker:{binary_name}"

    async def execute_command(
        self,
        command_args: List[str],
        timeout_seconds: float = 60.0,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        # Wrap in `docker run --rm <image> <command...>`
        docker_cmd = ["docker", "run", "--rm", "-i"]
        if cwd:
            docker_cmd.extend(["-v", f"{cwd}:/workspace", "-w", "/workspace"])
        docker_cmd.append(self.image)
        docker_cmd.extend(command_args)

        return await self.executor.execute(docker_cmd, timeout_seconds=timeout_seconds, cwd=cwd)

    def get_install_instruction(self, tool_name: str, pkg_name: Optional[str] = None) -> str:
        pkg = pkg_name or tool_name
        return f"docker run --rm {self.image} apt-get update && apt-get install -y {pkg}"
