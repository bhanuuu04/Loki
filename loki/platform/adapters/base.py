"""
Base interface for OS-specific execution adapters.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pydantic import BaseModel
from loki.executor.process_manager import ExecutionRecord


class BasePlatformAdapter(ABC):
    """Abstract adapter defining OS-specific tool discovery and process execution."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this adapter can execute on current environment."""
        pass

    @abstractmethod
    def find_tool_binary(self, binary_name: str) -> Optional[str]:
        """Resolves full executable path or command for a given security tool."""
        pass

    @abstractmethod
    async def execute_command(
        self,
        command_args: List[str],
        timeout_seconds: float = 60.0,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        """Executes a command safely using OS-appropriate process handling."""
        pass

    @abstractmethod
    def get_install_instruction(self, tool_name: str, pkg_name: Optional[str] = None) -> str:
        """Returns the platform-specific package manager install command."""
        pass
