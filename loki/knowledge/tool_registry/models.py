"""
Data models for the Security Tool Knowledge Base and Registry for Loki 2.0.
Tracks documented status, installation status, platform compatibility,
tested status, and output parser availability.
"""

from typing import Any, Dict, List, Optional
from enum import Enum
import shutil
from pydantic import BaseModel, Field


class ToolCategory(str, Enum):
    INFORMATION_GATHERING = "information_gathering"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    WEB_APPLICATION = "web_application"
    DATABASE_ASSESSMENT = "database_assessment"
    NETWORK_ANALYSIS = "network_analysis"
    API_SECURITY = "api_security"
    CONTAINER_CLOUD = "container_cloud"
    CRYPTOGRAPHY = "cryptography"
    FORENSICS = "forensics"
    REVERSE_ENGINEERING = "reverse_engineering"
    FUZZING = "fuzzing"


class CommandTemplate(BaseModel):
    purpose: str
    syntax: str
    args: List[str]
    description: str
    risk_level: str = "medium"  # low, medium, high


class SecurityToolEntry(BaseModel):
    name: str
    category: ToolCategory
    description: str
    binary_name: str
    installation_method: str  # e.g., "apt install nmap", "pip install ...", "binary"
    supported_platforms: List[str] = Field(default_factory=lambda: ["linux", "windows", "darwin"])
    commands: List[CommandTemplate] = Field(default_factory=list)
    required_inputs: List[str] = Field(default_factory=list)
    expected_outputs: List[str] = Field(default_factory=list)
    documentation_url: str = ""

    # Rigorous capability tracking fields
    documented_status: bool = True
    installed_status: bool = False
    platform_compatibility: List[str] = Field(default_factory=lambda: ["linux", "windows", "darwin"])
    tested_status: bool = False
    output_parser_availability: bool = False
    execution_handler_available: bool = False

    is_installed: bool = False
    resolved_path: Optional[str] = None

    def refresh_installed_status(self) -> bool:
        """Check if binary is executable and discoverable using platform adapter."""
        from loki.platform.adapters.factory import get_platform_adapter
        adapter = get_platform_adapter()
        path = adapter.find_tool_binary(self.binary_name)
        self.is_installed = path is not None
        self.installed_status = self.is_installed
        self.resolved_path = path
        return self.is_installed

    @property
    def is_implemented(self) -> bool:
        """
        A tool is strictly considered implemented ONLY when it is installed
        on the host AND has a tested handler or dedicated output parser.
        Mere appearance in the database never marks it as implemented.
        """
        return bool(self.is_installed and (self.execution_handler_available or self.output_parser_availability))

    def get_platform_install_hint(self) -> str:
        """Returns OS-specific installation recommendation."""
        from loki.platform.adapters.factory import get_platform_adapter
        adapter = get_platform_adapter()
        return adapter.get_install_instruction(self.name, self.binary_name)
