"""
Data models for the Security Tool Knowledge Base and Registry.
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
    supported_platforms: List[str] = ["linux", "windows", "darwin"]
    commands: List[CommandTemplate] = Field(default_factory=list)
    required_inputs: List[str] = Field(default_factory=list)
    expected_outputs: List[str] = Field(default_factory=list)
    documentation_url: str = ""
    is_installed: bool = False
    resolved_path: Optional[str] = None

    def refresh_installed_status(self) -> bool:
        """Check if binary is executable and discoverable on PATH."""
        path = shutil.which(self.binary_name)
        self.is_installed = path is not None
        self.resolved_path = path
        return self.is_installed
