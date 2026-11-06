"""
Domain models for Assessment Management and Vulnerability Findings.
"""

from typing import Any, Dict, List, Optional
from enum import Enum
import time
from pydantic import BaseModel, Field

from loki.security.scope_manager import ScopeConfig
from loki.security.policy_engine import ExecutionMode


class SeverityLevel(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    POTENTIAL = "potential"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class DiscoveredAsset(BaseModel):
    identifier: str  # domain, host, or IP
    ip_address: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict)  # port -> service
    technologies: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)


class SecurityFinding(BaseModel):
    finding_id: str
    title: str
    description: str
    affected_asset: str
    affected_endpoint: Optional[str] = None
    category: str  # OWASP or general category
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: float = 0.0  # 0.0 to 10.0
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    confidence: ConfidenceLevel = ConfidenceLevel.POTENTIAL
    evidence: str = ""
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    discovered_at: float = Field(default_factory=time.time)


class AssessmentSession(BaseModel):
    session_id: str
    assessment_name: str
    scope: ScopeConfig
    execution_mode: ExecutionMode = ExecutionMode.SAFE
    status: str = "active"  # active, paused, completed, stopped
    assets: Dict[str, DiscoveredAsset] = Field(default_factory=dict)
    findings: List[SecurityFinding] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
