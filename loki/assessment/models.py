"""
Domain models for Assessment Management and Vulnerability Findings for Loki 2.0.
Supports evidence-based confidence, reproduction records, false-positive analysis,
and finding lifecycle state machine.
"""

from typing import Any, Dict, List, Optional
from enum import Enum
import time
import uuid
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


class FindingLifecycle(str, Enum):
    DRAFT = "draft"
    DISCOVERED = "discovered"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class ReproductionRecord(BaseModel):
    """Structured proof-of-concept and reproduction trail."""
    reproduction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    payload: Optional[str] = None
    expected_behavior: str = ""
    observed_behavior: str = ""
    response_status: Optional[int] = None
    response_evidence_snippet: Optional[str] = None
    reproduced_successfully: bool = False


class DiscoveredAsset(BaseModel):
    asset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identifier: str  # domain, host, or IP
    ip_address: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict)  # port -> service
    technologies: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)


class SecurityFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    affected_asset: str
    affected_endpoint: Optional[str] = None
    category: str = "Vulnerability Assessment"
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: float = 0.0  # 0.0 to 10.0
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    confidence: ConfidenceLevel = ConfidenceLevel.POTENTIAL
    lifecycle: FindingLifecycle = FindingLifecycle.DISCOVERED
    evidence: str = ""
    evidence_hash: Optional[str] = None
    reproduction: Optional[ReproductionRecord] = None
    false_positive_risk_score: float = 0.0  # 0.0 (unlikely) to 1.0 (highly likely FP)
    false_positive_reasons: List[str] = Field(default_factory=list)
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    discovered_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


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
