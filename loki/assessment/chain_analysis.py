"""Evidence-backed correlation of individually observed security findings.

This module deliberately returns potential chains only. Finding adjacency is
not proof of exploitability; an end-to-end chain requires a separate, scoped
reproduction and direct evidence of the combined impact.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from loki.assessment.models import (
    ConfidenceLevel,
    FindingLifecycle,
    FindingSource,
    SecurityFinding,
)

CHAIN_CAPABILITIES: Set[str] = {
    "unauthenticated_access",
    "authenticated_low_privilege",
    "sensitive_read",
    "sensitive_write",
    "internal_service_access",
    "ssrf",
    "file_read",
    "code_execution",
    "privilege_escalation",
    "session_takeover",
    "account_takeover",
    "security_control_bypass",
    "admin_function_access",
    "tenant_boundary_crossing",
}


def normalize_capabilities(values: Optional[Iterable[str]]) -> List[str]:
    """Normalize declared capability labels and discard unknown labels."""
    if not values:
        return []
    normalized = {
        str(value).strip().lower().replace("-", "_").replace(" ", "_")
        for value in values
        if str(value).strip()
    }
    return sorted(normalized.intersection(CHAIN_CAPABILITIES))


class AttackChainCandidate(BaseModel):
    """A possible relationship between two or more evidence-backed findings."""

    chain_id: str
    finding_ids: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    evidence_record_ids: List[str] = Field(default_factory=list)
    status: str = "potential"
    note: str = (
        "Candidate only. Individually supported findings do not prove the combined path."
    )


def _evidence_is_anchored(
    finding: SecurityFinding,
    evidence_lookup: Callable[[str], Optional[Dict[str, Any]]],
) -> bool:
    """Require a real indexed tool record whose integrity hash and excerpt match."""
    if finding.source not in (FindingSource.TOOL_CONFIRMED, FindingSource.OPERATOR_VERIFIED):
        return False
    if finding.lifecycle in (FindingLifecycle.FALSE_POSITIVE, FindingLifecycle.CLOSED):
        return False
    if finding.confidence not in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED):
        return False
    if not finding.evidence_record_id or len((finding.evidence or "").strip()) < 15:
        return False
    record = evidence_lookup(finding.evidence_record_id)
    if not record:
        return False

    record_metadata = record.get("metadata") or {}
    if record_metadata.get("authorized") is not True:
        return False
    raw_output = str(record.get("raw_output") or "")
    output_hash = str(record.get("output_hash") or "")
    evidence_hash = hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest()
    finding_hash = hashlib.sha256(
        finding.evidence.encode("utf-8", errors="replace")
    ).hexdigest()
    return (
        bool(raw_output)
        and output_hash == evidence_hash
        and finding.evidence_hash == finding_hash
        and finding.evidence in raw_output
        and record.get("session_id") == finding.assessment_id
    )


def analyze_attack_chains(
    findings: Iterable[SecurityFinding],
    evidence_lookup: Callable[[str], Optional[Dict[str, Any]]],
    scope_check: Callable[[str], Tuple[bool, str]],
    max_chains: int = 20,
    max_depth: int = 4,
) -> List[AttackChainCandidate]:
    """Find explicit capability-to-prerequisite links among in-scope findings.

    An enabling capability in one finding must match a required capability in
    the next finding. Only findings backed by integrity-checked evidence records
    are included. Results are hypotheses, never proof of an end-to-end exploit.
    """
    usable: Dict[str, SecurityFinding] = {}
    for finding in findings:
        in_scope, _ = scope_check(finding.affected_asset)
        if not in_scope:
            continue
        if finding.false_positive_risk_score >= 0.6:
            continue
        if _evidence_is_anchored(finding, evidence_lookup):
            usable[finding.finding_id] = finding

    edges: Dict[str, List[Tuple[str, str]]] = {finding_id: [] for finding_id in usable}
    for source_id, source in usable.items():
        enabled = set(normalize_capabilities(source.enables))
        if not enabled:
            continue
        for target_id, target in usable.items():
            if source_id == target_id:
                continue
            required = set(normalize_capabilities(target.requires))
            for capability in sorted(enabled.intersection(required)):
                edges[source_id].append((target_id, capability))

    candidates: List[AttackChainCandidate] = []
    seen: Set[Tuple[str, ...]] = set()

    def walk(path: List[str], path_capabilities: List[str]) -> None:
        if len(candidates) >= max_chains:
            return
        if len(path) >= 2:
            key = tuple(path)
            if key not in seen:
                seen.add(key)
                path_findings = [usable[item] for item in path]
                evidence_ids = [
                    item.evidence_record_id for item in path_findings
                    if item.evidence_record_id
                ]
                candidates.append(
                    AttackChainCandidate(
                        chain_id="chain-" + "-".join(path),
                        finding_ids=path,
                        capabilities=sorted(set(path_capabilities)),
                        affected_assets=list(dict.fromkeys(
                            item.affected_asset for item in path_findings
                        )),
                        evidence_record_ids=evidence_ids,
                    )
                )
        if len(path) >= max_depth or len(candidates) >= max_chains:
            return
        for next_id, capability in edges.get(path[-1], []):
            if next_id not in path:
                walk(path + [next_id], path_capabilities + [capability])

    for finding_id in usable:
        walk([finding_id], [])
        if len(candidates) >= max_chains:
            break

    return candidates
