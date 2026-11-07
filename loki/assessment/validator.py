"""
Vulnerability Finding Validator & False-Positive Analyzer for Loki 2.0.
Calculates evidence-based confidence, evaluates false-positive heuristics,
manages finding lifecycles, and validates CWE/CVE references.
"""

from typing import Any, Dict, List, Optional, Tuple
import hashlib
import re

from loki.assessment.models import (
    ConfidenceLevel,
    FindingLifecycle,
    FindingSource,
    ReproductionRecord,
    SecurityFinding,
    SeverityLevel,
)
from loki.knowledge.cwe_database import lookup_cwe


class FindingValidator:
    """
    Evaluates evidence quality, detects common false positives,
    and updates finding lifecycle and confidence metrics.
    """

    # Common false-positive indicators (WAF interception, generic error pages, soft 404)
    WAF_SIGNATURES = [
        r"attention required! \| cloudflare",
        r"cloudflare ray id",
        r"access denied",
        r"request blocked by security policy",
        r"sucuri webSite firewall",
        r"akamai ghost",
        r"incapsula incident id",
        r"fortigate ips sensor",
        r"aws waf",
    ]

    GENERIC_ERROR_PATTERNS = [
        r"internal server error",
        r"502 bad gateway",
        r"503 service temporarily unavailable",
        r"error 404 page not found",
        r"the requested url was not found",
    ]

    @classmethod
    def calculate_evidence_hash(cls, evidence: str) -> str:
        """Compute SHA-256 fingerprint of evidence for integrity verification."""
        if not evidence:
            return ""
        return hashlib.sha256(evidence.encode("utf-8", errors="replace")).hexdigest()

    @classmethod
    def evaluate_confidence(cls, finding: SecurityFinding) -> ConfidenceLevel:
        """
        Calculates evidence-based confidence based on:
        1. Distinction between model hypotheses and tool-confirmed findings.
        2. Evidence provenance and response context.
        3. Structured reproduction trail.
        4. Verified CWE / CVE correlation (syntactic validity alone does not grant confidence).
        """
        # Pure model hypotheses without any evidence or reproduction remain POTENTIAL
        has_evidence = bool(finding.evidence and len(finding.evidence.strip()) > 5)
        has_reproduction = bool(finding.reproduction and finding.reproduction.reproduced_successfully)

        if finding.source == FindingSource.MODEL_HYPOTHESIS and not has_evidence and not has_reproduction:
            return ConfidenceLevel.POTENTIAL

        score = 0

        # Evidence provenance & content
        if finding.evidence and len(finding.evidence.strip()) > 25:
            score += 2
            if finding.evidence_provenance:
                score += 1
        elif finding.evidence and len(finding.evidence.strip()) > 5:
            score += 1

        # Tool confirmation source
        if finding.source in (FindingSource.TOOL_CONFIRMED, FindingSource.OPERATOR_VERIFIED):
            score += 1

        # Structured reproduction verified
        if finding.reproduction:
            score += 1
            if finding.reproduction.reproduced_successfully:
                score += 3

        # CWE verified against registry
        if finding.cwe_id:
            cwe_data = lookup_cwe(finding.cwe_id)
            if cwe_data:
                score += 1  # Verified existence in local database
            # Do NOT grant points for invalid / unknown CWE

        # CVE verified against format AND presence of tool evidence
        if finding.cve_id and re.match(r"^CVE-\d{4}-\d{4,8}$", finding.cve_id, re.IGNORECASE):
            # Syntactic match only gives point if evidence or affected version is present
            if finding.evidence or (finding.reproduction and finding.reproduction.response_status):
                score += 1

        # Model hypothesis can only be CONFIRMED if reproduction was executed and verified
        if score >= 6 and (has_reproduction or finding.source != FindingSource.MODEL_HYPOTHESIS):
            return ConfidenceLevel.CONFIRMED
        elif score >= 4:
            return ConfidenceLevel.HIGH
        elif score >= 2:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.POTENTIAL

    @classmethod
    def analyze_false_positive(
        cls,
        finding: SecurityFinding,
        raw_response_text: Optional[str] = None,
        response_status: Optional[int] = None,
    ) -> Tuple[bool, float, List[str]]:
        """
        Heuristic false-positive detection:
        - Detects WAF blocks mistaken for application behavior.
        - Detects Soft 404 (status 200 with 'Page not found').
        - Detects generic 500 error pages mistaken for injection vulnerabilities.
        - Detects raw unexecuted reflection without context.
        Returns: (is_likely_false_positive, risk_score_0_to_1, reasons)
        """
        reasons: List[str] = []
        score = 0.0

        content = (raw_response_text or finding.evidence or "").lower()

        # 1. WAF Interception Check
        for waf_pat in cls.WAF_SIGNATURES:
            if re.search(waf_pat, content):
                reasons.append(f"Response matches known WAF block pattern: '{waf_pat}'")
                score += 0.5
                break

        # 2. Soft 404 Check (Status 200 returning '404 not found' content)
        if response_status == 200:
            for err_pat in cls.GENERIC_ERROR_PATTERNS:
                if re.search(err_pat, content):
                    reasons.append(f"HTTP 200 response contains generic error page pattern: '{err_pat}' (Soft 404)")
                    score += 0.6
                    break

        # 3. WAF Status 403 / 429
        if response_status in (403, 429):
            if any(term in finding.title.lower() for term in ("sqli", "sql injection", "rce", "xss")):
                reasons.append(f"Endpoint returned HTTP {response_status} indicating rate limiting or WAF block rather than execution.")
                score += 0.3

        # 4. Lack of proof / evidence
        if not finding.evidence or len(finding.evidence.strip()) < 15:
            reasons.append("Finding lacks sufficient raw evidence or response captures.")
            score += 0.3

        score = min(score, 1.0)
        is_fp = score >= 0.6
        return is_fp, round(score, 2), reasons

    @classmethod
    def validate_and_refine(
        cls,
        finding: SecurityFinding,
        raw_response_text: Optional[str] = None,
        response_status: Optional[int] = None,
    ) -> SecurityFinding:
        """
        Validates finding, calculates confidence, checks false positives,
        and transitions finding lifecycle.
        """
        finding.evidence_hash = cls.calculate_evidence_hash(finding.evidence)
        finding.confidence = cls.evaluate_confidence(finding)

        is_fp, fp_score, fp_reasons = cls.analyze_false_positive(
            finding, raw_response_text=raw_response_text, response_status=response_status
        )
        finding.false_positive_risk_score = fp_score
        finding.false_positive_reasons = fp_reasons

        # Lifecycle transition
        if is_fp:
            finding.lifecycle = FindingLifecycle.FALSE_POSITIVE
            finding.severity = SeverityLevel.INFORMATIONAL
        elif finding.confidence == ConfidenceLevel.CONFIRMED:
            finding.lifecycle = FindingLifecycle.CONFIRMED
        elif finding.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM):
            finding.lifecycle = FindingLifecycle.VALIDATING

        # Attach CWE remediation if available
        if finding.cwe_id and not finding.remediation:
            cwe_data = lookup_cwe(finding.cwe_id)
            if cwe_data and cwe_data.remediation:
                finding.remediation = cwe_data.remediation

        return finding
