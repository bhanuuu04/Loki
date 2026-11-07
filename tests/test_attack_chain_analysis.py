import hashlib

from loki.assessment.chain_analysis import analyze_attack_chains
from loki.assessment.models import (
    ConfidenceLevel,
    FindingLifecycle,
    FindingSource,
    SecurityFinding,
)


def _finding(finding_id, evidence_id, evidence, *, requires=None, enables=None):
    return SecurityFinding(
        finding_id=finding_id,
        title=f"Finding {finding_id}",
        description="Observed behavior captured by an assessment tool.",
        affected_asset="app.example.test",
        assessment_id="assessment-1",
        source=FindingSource.TOOL_CONFIRMED,
        confidence=ConfidenceLevel.HIGH,
        lifecycle=FindingLifecycle.VALIDATING,
        evidence_record_id=evidence_id,
        evidence=evidence,
        evidence_hash=hashlib.sha256(evidence.encode()).hexdigest(),
        requires=requires or [],
        enables=enables or [],
    )


def _record(evidence_id, evidence):
    raw_output = f"Scanner output: {evidence}\nEnd of captured output."
    return {
        "session_id": "assessment-1",
        "raw_output": raw_output,
        "output_hash": hashlib.sha256(raw_output.encode()).hexdigest(),
    }


def test_correlates_two_evidence_backed_findings_as_potential_chain_only():
    first_evidence = "Unauthenticated endpoint returned a restricted route marker."
    second_evidence = "Low-privilege role reached an admin-only function marker."
    records = {
        "evidence-1": _record("evidence-1", first_evidence),
        "evidence-2": _record("evidence-2", second_evidence),
    }
    findings = [
        _finding(
            "F-1", "evidence-1", first_evidence,
            enables=["authenticated_low_privilege"],
        ),
        _finding(
            "F-2", "evidence-2", second_evidence,
            requires=["authenticated_low_privilege"],
            enables=["admin_function_access"],
        ),
    ]

    chains = analyze_attack_chains(
        findings,
        evidence_lookup=records.get,
        scope_check=lambda _asset: (True, "in scope"),
    )

    assert len(chains) == 1
    assert chains[0].finding_ids == ["F-1", "F-2"]
    assert chains[0].capabilities == ["authenticated_low_privilege"]
    assert chains[0].status == "potential"
    assert "do not prove" in chains[0].note


def test_does_not_correlate_model_hypotheses_or_tampered_evidence():
    evidence = "Observed response contains a stable marker from the scanner."
    records = {
        "good": _record("good", evidence),
        "bad": {
            **_record("bad", evidence),
            "output_hash": "0" * 64,
        },
    }
    findings = [
        _finding("F-1", "good", evidence, enables=["sensitive_read"]),
        _finding("F-2", "bad", evidence, requires=["sensitive_read"]),
        _finding("F-3", "missing", evidence, requires=["sensitive_read"]),
    ]
    findings[0].source = FindingSource.MODEL_HYPOTHESIS

    chains = analyze_attack_chains(
        findings,
        evidence_lookup=records.get,
        scope_check=lambda _asset: (True, "in scope"),
    )

    assert chains == []


def test_excludes_out_of_scope_assets():
    evidence = "A scanner returned a verified route-level behavior marker."
    records = {
        "evidence-1": _record("evidence-1", evidence),
        "evidence-2": _record("evidence-2", evidence),
    }
    findings = [
        _finding("F-1", "evidence-1", evidence, enables=["ssrf"]),
        _finding("F-2", "evidence-2", evidence, requires=["ssrf"]),
    ]

    chains = analyze_attack_chains(
        findings,
        evidence_lookup=records.get,
        scope_check=lambda _asset: (False, "out of scope"),
    )

    assert chains == []
