import hashlib

from loki.assessment.db import DatabaseManager
from loki.assessment.evidence import sanitize_evidence_output
from loki.assessment.models import FindingLifecycle, SeverityLevel
from loki.assessment.store import AssessmentStore
from loki.security.context import AssessmentSecurityContext
from loki.security.scope_manager import ScopeConfig, ScopeManager
from loki.tools import security_tools


def _active_assessment(tmp_path):
    db = DatabaseManager(db_path=str(tmp_path / "evidence-test.sqlite"))
    store = AssessmentStore(
        storage_dir=str(tmp_path / "assessments"),
        db_manager=db,
    )
    scope_config = ScopeConfig(
        assessment_name="Evidence test",
        targets=["app.example.test"],
        dns_check_enabled=False,
    )
    scope = ScopeManager(scope_config)
    ctx = AssessmentSecurityContext(
        scope_manager=scope,
        db_manager=db,
        assessment_store=store,
    )
    ctx.active_assessment_id = "audit_evidence_test"
    store.create_assessment(ctx.active_assessment_id, "Evidence test", scope_config)
    AssessmentSecurityContext.reset_default(ctx)
    return ctx


def _record_finding(ctx, finding_id, evidence_id, evidence, *, requires=None, enables=None):
    return security_tools.record_finding(
        session_id=ctx.active_assessment_id,
        finding_id=finding_id,
        title=f"Observed weakness {finding_id}",
        description="A behavior observed during an in-scope assessment.",
        affected_asset="app.example.test",
        severity="medium",
        remediation="Apply the relevant security control.",
        evidence_record_id=evidence_id,
        evidence=evidence,
        requires=requires or [],
        enables=enables or [],
    )


def test_sanitizer_redacts_common_secrets_and_bounds_output():
    raw = (
        "Authorization: Bearer abc.def.ghi\n"
        "Cookie: session=secret-value\n"
        "GET /?access_token=very-secret HTTP/1.1\n"
        "Observed: public route marker"
    )
    clean = sanitize_evidence_output(raw, max_chars=1024)

    assert "abc.def.ghi" not in clean
    assert "secret-value" not in clean
    assert "very-secret" not in clean
    assert "public route marker" in clean

    bounded = sanitize_evidence_output("A" * 200, max_chars=50)
    assert len(bounded) <= 80
    assert "LOKI_EVIDENCE_TRUNCATED" in bounded


def test_record_finding_requires_real_evidence_and_uses_scoped_evidence_ids(tmp_path):
    ctx = _active_assessment(tmp_path)

    rejected = _record_finding(
        ctx,
        "F-MISSING",
        "missing-evidence-id",
        "This excerpt does not exist in any stored result.",
    )
    assert "Finding rejected" in rejected

    raw = (
        "Scanner output: endpoint /profile returned the account-role marker "
        "to the test principal with HTTP 200."
    )
    evidence_id = ctx.assessment_store.index_evidence(
        session_id=ctx.active_assessment_id,
        tool_name="authorized_test_probe",
        raw_output=raw,
        metadata={"authorized": True},
    )
    recorded = _record_finding(
        ctx,
        "F-1",
        evidence_id,
        "endpoint /profile returned the account-role marker",
    )

    assert "recorded" in recorded
    assert evidence_id in recorded
    session = ctx.assessment_store.load_assessment(ctx.active_assessment_id)
    finding = next(item for item in session.findings if item.finding_id == "F-1")
    assert finding.evidence_record_id == evidence_id
    assert finding.confidence.value == "high"
    assert finding.lifecycle == FindingLifecycle.VALIDATING


def test_second_evidence_backed_finding_triggers_potential_chain_correlation(tmp_path):
    ctx = _active_assessment(tmp_path)
    evidence_a = "Observed unauthenticated profile route exposing the test principal role marker."
    evidence_b = "Observed low-privilege principal reaching a restricted administrative function marker."

    id_a = ctx.assessment_store.index_evidence(
        session_id=ctx.active_assessment_id,
        tool_name="route_probe_a",
        raw_output=f"Tool output: {evidence_a}\n",
        metadata={"authorized": True},
    )
    id_b = ctx.assessment_store.index_evidence(
        session_id=ctx.active_assessment_id,
        tool_name="route_probe_b",
        raw_output=f"Tool output: {evidence_b}\n",
        metadata={"authorized": True},
    )

    first = _record_finding(
        ctx,
        "F-CHAIN-1",
        id_a,
        evidence_a,
        enables=["authenticated_low_privilege"],
    )
    assert "recorded" in first

    second = _record_finding(
        ctx,
        "F-CHAIN-2",
        id_b,
        evidence_b,
        requires=["authenticated_low_privilege"],
        enables=["admin_function_access"],
    )

    assert "AUTOMATIC CROSS-FINDING CORRELATION" in second
    assert "POTENTIAL" in second
    assert "F-CHAIN-1 -> F-CHAIN-2" in second
    assert "do not" in second.lower() or "not confirmed" in second.lower()


def test_record_finding_rejects_excerpt_not_in_evidence_record(tmp_path):
    ctx = _active_assessment(tmp_path)
    raw = "Actual scanner output only includes a harmless public landing page."
    evidence_id = ctx.assessment_store.index_evidence(
        session_id=ctx.active_assessment_id,
        tool_name="safe_probe",
        raw_output=raw,
        metadata={"authorized": True},
    )

    result = _record_finding(
        ctx,
        "F-FABRICATED",
        evidence_id,
        "A critical SQL injection allowed database administrator access.",
    )

    assert "exact excerpt" in result
    session = ctx.assessment_store.load_assessment(ctx.active_assessment_id)
    assert all(item.finding_id != "F-FABRICATED" for item in session.findings)


def test_agent_persists_authorized_tool_output_as_redacted_evidence(tmp_path):
    from loki.runtime.agent import LokiAgent
    from loki.types import ToolCall, ToolResult

    ctx = _active_assessment(tmp_path)
    agent = LokiAgent(provider="mock")
    result = ToolResult(
        call_id="call-evidence-1",
        tool_name="audit_http_security_headers",
        output=(
            "HTTP/1.1 200 OK\n"
            "Authorization: Bearer do-not-store-this-token\n"
            "Cookie: session=do-not-store-this-cookie\n"
            "Observed: Strict-Transport-Security header is absent."
        ),
        metadata={"authorized": True, "target": "app.example.test"},
    )
    call = ToolCall(
        id="call-evidence-1",
        name="audit_http_security_headers",
        arguments={"url": "https://app.example.test"},
    )

    agent._persist_tool_evidence(call, result)

    assert "LOKI_EVIDENCE_ID:" in result.output
    assert "do-not-store-this-token" not in result.output
    assert "do-not-store-this-cookie" not in result.output
    evidence_id = result.metadata["evidence_record_id"]
    record = ctx.assessment_store.get_evidence(ctx.active_assessment_id, evidence_id)
    assert record is not None
    assert record["metadata"]["authorized"] is True
    assert "do-not-store-this-token" not in record["raw_output"]
    assert "Strict-Transport-Security header is absent" in record["raw_output"]
