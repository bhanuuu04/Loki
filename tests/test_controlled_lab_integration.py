import pytest
from pathlib import Path
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode, CommandRisk
from loki.security.gateway import ExecutionGateway
from loki.security.audit_logger import AuditLogger
from loki.assessment.orchestrator import AssessmentOrchestrator, AssessmentPhase, TaskStatus
from loki.assessment.validator import FindingValidator
from loki.assessment.models import SecurityFinding, DiscoveredAsset, SeverityLevel, ConfidenceLevel
from loki.assessment.db import DatabaseManager
from loki.assessment.store import AssessmentStore
from loki.tools.base import tool


@pytest.mark.asyncio
async def test_full_controlled_lab_assessment_lifecycle(tmp_path):
    lab_dir = tmp_path / "lab_assessment"
    lab_dir.mkdir(parents=True, exist_ok=True)

    # 1. Scope initialization
    scope_mgr = ScopeManager.create_explicit_scope(
        assessment_name="Controlled Lab Security Assessment",
        targets=["lab.internal.local", "192.168.50.0/24"],
        excluded_targets=["admin.lab.internal.local", "192.168.50.1"],
        allow_subdomains=True,
        allow_private_ips=True,
        author="lab_operator",
    )

    # 2. Policy & Gateway initialization
    audit_logger = AuditLogger(log_dir=str(lab_dir / "logs"))
    policy_engine = PolicyEngine(
        scope_manager=scope_mgr,
        mode=ExecutionMode.SAFE,
        audit_logger=audit_logger,
    )
    gateway = ExecutionGateway(
        scope_manager=scope_mgr,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
    )

    # 3. Persistence layer
    db = DatabaseManager(db_path=str(lab_dir / "loki_lab.db"))
    store = AssessmentStore(storage_dir=str(lab_dir / "reports"), db_manager=db)
    session = store.create_assessment("lab_sess_001", "Controlled Lab Security Assessment", scope_mgr.config)

    # 4. Orchestration Plan
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id=session.session_id,
        assessment_name="Controlled Lab Security Assessment",
        target="lab.internal.local",
    )
    orch.gateway = gateway

    # Mock tools for controlled execution
    @tool(name="dns_lookup", description="Lookup DNS")
    def lab_dns(host: str) -> str:
        return f"DNS Result for {host}: 192.168.50.10"

    @tool(name="enumerate_subdomains", description="Enumerate subdomains")
    def lab_sub(domain: str) -> str:
        return f"Discovered: app.{domain}, api.{domain}, admin.{domain}"

    @tool(name="audit_http_security_headers", description="Audit headers")
    def lab_headers(url: str) -> str:
        return f"Headers for {url}: Server: Apache/2.4.52; Missing HSTS, Missing CSP"

    @tool(name="lookup_owasp_guidelines", description="OWASP lookup")
    def lab_owasp(category: str) -> str:
        return "OWASP A05: Security Misconfiguration prevention steps."

    @tool(name="generate_assessment_report", description="Generate report")
    def lab_report(session_id: str) -> str:
        return f"Report generated successfully for session {session_id}."

    tool_map = {
        "dns_lookup": lab_dns,
        "enumerate_subdomains": lab_sub,
        "audit_http_security_headers": lab_headers,
        "lookup_owasp_guidelines": lab_owasp,
        "generate_assessment_report": lab_report,
    }

    # Execute all orchestrated tasks phase by phase
    while not orch.is_assessment_complete():
        executable_tasks = orch.get_next_tasks()
        if not executable_tasks:
            break
        for task in executable_tasks:
            await orch.execute_task(task, tool_resolver=lambda name: tool_map.get(name))

    # Verify coverage and phase progression
    assert orch.plan.coverage.coverage_percentage == 100.0
    assert AssessmentPhase.RECONNAISSANCE in orch.plan.coverage.phases_completed
    assert AssessmentPhase.REPORTING in orch.plan.coverage.phases_completed

    # 5. Asset Recording & Finding Validation
    asset = DiscoveredAsset(
        identifier="lab.internal.local",
        ip_address="192.168.50.10",
        open_ports=[80, 443],
    )
    store.record_asset(session.session_id, asset)

    # Finding 1: Valid Security Misconfiguration
    f1 = SecurityFinding(
        title="Missing HTTP Strict Transport Security (HSTS)",
        description="The web application does not enforce HTTPS connections via HSTS headers.",
        affected_asset="lab.internal.local",
        affected_endpoint="/",
        severity=SeverityLevel.LOW,
        evidence="HTTP/1.1 200 OK\nServer: Apache/2.4.52\nStrict-Transport-Security: (missing)",
        cwe_id="CWE-16",
    )
    v1 = FindingValidator.validate_and_refine(f1)
    store.add_finding(session.session_id, v1)

    # Finding 2: False-positive test (WAF block page mistakenly flagged as RCE)
    f2 = SecurityFinding(
        title="Remote Code Execution",
        description="Command returned block",
        affected_asset="lab.internal.local",
        severity=SeverityLevel.CRITICAL,
        evidence="HTTP/1.1 403 Forbidden\nAccess Denied: Request Blocked by Security Policy",
    )
    v2 = FindingValidator.validate_and_refine(f2, response_status=403)
    store.add_finding(session.session_id, v2)

    # 6. Verify transactional recovery from SQLite
    recovered_session = store.load_assessment(session.session_id)
    assert recovered_session is not None
    assert len(recovered_session.findings) == 2
    assert "lab.internal.local" in recovered_session.assets
    assert v2.false_positive_risk_score >= 0.5

    # 7. Verify audit logging captured all operations
    audit_entries = audit_logger.get_entries()
    assert len(audit_entries) >= 5
    assert all(e.is_authorized is True for e in audit_entries)
