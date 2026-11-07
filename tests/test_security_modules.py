import pytest
from pathlib import Path
from loki.security import ScopeManager, ScopeConfig, PolicyEngine, ExecutionMode, CommandRisk
from loki.knowledge import SecurityToolCatalog, lookup_cwe, lookup_owasp
from loki.executor import SecureProcessExecutor, OutputParser
from loki.assessment import AssessmentStore, SecurityFinding, SeverityLevel, ConfidenceLevel
from loki.reporting import ReportGenerator


def test_scope_manager_cidr_and_subdomains():
    config = ScopeConfig(
        assessment_name="Unit Test Scope",
        targets=["example.com", "10.0.0.0/24"],
        excluded_targets=["admin.example.com", "10.0.0.5"],
        allow_subdomains=True,
    )
    scope = ScopeManager(config)

    # In scope
    allowed, _ = scope.is_in_scope("example.com")
    assert allowed
    allowed_sub, _ = scope.is_in_scope("api.example.com")
    assert allowed_sub
    allowed_ip, _ = scope.is_in_scope("10.0.0.42")
    assert allowed_ip

    # Excluded
    ex_sub, reason_sub = scope.is_in_scope("admin.example.com")
    assert not ex_sub
    assert "excluded" in reason_sub

    ex_ip, reason_ip = scope.is_in_scope("10.0.0.5")
    assert not ex_ip

    # Out of scope
    out_scope, _ = scope.is_in_scope("google.com")
    assert not out_scope


def test_policy_engine_risk_and_modes():
    config = ScopeConfig(assessment_name="Policy Test", targets=["target.local"])
    scope = ScopeManager(config)
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.SAFE)

    # Low risk in SAFE mode -> permitted
    permitted, risk, _ = policy.evaluate_execution("dig", ["target.local"], target="target.local")
    assert permitted
    assert risk == CommandRisk.LOW

    # High risk in SAFE mode -> blocked by mode
    permitted_high, risk_high, reason = policy.evaluate_execution("ffuf", ["-u", "http://target.local/FUZZ"], target="target.local")
    assert not permitted_high
    assert "SAFE" in reason

    # Out of scope -> blocked
    permitted_oos, risk_oos, reason_oos = policy.evaluate_execution("dig", ["external.com"], target="external.com")
    assert not permitted_oos
    assert risk_oos == CommandRisk.BLOCKED


def test_security_tool_catalog():
    catalog = SecurityToolCatalog()
    nmap_entry = catalog.get_tool("nmap")
    assert nmap_entry is not None
    assert nmap_entry.category.value == "information_gathering"

    # Search by objective
    dns_tools = catalog.search_by_objective("dns lookup records")
    assert len(dns_tools) > 0
    names = [t.name for t in dns_tools]
    assert "dig" in names or "whois" in names


def test_cwe_and_owasp_knowledge():
    cwe = lookup_cwe("89")
    assert cwe is not None
    assert "SQL" in cwe.name
    assert len(cwe.remediation) > 0

    owasp = lookup_owasp("A01")
    assert owasp is not None
    assert owasp.name == "Broken Access Control"
    assert len(owasp.prevention_steps) > 0


@pytest.mark.asyncio
async def test_secure_process_executor():
    executor = SecureProcessExecutor(default_timeout_seconds=5.0)
    # Run a safe command (python -c "print('loki_test')")
    record = await executor.execute(["python", "-c", "print('loki_test')"])
    assert record.exit_code == 0
    assert "loki_test" in record.stdout
    assert not record.timed_out
    assert len(executor.history) >= 1


def test_assessment_and_reporting_lifecycle(tmp_path):
    store = AssessmentStore(storage_dir=str(tmp_path))
    scope = ScopeConfig(assessment_name="Lifecycle Test", targets=["test.domain"])
    session = store.create_assessment("sess_01", "Lifecycle Test", scope)

    finding = SecurityFinding(
        finding_id="FIND-101",
        title="Sample Test Finding",
        description="Detailed vulnerability description.",
        affected_asset="test.domain",
        category="Test Category",
        cwe_id="CWE-79",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CONFIRMED,
        remediation="Apply proper output encoding.",
    )
    store.add_finding("sess_01", finding)

    loaded = store.load_assessment("sess_01")
    assert len(loaded.findings) == 1

    generator = ReportGenerator(loaded)
    md = generator.to_markdown()
    html = generator.to_html()

    assert "# Security Assessment Report" in md
    assert "FIND-101" in md
    assert "HIGH" in md
    assert "<!DOCTYPE html>" in html


def test_audit_mode_allows_controlled_active_scanning():
    scope = ScopeManager(ScopeConfig(assessment_name="Audit Test", targets=["target.local"]))
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.AUDIT)
    permitted, risk, _ = policy.evaluate_execution(
        "run_command", ["command=sqlmap -u http://target.local/item?id=1"], target="target.local"
    )
    assert permitted
    assert risk == CommandRisk.HIGH


def test_bruteforce_requires_confirmed_nomercy_mode():
    scope = ScopeManager(ScopeConfig(assessment_name="Nomercy Test", targets=["target.local"]))
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.AUDIT)
    permitted, _, reason = policy.evaluate_execution(
        "run_command", ["command=hydra -l test -P passwords.txt target.local ssh"], target="target.local"
    )
    assert not permitted
    assert "NOMERCY" in reason

    with pytest.raises(PermissionError, match="explicit confirmation"):
        policy.set_mode(ExecutionMode.NOMERCY)

    policy.set_mode(ExecutionMode.NOMERCY, operator_confirmed=True)
    permitted, risk, _ = policy.evaluate_execution(
        "run_command", ["command=hydra -l test -P passwords.txt target.local ssh"], target="target.local"
    )
    assert permitted
    assert risk == CommandRisk.HIGH


@pytest.mark.parametrize("mode", [ExecutionMode.SAFE, ExecutionMode.AUDIT, ExecutionMode.NOMERCY])
def test_denial_of_service_stress_tools_are_blocked_in_every_mode(mode):
    scope = ScopeManager(ScopeConfig(assessment_name="Stress Test", targets=["target.local"]))
    policy = PolicyEngine(scope_manager=scope, mode=mode)
    permitted, risk, _ = policy.evaluate_execution(
        "run_command", ["command=hping3 --flood target.local"], target="target.local"
    )
    assert not permitted
    assert risk == CommandRisk.CRITICAL


def test_lab_data_verification_is_classified_as_high_risk_active_test():
    scope = ScopeManager(ScopeConfig(
        assessment_name="Lab Probe Policy",
        targets=["lab.example.test"],
        dns_check_enabled=False,
    ))
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.SAFE)
    risk = policy.classify_command("verify_lab_data_access", [
        "url=https://lab.example.test/api/records",
        "canary_marker=LOKI-LAB-CANARY:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ])
    assert risk == CommandRisk.HIGH

    permitted, _, reason = policy.evaluate_execution(
        "verify_lab_data_access",
        ["url=https://lab.example.test/api/records"],
        target="lab.example.test",
    )
    assert not permitted
    assert "SAFE" in reason

    policy.set_mode(ExecutionMode.NOMERCY, operator_confirmed=True)
    permitted, _, _ = policy.evaluate_execution(
        "verify_lab_data_access",
        ["url=https://lab.example.test/api/records"],
        target="lab.example.test",
    )
    assert permitted


def test_policy_engine_does_not_shlex_parse_python_source_or_payloads():
    """Unmatched quotes in non-shell tool data must not abort policy evaluation."""
    scope = ScopeManager(ScopeConfig(assessment_name="Python Parser Test", targets=["target.local"]))
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.AUDIT)

    malformed_python = "code=print('this string is deliberately unterminated"
    tokens = policy._command_tokens("python_exec", [malformed_python])
    assert tokens == ["python_exec"]

    permitted, risk, reason = policy.evaluate_execution(
        "python_exec",
        [malformed_python],
    )
    assert permitted
    assert risk == CommandRisk.MEDIUM
    assert reason


def test_policy_engine_still_classifies_shell_commands_with_unmatched_quotes():
    """Malformed shell quoting must not hide dangerous executable names."""
    scope = ScopeManager(ScopeConfig(assessment_name="Shell Parser Test", targets=["target.local"]))
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.NOMERCY)

    malformed_command = "command=hydra -l test -P words 'unterminated"
    assert policy.is_brute_force_command("run_command", [malformed_command])
    assert policy.is_brute_force_command("shell_exec", [malformed_command])
