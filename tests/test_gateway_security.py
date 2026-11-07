import pytest
from loki.security.gateway import ExecutionGateway
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode, CommandRisk
from loki.security.audit_logger import AuditLogger
from loki.tools.base import tool, Tool
from loki.types import ToolCall


@pytest.fixture
def clean_gateway(tmp_path):
    log_dir = tmp_path / "logs"
    logger = AuditLogger(log_dir=str(log_dir))
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="Gateway Test",
            targets=["authorized.example.com", "127.0.0.1"],
            allow_loopback=True,
        )
    )
    policy = PolicyEngine(scope_manager=scope, audit_logger=logger, mode=ExecutionMode.SAFE)
    return ExecutionGateway(scope_manager=scope, policy_engine=policy, audit_logger=logger)


@pytest.mark.asyncio
async def test_gateway_unregistered_tool_rejection(clean_gateway):
    call = ToolCall(id="call_01", name="fake_tool", arguments={})
    res = await clean_gateway.execute(call, None)

    assert res.is_error
    assert "not found in registry" in res.output
    # Verify audit log recorded the blocked call
    entries = clean_gateway.audit_logger.get_entries("Gateway Test")
    assert any(e.tool_name == "fake_tool" and e.status == "blocked" for e in entries)


@pytest.mark.asyncio
async def test_gateway_argument_validation(clean_gateway):
    @tool(name="typed_tool", description="A tool with typed arguments")
    def typed_tool(target: str, count: int) -> str:
        return f"{target}:{count}"

    # Missing required argument 'count'
    call_missing = ToolCall(id="call_02", name="typed_tool", arguments={"target": "authorized.example.com"})
    res_missing = await clean_gateway.execute(call_missing, typed_tool)
    assert res_missing.is_error
    assert "Missing required parameter 'count'" in res_missing.output

    # Wrong argument type for 'count'
    call_wrong_type = ToolCall(
        id="call_03",
        name="typed_tool",
        arguments={"target": "authorized.example.com", "count": "not_an_int"},
    )
    res_wrong = await clean_gateway.execute(call_wrong_type, typed_tool)
    assert res_wrong.is_error
    assert "expected integer" in res_wrong.output


@pytest.mark.asyncio
async def test_gateway_scope_boundary_enforcement(clean_gateway):
    @tool(name="dns_lookup", description="Simulated DNS lookup")
    def mock_dns(host: str) -> str:
        return "1.2.3.4"

    # Out of scope target
    call_oos = ToolCall(id="call_04", name="dns_lookup", arguments={"host": "unauthorized-target.org"})
    res_oos = await clean_gateway.execute(call_oos, mock_dns)
    assert res_oos.is_error
    assert "Scope Violation" in res_oos.output
    assert not res_oos.metadata.get("authorized", True)


@pytest.mark.asyncio
async def test_gateway_isolation_and_destructive_pattern_blocking(clean_gateway):
    # Shell execution attempting dangerous destructive command
    call_rm = ToolCall(id="call_05", name="run_command", arguments={"command": "rm -rf /var/data"})
    @tool(name="run_command", description="Run command")
    def mock_run(command: str, timeout_seconds: int = 30) -> str:
        return "Executed"

    res_rm = await clean_gateway.execute(call_rm, mock_run)
    assert res_rm.is_error
    assert "Blocked" in res_rm.output

    # Python execution attempting root wipe
    call_py = ToolCall(id="call_06", name="python_exec", arguments={"code": "import shutil; shutil.rmtree('/')"})
    @tool(name="python_exec", description="Python exec")
    def mock_py(code: str, timeout_seconds: int = 15) -> str:
        return "Executed"

    res_py = await clean_gateway.execute(call_py, mock_py)
    assert res_py.is_error
    assert "Root directory deletion attempt detected" in res_py.output


@pytest.mark.asyncio
async def test_gateway_result_normalization(clean_gateway):
    @tool(name="ansi_tool", description="Outputs terminal colored string")
    def ansi_tool() -> str:
        return "\x1b[31mRed Text\x1b[0m and \x1b[32mGreen Text\x1b[0m"

    call = ToolCall(id="call_07", name="ansi_tool", arguments={})
    res = await clean_gateway.execute(call, ansi_tool)

    assert not res.is_error
    assert "\x1b[" not in res.output
    assert "Red Text and Green Text" == res.output
    assert res.execution_time_ms >= 0.0
    assert res.metadata["authorized"] is True


@pytest.mark.asyncio
async def test_shell_command_embedded_target_scope_enforcement(clean_gateway):
    """Verify shell commands cannot bypass scope checks by placing targets inside command strings."""
    from loki.tools.builtins.shell_tools import run_command

    # Shell command targeting out-of-scope internal/external targets
    call_curl = ToolCall(id="call_curl_01", name="run_command", arguments={"command": "curl http://secret.internal/admin"})
    res_curl = await clean_gateway.execute(call_curl, run_command)
    assert res_curl.is_error
    assert "Scope Violation" in res_curl.output

    call_nmap = ToolCall(id="call_nmap_01", name="run_command", arguments={"command": "nmap -sV 192.168.1.50"})
    res_nmap = await clean_gateway.execute(call_nmap, run_command)
    assert res_nmap.is_error
    assert "Scope Violation" in res_nmap.output

    call_meta = ToolCall(id="call_meta_01", name="run_command", arguments={"command": "curl http://169.254.169.254/latest/meta-data/"})
    res_meta = await clean_gateway.execute(call_meta, run_command)
    assert res_meta.is_error
    assert "Scope Violation" in res_meta.output


@pytest.mark.asyncio
async def test_capability_based_scope_enforcement(clean_gateway):
    """Verify tools with ToolCapability.TARGET_INTERACTION require targets and validate them."""
    from loki.tools.base import ToolCapability

    @tool(
        name="custom_scanner",
        description="Custom network scanner",
        capabilities=[ToolCapability.NETWORK, ToolCapability.TARGET_INTERACTION],
    )
    def custom_scanner(target: str) -> str:
        return f"Scanned {target}"

    # Target out of scope
    call_oos = ToolCall(id="call_cust_01", name="custom_scanner", arguments={"target": "malicious.com"})
    res_oos = await clean_gateway.execute(call_oos, custom_scanner)
    assert res_oos.is_error
    assert "Scope Violation" in res_oos.output

    # Target in scope
    call_in = ToolCall(id="call_cust_02", name="custom_scanner", arguments={"target": "authorized.example.com"})
    res_in = await clean_gateway.execute(call_in, custom_scanner)
    assert not res_in.is_error
    assert res_in.output == "Scanned authorized.example.com"


@pytest.mark.asyncio
async def test_scope_synchronization_active_agent_session():
    """Verify that updating scope via configure_scope propagates immediately to an active LokiAgent."""
    from loki.runtime.agent import LokiAgent
    from loki.security.context import AssessmentSecurityContext
    from loki.tools.security_tools import configure_scope

    # Reset to clean context
    ctx = AssessmentSecurityContext.reset_default()
    agent = LokiAgent(provider="mock")

    # Initial scope only has 127.0.0.1 and localhost
    call_init = ToolCall(id="call_sync_01", name="dns_lookup", arguments={"domain": "corp-target.net"})
    res_init = await agent.gateway.execute(call_init, agent.registry.get("dns_lookup"))
    assert res_init.is_error
    assert "Scope Violation" in res_init.output

    # Configure scope during active session
    from loki.config import settings
    operator_token = "test-operator-token-with-at-least-32-bytes"
    settings.operator_token = operator_token
    configure_scope(targets=["corp-target.net", "127.0.0.1"], assessment_name="Corp Audit", operator_token=operator_token)

    # The existing agent instance must now immediately allow corp-target.net
    assert agent.gateway.scope_manager.config.assessment_name == "Corp Audit"
    assert "corp-target.net" in agent.gateway.scope_manager.config.targets


def test_operator_authorization_rejects_arbitrary_tokens():
    """Verify arbitrary authorization tokens cannot expand scope autonomously."""
    from loki.security.context import AssessmentSecurityContext
    from loki.tools.security_tools import authorize_target

    ctx = AssessmentSecurityContext.reset_default()
    from loki.config import settings
    operator_token = "test-operator-token-with-at-least-32-bytes"
    settings.operator_token = operator_token
    from loki.tools.security_tools import configure_scope
    configure_scope(targets=["127.0.0.1"], assessment_name="Unauthorized Ticket Test", operator_token=operator_token)

    # Pass arbitrary token
    res = authorize_target("evil-unauthorized-host.org", authorization_token="any_random_token_123")
    assert "Authorization Denied" in res
    assert "Autonomous self-authorization by the model is disabled" in res


@pytest.mark.asyncio
async def test_nested_and_percent_encoded_target_extraction(clean_gateway):
    """Verify targets inside nested structures and percent-encoded URLs are extracted and validated."""
    from loki.tools.base import ToolCapability

    @tool(
        name="api_tester",
        description="Complex API caller with nested configs",
        capabilities=[ToolCapability.NETWORK, ToolCapability.TARGET_INTERACTION],
    )
    def api_tester(options: dict) -> str:
        return "Executed"

    # Nested target out of scope
    call_nested = ToolCall(
        id="call_nest_01",
        name="api_tester",
        arguments={"options": {"remote_endpoint": "https://unauthorized-internal.net/v1"}},
    )
    res_nested = await clean_gateway.execute(call_nested, api_tester)
    assert res_nested.is_error
    assert "Scope Violation" in res_nested.output

    # Percent-encoded target out of scope
    call_encoded = ToolCall(
        id="call_enc_01",
        name="api_tester",
        arguments={"options": {"url": "http%3A%2F%2Fevil-target.com%2Fexploit"}},
    )
    res_encoded = await clean_gateway.execute(call_encoded, api_tester)
    assert res_encoded.is_error
    assert "Scope Violation" in res_encoded.output


def test_signed_operator_ticket_authorization(monkeypatch, tmp_path):
    """Verify cryptographically signed operator ticket authorizes targets, while tampered tickets fail."""
    from loki.security.authorization import OperatorAuthorizationManager
    from loki.security.context import AssessmentSecurityContext
    from loki.tools.security_tools import authorize_target

    ctx = AssessmentSecurityContext.reset_default()
    monkeypatch.setenv("LOKI_AUTH_SIGNING_KEY", "test-signing-key-with-at-least-32-bytes")
    monkeypatch.setenv("LOKI_AUTH_REVOCATION_FILE", str(tmp_path / "revoked.json"))
    operator_token = "test-operator-token-with-at-least-32-bytes"
    from loki.config import settings
    settings.operator_token = operator_token
    from loki.tools.security_tools import configure_scope
    configure_scope(targets=["127.0.0.1"], assessment_name="Ticket Audit", operator_token=operator_token)
    active_assessment_id = ctx.active_assessment_id

    # 1. Generate valid signed operator ticket
    valid_ticket = OperatorAuthorizationManager.issue_ticket(
        assessment_id=active_assessment_id,
        approved_targets=["new-approved-asset.com"],
        valid_seconds=3600.0,
        operator="security_lead",
        operator_token=operator_token,
    )

    res_auth = authorize_target("new-approved-asset.com", authorization_token=valid_ticket)
    assert "has been authorized via signed operator ticket" in res_auth

    # 2. Tampered ticket (modify payload)
    tampered_ticket = valid_ticket[:-4] + "ffff"
    res_tampered = authorize_target("unauthorized-hack.com", authorization_token=tampered_ticket)
    assert "Authorization Denied" in res_tampered

    # 3. Revoked ticket
    parts = valid_ticket.split(".")
    import base64, json
    payload_dict = json.loads(base64.urlsafe_b64decode(parts[0].encode()).decode())
    ticket_id = payload_dict["ticket_id"]

    OperatorAuthorizationManager.revoke_ticket(ticket_id, reason="Operator emergency revocation")
    is_valid, reason, _ = OperatorAuthorizationManager.verify_ticket(valid_ticket, assessment_id=active_assessment_id)
    assert not is_valid
    assert "revoked" in reason.lower()


@pytest.mark.asyncio
async def test_dynamic_target_revocation_enforced_by_gateway(clean_gateway):
    """Verify revoking a target immediately blocks subsequent tool calls through the gateway."""
    @tool(name="ping_target", description="Ping target", capabilities=["network", "target_interaction"])
    def ping_target(target: str) -> str:
        return f"Pong from {target}"

    # Initial call is authorized
    call_in = ToolCall(id="call_ping_01", name="ping_target", arguments={"target": "authorized.example.com"})
    res_in = await clean_gateway.execute(call_in, ping_target)
    assert not res_in.is_error

    # Operator revokes target
    clean_gateway.scope_manager.revoke_target("authorized.example.com", reason="Audit terminated early")

    # Immediate subsequent call must be blocked
    call_revoked = ToolCall(id="call_ping_02", name="ping_target", arguments={"target": "authorized.example.com"})
    res_revoked = await clean_gateway.execute(call_revoked, ping_target)
    assert res_revoked.is_error
    assert "Scope Violation" in res_revoked.output


def test_scope_mutation_tools_are_not_exposed_to_the_agent():
    from loki.runtime.agent import LokiAgent
    agent = LokiAgent(provider="mock")
    assert agent.registry.get("configure_assessment_scope") is None
    assert agent.registry.get("authorize_target") is None


@pytest.mark.asyncio
async def test_gateway_rejects_operator_only_scope_mutator(clean_gateway):
    @tool(name="configure_assessment_scope", description="Operator-only scope mutation")
    def fake_scope_mutator(targets: str) -> str:
        return "should never execute"
    call = ToolCall(id="operator-control-call", name="configure_assessment_scope",
                    arguments={"targets": "evil.example"})
    result = await clean_gateway.execute(call, fake_scope_mutator)
    assert result.is_error
    assert "operator-only" in result.output.lower()


def test_signed_ticket_requires_assessment_binding(monkeypatch, tmp_path):
    from loki.security.authorization import OperatorAuthorizationManager
    from loki.config import settings
    settings.operator_token = "test-operator-token-with-at-least-32-bytes"
    monkeypatch.setenv("LOKI_AUTH_SIGNING_KEY", "test-signing-key-with-at-least-32-bytes")
    monkeypatch.setenv("LOKI_AUTH_REVOCATION_FILE", str(tmp_path / "revoked.json"))
    token = OperatorAuthorizationManager.issue_ticket(
        "assessment-one", ["example.com"], operator_token="test-operator-token-with-at-least-32-bytes"
    )
    valid, reason, _ = OperatorAuthorizationManager.verify_ticket(
        token, assessment_id="assessment-two", target="example.com"
    )
    assert not valid
    assert "active assessment" in reason.lower()


def test_signing_fails_without_explicit_secret(monkeypatch):
    from loki.security.authorization import OperatorAuthorizationManager
    monkeypatch.delenv("LOKI_AUTH_SIGNING_KEY", raising=False)
    from loki.config import settings
    settings.operator_token = "test-operator-token-with-at-least-32-bytes"
    with pytest.raises(RuntimeError, match="LOKI_AUTH_SIGNING_KEY"):
        OperatorAuthorizationManager.issue_ticket(
            "assessment-one", ["example.com"], operator_token=settings.operator_token
        )


def test_ticket_revocation_persists_to_disk(monkeypatch, tmp_path):
    import base64, json
    from loki.security.authorization import OperatorAuthorizationManager
    from loki.config import settings
    settings.operator_token = "test-operator-token-with-at-least-32-bytes"
    monkeypatch.setenv("LOKI_AUTH_SIGNING_KEY", "test-signing-key-with-at-least-32-bytes")
    monkeypatch.setenv("LOKI_AUTH_REVOCATION_FILE", str(tmp_path / "revoked.json"))
    from loki.config import settings
    settings.operator_token = "test-operator-token-with-at-least-32-bytes"
    token = OperatorAuthorizationManager.issue_ticket(
        "assessment-one", ["example.com"], operator_token=settings.operator_token
    )
    payload = json.loads(base64.urlsafe_b64decode(token.split(".", 1)[0] + "==").decode())
    OperatorAuthorizationManager.revoke_ticket(payload["ticket_id"], "test revocation")
    valid, reason, _ = OperatorAuthorizationManager.verify_ticket(
        token, assessment_id="assessment-one", target="example.com"
    )
    assert not valid
    assert "revoked" in reason.lower()


def test_human_approval_metadata_is_enforced(clean_gateway):
    from loki.tools.base import ToolMetadata
    @tool(name="dangerous_tool", description="Requires operator approval",
          metadata=ToolMetadata(tool_name="dangerous_tool", requires_human_approval=True))
    def dangerous_tool() -> str:
        return "should never execute"
    call = ToolCall(id="approval-required", name="dangerous_tool", arguments={})
    import asyncio
    result = asyncio.run(clean_gateway.execute(call, dangerous_tool))
    assert result.is_error
    assert result.metadata.get("requires_human_approval") is True


def test_ticket_issue_rejects_missing_operator_credential(monkeypatch):
    from loki.security.authorization import OperatorAuthorizationManager
    from loki.config import settings
    settings.operator_token = "operator-token-with-at-least-32-bytes"
    with pytest.raises(PermissionError, match="LOKI_OPERATOR_TOKEN"):
        OperatorAuthorizationManager.issue_ticket(
            "assessment-one", ["example.com"], operator_token="not-the-operator-token"
        )
