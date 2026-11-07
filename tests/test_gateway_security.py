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
    configure_scope(targets=["corp-target.net", "127.0.0.1"], assessment_name="Corp Audit")

    # The existing agent instance must now immediately allow corp-target.net
    assert agent.gateway.scope_manager.config.assessment_name == "Corp Audit"
    assert "corp-target.net" in agent.gateway.scope_manager.config.targets


def test_operator_authorization_rejects_arbitrary_tokens():
    """Verify arbitrary authorization tokens cannot expand scope autonomously."""
    from loki.security.context import AssessmentSecurityContext
    from loki.tools.security_tools import authorize_target

    AssessmentSecurityContext.reset_default()

    # Pass arbitrary token
    res = authorize_target("evil-unauthorized-host.org", authorization_token="any_random_token_123")
    assert "Authorization Denied" in res
    assert "Autonomous self-authorization by the model is disabled" in res
