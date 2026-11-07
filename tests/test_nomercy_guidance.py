from types import SimpleNamespace

from loki.runtime.agent import LokiAgent
from loki.security.gateway import ExecutionGateway
from loki.security.policy_engine import ExecutionMode, PolicyEngine
from loki.security.scope_manager import ScopeConfig, ScopeManager


def _agent_for_mode(mode):
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="NOMERCY Prompt Test",
            targets=["example.com"],
            allow_subdomains=True,
            dns_check_enabled=False,
        )
    )
    policy = PolicyEngine(scope_manager=scope, mode=mode)
    gateway = ExecutionGateway(scope_manager=scope, policy_engine=policy)
    return LokiAgent(
        provider=object(),
        gateway=gateway,
        include_builtins=False,
        include_security_tools=False,
        tool_learning=SimpleNamespace(format_guidance=lambda _task: "No prior tool history."),
    )


def test_nomercy_runtime_prompt_allows_scoped_origin_validation():
    prompt = _agent_for_mode(ExecutionMode.NOMERCY)._build_runtime_system_prompt("origin_ip")

    assert "NOMERCY FIELD PLAYBOOK" in prompt
    assert "CDN presence is not a reason to abandon origin attribution" in prompt
    assert "candidate IP/CIDR is explicitly in scope" in prompt
    assert "/scope add <IP>" in prompt
    assert "do not produce canned" in prompt.lower()
    assert "do not probe candidate origin IPs" not in prompt.lower()


def test_non_nomercy_prompt_does_not_claim_nomercy_authority():
    prompt = _agent_for_mode(ExecutionMode.AUDIT)._build_runtime_system_prompt("origin_ip")

    assert "NOMERCY FIELD PLAYBOOK" not in prompt
