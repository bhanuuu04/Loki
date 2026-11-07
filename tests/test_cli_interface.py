import pytest
from loki.cli.interface import LokiConversationalCLI
from loki.security.policy_engine import ExecutionMode


def test_cli_slash_commands():
    cli = LokiConversationalCLI(provider="mock")

    # Test /help
    assert cli.handle_command("/help") is True

    # Test /status
    assert cli.handle_command("/status") is True

    # Test /mode
    assert cli.handle_command("/mode aggressive") is True
    assert cli.mode == ExecutionMode.AGGRESSIVE

    # Test /model
    assert cli.handle_command("/model custom-nim-model") is True
    assert cli.model_name == "custom-nim-model"

    # Test /scope
    assert cli.handle_command("/scope") is True
    assert cli.handle_command("/scope 192.168.1.100") is True
    assert "192.168.1.100" in cli.scope_manager.config.targets

    # Test /tools
    assert cli.handle_command("/tools") is True

    # Test /history
    assert cli.handle_command("/history") is True

    # Test /exit
    assert cli.handle_command("/exit") is False
    assert cli.handle_command("/quit") is False


def test_cli_nomercy_requires_interactive_confirmation(monkeypatch):
    from loki.cli import interface as interface_module
    cli = LokiConversationalCLI(provider="mock")

    monkeypatch.setattr(interface_module.Confirm, "ask", lambda *args, **kwargs: False)
    assert cli.handle_command("/mode nomercy") is True
    assert cli.mode == ExecutionMode.SAFE
    assert cli.agent.gateway.policy_engine.mode == ExecutionMode.SAFE

    monkeypatch.setattr(interface_module.Confirm, "ask", lambda *args, **kwargs: True)
    assert cli.handle_command("/mode nomercy") is True
    assert cli.mode == ExecutionMode.NOMERCY
    assert cli.agent.gateway.policy_engine.mode == ExecutionMode.NOMERCY


def test_lab_mode_requires_nomercy_and_creates_assessment(tmp_path, monkeypatch):
    from loki.cli import interface as interface_module
    from loki.assessment.store import AssessmentStore
    from loki.security.context import AssessmentSecurityContext
    from loki.security.scope_manager import ScopeConfig, ScopeManager

    scope = ScopeManager(ScopeConfig(
        assessment_name="CLI Disposable Lab",
        targets=["lab.example.test"],
        dns_check_enabled=False,
    ))
    ctx = AssessmentSecurityContext(scope_manager=scope)
    ctx.assessment_store = AssessmentStore(storage_dir=str(tmp_path / "assessments"))
    AssessmentSecurityContext.reset_default(ctx)

    cli = LokiConversationalCLI(provider="mock")
    monkeypatch.setattr(interface_module.Confirm, "ask", lambda *args, **kwargs: True)

    # SAFE/AUDIT cannot activate the lab data verification feature.
    assert cli.handle_command("/lab enable") is True
    assert not ctx.scope_manager.config.lab_mode_enabled
    assert ctx.active_assessment_id is None

    cli.agent.gateway.policy_engine.set_mode(ExecutionMode.NOMERCY, operator_confirmed=True)
    cli.mode = ExecutionMode.NOMERCY
    assert cli.handle_command("/lab enable") is True
    assert ctx.scope_manager.config.lab_mode_enabled
    assert ctx.active_assessment_id
    session = ctx.assessment_store.load_assessment(ctx.active_assessment_id)
    assert session is not None
    assert session.execution_mode == ExecutionMode.NOMERCY
    assert session.scope.lab_mode_enabled

    assert cli.handle_command("/lab disable") is True
    assert not ctx.scope_manager.config.lab_mode_enabled
