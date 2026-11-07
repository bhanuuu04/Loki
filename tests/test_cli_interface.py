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
