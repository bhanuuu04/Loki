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

    # Test /exit
    assert cli.handle_command("/exit") is False
    assert cli.handle_command("/quit") is False
