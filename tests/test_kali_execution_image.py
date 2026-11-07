import pytest

from loki.executor.isolation import ExecutionIsolationResult, IsolatedExecutionEngine, IsolationBackend


@pytest.mark.asyncio
async def test_shell_image_reference_is_validated_before_docker(monkeypatch):
    monkeypatch.setattr(
        IsolatedExecutionEngine,
        "is_docker_available",
        classmethod(lambda cls: (_ for _ in ()).throw(AssertionError("Docker should not be checked"))),
    )

    result = await IsolatedExecutionEngine.execute_shell(
        "echo test",
        image=";malicious-shell-value",
    )

    assert result.backend == IsolationBackend.UNAVAILABLE
    assert result.exit_code != 0
    assert "invalid Docker image" in result.stderr


@pytest.mark.asyncio
async def test_run_command_uses_configured_shell_image(monkeypatch):
    from loki.tools.builtins import shell_tools

    captured = {}

    async def fake_execute_shell(command, timeout_seconds, image):
        captured.update(
            command=command,
            timeout_seconds=timeout_seconds,
            image=image,
        )
        return ExecutionIsolationResult(
            command=command,
            stdout="tool output",
            stderr="",
            exit_code=0,
            backend=IsolationBackend.DOCKER,
        )

    monkeypatch.setattr(shell_tools.settings, "shell_docker_image", "loki-kali-tools:latest")
    monkeypatch.setattr(shell_tools.IsolatedExecutionEngine, "execute_shell", fake_execute_shell)

    output = await shell_tools.run_command.func(
        command="nmap --version",
        timeout_seconds=12,
    )

    assert captured == {
        "command": "nmap --version",
        "timeout_seconds": 12.0,
        "image": "loki-kali-tools:latest",
    }
    assert "tool output" in output
