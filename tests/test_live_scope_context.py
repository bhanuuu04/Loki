import pytest

from loki.cli.interface import LokiConversationalCLI
from loki.runtime.agent import LokiAgent
from loki.runtime.context import AgentContext
from loki.runtime.memory import MemoryStore
from loki.security.context import AssessmentSecurityContext
from loki.types import LLMResponse, Role, TokenUsage


class CapturingProvider:
    """Minimal provider that records the exact messages Loki sends to its model."""

    model = "scope-context-test"

    def __init__(self):
        self.messages = None

    async def chat_complete(self, messages, tools=None, temperature=0.2):
        self.messages = list(messages)
        return LLMResponse(content="Scope snapshot received.", usage=TokenUsage())


def test_cli_scope_add_is_visible_to_the_agent_and_gateway():
    context = AssessmentSecurityContext.reset_default()
    cli = LokiConversationalCLI(provider="mock")

    assert cli.handle_command("/scope add schoolknot.com") is True

    # The CLI, agent, gateway, and global tool proxies must agree on one scope.
    assert "schoolknot.com" in cli.scope_manager.config.targets
    assert cli.agent.gateway.scope_manager is context.scope_manager
    assert cli.agent.security_context is context
    assert cli.agent.gateway.scope_manager.is_in_scope(
        "schoolknot.com", check_dns=False
    )[0]


@pytest.mark.asyncio
async def test_agent_refreshes_scope_snapshot_when_resuming_saved_session(tmp_path):
    # Start with a new default context and use the real CLI command to add a host.
    context = AssessmentSecurityContext.reset_default()
    cli = LokiConversationalCLI(provider="mock")
    cli.handle_command("/scope add schoolknot.com")

    # Simulate a session saved before the target was added, with stale system context.
    memory_store = MemoryStore(persistence_dir=str(tmp_path / "sessions"))
    stale_context = AgentContext(
        system_prompt=(
            "OLD SCOPE SNAPSHOT: only 127.0.0.1 and localhost are authorized."
        )
    )
    stale_context.add_user_message("Earlier question")
    memory_store.save_session("existing-session", stale_context)

    provider = CapturingProvider()
    agent = LokiAgent(provider=provider, memory_store=memory_store, max_steps=1)

    result = await agent.run(
        prompt="Find the origin IP address of schoolknot.com",
        session_id="existing-session",
    )

    assert result.final_response == "Scope snapshot received."
    assert provider.messages is not None
    system_messages = [m for m in provider.messages if m.role == Role.SYSTEM]
    assert len(system_messages) == 1
    system_prompt = system_messages[0].content

    assert "LIVE AUTHORIZATION SNAPSHOT" in system_prompt
    assert "schoolknot.com" in system_prompt
    assert "OLD SCOPE SNAPSHOT" not in system_prompt
    assert "Authorized targets (3)" in system_prompt
