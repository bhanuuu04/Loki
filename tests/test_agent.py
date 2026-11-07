import pytest
from loki.runtime.agent import LokiAgent
from loki.types import RunStatus, EventType


@pytest.mark.asyncio
async def test_agent_execution_loop():
    agent = LokiAgent(provider="mock")
    events = []
    agent.add_listener(lambda e: events.append(e.event_type))

    result = await agent.run("Please calculate 25 * 4 using the calculator tool.")
    
    assert result.status == RunStatus.SUCCESS
    assert len(result.steps) >= 1
    assert result.total_usage.total_tokens > 0
    assert EventType.RUN_START in events
    assert EventType.RUN_END in events


@pytest.mark.asyncio
async def test_agent_step_limit():
    # Set max steps to 0 or 1 with an iterative prompt to test step bounds
    agent = LokiAgent(provider="mock", max_steps=1)
    result = await agent.run("Please calculate 25 * 4 using the calculator tool.")
    # In step 1, mock agent invokes calculator tool. Since max_steps=1, it should stop gracefully
    assert result.status in (RunStatus.SUCCESS, RunStatus.MAX_STEPS_REACHED)


@pytest.mark.asyncio
async def test_agent_error_handling():
    class FailingProvider:
        model = "failing-model"
        async def chat_complete(self, *args, **kwargs):
            raise ConnectionError("Simulated network outage")

    agent = LokiAgent(provider=FailingProvider())
    result = await agent.run("Hello world")

    assert result.status == RunStatus.ERROR
    assert "Simulated network outage" in result.error_message
    assert result.final_response != ""
    assert "Simulated network outage" in result.final_response


@pytest.mark.asyncio
async def test_tool_execution_exception_does_not_abort_agent_tool_loop():
    from loki.types import ToolCall

    agent = LokiAgent(provider="mock")

    async def exploding_tool_call(_tool_call):
        raise ValueError("No closing quotation")

    agent.registry.execute_call = exploding_tool_call
    result = await agent._execute_tool_call(
        ToolCall(id="bad-quote-1", name="python_exec", arguments={"code": "print('broken"})
    )

    assert result.is_error
    assert result.metadata["execution_exception"] is True
    assert result.metadata["authorized"] is False
    assert "No closing quotation" in result.output
