import json

import pytest

from loki.knowledge.tool_registry.performance_memory import (
    ToolPerformanceMemory,
    classify_task,
    classify_tool_outcome,
)
from loki.runtime.agent import LokiAgent
from loki.tools.base import Tool, ToolCapability
from loki.types import LLMResponse, ToolCall, TokenUsage


def test_task_categories_and_origin_ip_evidence_rules():
    assert classify_task("Find the origin IP address") == "origin_ip_verification"
    assert classify_task("Find all subdomains") == "subdomain_discovery"
    assert classify_task("Fingerprint the web technology stack") == "web_fingerprinting"

    # A DNS A record may be the CDN edge, not the origin server.
    assert classify_tool_outcome(
        "DNS Resolution: IP Addresses: 203.0.113.20",
        task_type="origin_ip_verification",
    ) == "partial"
    assert classify_tool_outcome(
        "Origin IP verified from owner inventory: 203.0.113.10",
        task_type="origin_ip_verification",
    ) == "success"
    assert classify_tool_outcome(
        "No results returned from this source.",
        task_type="origin_ip_verification",
    ) == "no_result"


def test_tool_effectiveness_memory_prioritizes_a_tool_that_found_results(tmp_path):
    memory_path = tmp_path / "tool-performance.json"
    memory = ToolPerformanceMemory(str(memory_path))

    earlier_methods = [f"method_{i:02d}" for i in range(1, 16)]
    for name in earlier_methods:
        for _ in range(2):
            memory.record("origin_ip_verification", name, "no_result")

    memory.record("origin_ip_verification", "method_16", "success")

    ranked = memory.rank_tool_names(
        "origin_ip_verification",
        earlier_methods + ["method_16"],
    )
    assert ranked[0] == "method_16"

    # The persisted learning file must not contain target names or raw tool output.
    raw = memory_path.read_text(encoding="utf-8")
    assert "example.com" not in raw
    assert "203.0.113.10" not in raw
    assert '"no_result": 2' in raw
    assert '"success": 1' in raw

    reloaded = ToolPerformanceMemory(str(memory_path))
    assert reloaded.rank_tool_names(
        "origin_ip_verification",
        earlier_methods + ["method_16"],
    )[0] == "method_16"


class SequencedProvider:
    model = "adaptive-test-model"

    def __init__(self):
        self.responses = [
            LLMResponse(
                content="The target is behind a CDN. I could not find the origin IP with the first method.",
                usage=TokenUsage(),
            ),
            LLMResponse(
                content="I will check the operator-provided asset inventory.",
                tool_calls=[
                    ToolCall(
                        id="inventory-call",
                        name="owner_asset_inventory",
                        arguments={},
                    )
                ],
                usage=TokenUsage(),
            ),
            LLMResponse(
                content="Origin IP verified from owner inventory: 203.0.113.10",
                usage=TokenUsage(),
            ),
        ]
        self.seen_messages = []

    async def chat_complete(self, messages, tools=None, temperature=0.2):
        self.seen_messages.append(list(messages))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_agent_continues_after_unresolved_answer_and_records_success(tmp_path):
    def owner_asset_inventory() -> str:
        return "Origin IP verified from owner inventory: 203.0.113.10"

    owner_tool = Tool(
        name="owner_asset_inventory",
        description="Read a local, operator-supplied asset inventory fixture.",
        func=owner_asset_inventory,
        capabilities=[ToolCapability.UTILITY],
    )
    memory = ToolPerformanceMemory(str(tmp_path / "learning.json"))
    provider = SequencedProvider()
    agent = LokiAgent(
        provider=provider,
        tools=[owner_tool],
        include_builtins=False,
        include_security_tools=False,
        max_steps=5,
        tool_learning=memory,
        max_adaptive_continuations=3,
    )

    result = await agent.run("Find the origin IP address from approved owner records.")

    assert "Origin IP verified" in result.final_response
    assert len(provider.seen_messages) == 3
    second_turn = provider.seen_messages[1]
    assert any(
        "INVESTIGATION CONTINUATION" in (message.content or "")
        for message in second_turn
    )

    stats = memory.get_task_stats("origin_ip_verification")["owner_asset_inventory"]
    assert stats["success"] == 1
    assert stats["score"] > 0.5


def test_gateway_blocks_are_not_treated_as_a_reason_to_try_bypasses():
    assert not LokiAgent._looks_unresolved(
        "origin_ip_verification",
        "Scope violation: target is out of scope. No request was made.",
    )
