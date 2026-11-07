import json

import pytest

from loki.knowledge.tool_registry.performance_memory import (
    ToolPerformanceMemory,
    classify_task,
    effective_tool_name,
    classify_tool_outcome,
)
from loki.runtime.agent import LokiAgent
from loki.tools.base import Tool, ToolCapability
from loki.types import LLMResponse, ToolCall, TokenUsage


def test_effective_tool_name_extracts_kali_binary_from_shell_wrapper():
    assert effective_tool_name(
        "run_command",
        {"command": "sudo nmap -sV example.test"},
    ) == "nmap"
    assert effective_tool_name(
        "run_command",
        {"command": "proxychains4 curl -I https://example.test"},
    ) == "curl"
    assert effective_tool_name(
        "audit_http_security_headers",
        {"url": "https://example.test"},
    ) == "audit_http_security_headers"


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

    # With no history, preserve the discovery engine's relevance ordering.
    assert reloaded.rank_tool_names("new_task", ["most_relevant", "second_relevant"]) == [
        "most_relevant", "second_relevant"
    ]


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
    third_turn_system = [m.content for m in provider.seen_messages[2] if m.role.value == "system"]
    assert third_turn_system
    assert "owner_asset_inventory" in third_turn_system[0]


def test_gateway_blocks_are_not_treated_as_a_reason_to_try_bypasses():
    assert not LokiAgent._looks_unresolved(
        "origin_ip_verification",
        "Scope violation: target is out of scope. No request was made.",
    )


class SixteenMethodProvider:
    model = "adaptive-sixteen-method-test"

    def __init__(self):
        self.responses = [
            LLMResponse(
                content="The site is behind a CDN. The origin remains unknown; the visible address is only an edge IP.",
                usage=TokenUsage(),
            )
        ]
        self.seen_messages = []

        for index in range(1, 16):
            self.responses.append(
                LLMResponse(
                    content=f"Trying distinct authorized method {index}.",
                    tool_calls=[
                        ToolCall(
                            id=f"method-{index:02d}",
                            name=f"method_{index:02d}",
                            arguments={},
                        )
                    ],
                    usage=TokenUsage(),
                )
            )
            self.responses.append(
                LLMResponse(
                    content="No results returned from this source; the origin remains unknown behind the CDN.",
                    usage=TokenUsage(),
                )
            )

        self.responses.append(
            LLMResponse(
                content="Checking the operator-provided owner inventory.",
                tool_calls=[
                    ToolCall(
                        id="method-16",
                        name="owner_inventory_lookup",
                        arguments={},
                    )
                ],
                usage=TokenUsage(),
            )
        )
        self.responses.append(
            LLMResponse(
                content="Origin IP verified from owner inventory: 198.51.100.16",
                usage=TokenUsage(),
            )
        )

    async def chat_complete(self, messages, tools=None, temperature=0.2):
        self.seen_messages.append(list(messages))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_agent_can_continue_through_fifteen_failures_and_learn_sixteenth_method(tmp_path):
    tools = []
    for index in range(1, 16):
        def no_result(index=index):
            return f"No results returned by authorized method {index}."

        tools.append(
            Tool(
                name=f"method_{index:02d}",
                description=f"Distinct read-only research method {index}.",
                func=no_result,
                capabilities=[ToolCapability.UTILITY],
            )
        )

    def owner_inventory_lookup():
        return "Origin IP verified from owner inventory: 198.51.100.16"

    tools.append(
        Tool(
            name="owner_inventory_lookup",
            description="Read an operator-supplied owner asset inventory fixture.",
            func=owner_inventory_lookup,
            capabilities=[ToolCapability.UTILITY],
        )
    )

    memory = ToolPerformanceMemory(str(tmp_path / "sixteen-method-learning.json"))
    provider = SixteenMethodProvider()
    agent = LokiAgent(
        provider=provider,
        tools=tools,
        include_builtins=False,
        include_security_tools=False,
        max_steps=40,
        tool_learning=memory,
        max_adaptive_continuations=16,
    )

    result = await agent.run("Find the origin IP from approved owner inventory and DNS records.")

    assert "Origin IP verified from owner inventory" in result.final_response
    assert len(provider.responses) == 0
    assert len(provider.seen_messages) == 33

    stats = memory.get_task_stats("origin_ip_verification")
    assert len(stats) == 16
    assert stats["method_01"]["no_result"] == 1
    assert stats["method_15"]["no_result"] == 1
    assert stats["owner_inventory_lookup"]["success"] == 1

    ranked = memory.rank_tool_names(
        "origin_ip_verification",
        [f"method_{index:02d}" for index in range(1, 16)] + ["owner_inventory_lookup"],
    )
    assert ranked[0] == "owner_inventory_lookup"

    continuation_messages = {
        message.content
        for messages in provider.seen_messages
        for message in messages
        if message.content and "INVESTIGATION CONTINUATION" in message.content
    }
    assert len(continuation_messages) == 16
    final_continuation = next(message for message in continuation_messages if "16/16" in message)
    assert "15" in final_continuation


def test_adaptive_continuation_budget_is_bounded_at_twenty():
    agent = LokiAgent(
        provider="mock",
        include_builtins=False,
        include_security_tools=False,
        max_adaptive_continuations=99,
    )
    assert agent.max_adaptive_continuations == 20
