"""
Model Compatibility and Capability Testing Utility.
Probes LLM endpoints for connectivity, auth, streaming, tool-calling, and latency.
"""

from typing import Any, Dict, List, Optional
import time
import asyncio
from pydantic import BaseModel, Field

from loki.providers.base import BaseLLMProvider
from loki.types import Message, Role, ToolCall


class CapabilityTestItem(BaseModel):
    name: str
    passed: bool
    latency_ms: float = 0.0
    details: str = ""
    critical: bool = True


class ModelCompatibilityReport(BaseModel):
    provider_name: str
    model_id: str
    endpoint_url: str
    overall_status: str  # "COMPATIBLE", "PARTIAL", "INCOMPATIBLE"
    tests: List[CapabilityTestItem] = Field(default_factory=list)
    tested_at: float = Field(default_factory=time.time)


class ModelCompatibilityTester:
    """Runs capability verification against any configured LLM provider."""

    def __init__(self, provider: BaseLLMProvider):
        self.provider = provider

    async def run_suite(self) -> ModelCompatibilityReport:
        tests: List[CapabilityTestItem] = []
        provider_name = type(self.provider).__name__
        model_id = self.provider.model
        base_url = getattr(self.provider, "base_url", "local/native")

        # 1. Test: Connectivity & Basic Text Generation
        start = time.perf_counter()
        try:
            resp = await self.provider.chat_complete(
                messages=[
                    Message(role=Role.SYSTEM, content="You are a helpful assistant."),
                    Message(role=Role.USER, content="Reply with exactly 'PONG'"),
                ],
                max_tokens=20,
            )
            lat = (time.perf_counter() - start) * 1000
            content = (resp.content or "").strip()
            passed = "pong" in content.lower() or len(content) > 0
            tests.append(CapabilityTestItem(
                name="Basic Text Generation & Connectivity",
                passed=passed,
                latency_ms=round(lat, 1),
                details=f"Received: '{content[:50]}' ({resp.usage.total_tokens} tokens)",
                critical=True,
            ))
        except Exception as e:
            lat = (time.perf_counter() - start) * 1000
            tests.append(CapabilityTestItem(
                name="Basic Text Generation & Connectivity",
                passed=False,
                latency_ms=round(lat, 1),
                details=f"Connection/Auth failure: {type(e).__name__}: {str(e)}",
                critical=True,
            ))

        # 2. Test: Streaming Capability
        start = time.perf_counter()
        stream_chunks = []
        try:
            async for chunk in self.provider.chat_stream(
                messages=[Message(role=Role.USER, content="Count 1 to 3")],
                max_tokens=20,
            ):
                if isinstance(chunk, str):
                    stream_chunks.append(chunk)
            lat = (time.perf_counter() - start) * 1000
            passed = len(stream_chunks) > 0
            tests.append(CapabilityTestItem(
                name="Streaming Generation",
                passed=passed,
                latency_ms=round(lat, 1),
                details=f"Received {len(stream_chunks)} streaming tokens/chunks",
                critical=False,
            ))
        except Exception as e:
            lat = (time.perf_counter() - start) * 1000
            tests.append(CapabilityTestItem(
                name="Streaming Generation",
                passed=False,
                latency_ms=round(lat, 1),
                details=f"Streaming not supported or failed: {str(e)}",
                critical=False,
            ))

        # 3. Test: Tool / Function Calling
        start = time.perf_counter()
        tool_schema = [{
            "type": "function",
            "function": {
                "name": "check_target",
                "description": "Check status of target",
                "parameters": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            },
        }]
        try:
            resp_tool = await self.provider.chat_complete(
                messages=[Message(role=Role.USER, content="Call check_target for host 'example.test'")],
                tools=tool_schema,
                max_tokens=100,
            )
            lat = (time.perf_counter() - start) * 1000
            has_tool_call = len(resp_tool.tool_calls) > 0
            tests.append(CapabilityTestItem(
                name="Tool / Function Calling",
                passed=has_tool_call,
                latency_ms=round(lat, 1),
                details=f"Generated {len(resp_tool.tool_calls)} tool call(s)" if has_tool_call else "Model answered with text instead of tool call",
                critical=False,
            ))
        except Exception as e:
            lat = (time.perf_counter() - start) * 1000
            tests.append(CapabilityTestItem(
                name="Tool / Function Calling",
                passed=False,
                latency_ms=round(lat, 1),
                details=f"Tool calling unsupported on this model: {type(e).__name__}: {str(e)}",
                critical=False,
            ))

        # Determine overall status
        critical_passed = all(t.passed for t in tests if t.critical)
        all_passed = all(t.passed for t in tests)

        if all_passed:
            status = "COMPATIBLE"
        elif critical_passed:
            status = "PARTIAL"  # Works for text/reasoning, but lacks optional capabilities like tool calling
        else:
            status = "INCOMPATIBLE"

        return ModelCompatibilityReport(
            provider_name=provider_name,
            model_id=model_id,
            endpoint_url=base_url,
            overall_status=status,
            tests=tests,
        )
