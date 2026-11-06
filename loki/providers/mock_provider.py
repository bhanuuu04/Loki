"""
Mock LLM Provider for deterministic testing, offline demos, and benchmarking.
"""

from typing import Any, AsyncIterator, Callable, Dict, List, Optional
import json
import time
import uuid

from loki.providers.base import BaseLLMProvider
from loki.types import LLMResponse, Message, Role, TokenUsage, ToolCall


class MockProvider(BaseLLMProvider):
    """
    Simulates LLM responses and tool invocation cycles deterministically.
    Supports scriptable turns or dynamic rule-based matching.
    """

    def __init__(
        self,
        model: str = "mock-agent-v1",
        scripted_responses: Optional[List[LLMResponse]] = None,
        custom_router: Optional[Callable[[List[Message], Optional[List[Dict[str, Any]]]], LLMResponse]] = None,
        **kwargs: Any,
    ):
        super().__init__(model=model, **kwargs)
        self.scripted_responses = scripted_responses or []
        self.script_index = 0
        self.custom_router = custom_router

    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.perf_counter()

        # 1. Custom router if provided
        if self.custom_router:
            resp = self.custom_router(messages, tools)
            resp.latency_ms = (time.perf_counter() - start_time) * 1000
            return resp

        # 2. Check scripted responses queue
        if self.script_index < len(self.scripted_responses):
            resp = self.scripted_responses[self.script_index]
            self.script_index += 1
            resp.latency_ms = (time.perf_counter() - start_time) * 1000
            return resp

        # 3. Dynamic smart heuristic simulation
        last_msg = messages[-1] if messages else None
        
        # If the last message is a tool response, synthesize a final answer
        if last_msg and last_msg.role == Role.TOOL:
            content = f"Based on the tool execution output: '{last_msg.content}', the task is completed successfully."
            latency = (time.perf_counter() - start_time) * 1000
            return LLMResponse(
                content=content,
                tool_calls=[],
                usage=TokenUsage(prompt_tokens=120, completion_tokens=35, total_tokens=155),
                latency_ms=latency,
                model=self.model,
            )

        # Inspect user prompt for tool intent
        user_text = ""
        for m in reversed(messages):
            if m.role == Role.USER and m.content:
                user_text = m.content.lower()
                break

        available_tool_names = [t.get("name") or t.get("function", {}).get("name") for t in (tools or [])]

        # Trigger calculator tool if math requested and available
        if ("calculate" in user_text or "add" in user_text or "multiply" in user_text or "+" in user_text) and "calculator" in available_tool_names:
            expr = "2 + 2"
            if "25 * 4" in user_text or "25*4" in user_text:
                expr = "25 * 4"
            elif "150 / 3" in user_text:
                expr = "150 / 3"
            return LLMResponse(
                content="I will compute this calculation using the calculator tool.",
                tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="calculator", arguments={"expression": expr})],
                usage=TokenUsage(prompt_tokens=90, completion_tokens=25, total_tokens=115),
                latency_ms=(time.perf_counter() - start_time) * 1000,
                model=self.model,
            )

        # Trigger file tool if file requested
        if ("file" in user_text or "read" in user_text or "write" in user_text) and "read_file" in available_tool_names:
            return LLMResponse(
                content="I will inspect the file contents.",
                tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="read_file", arguments={"filepath": "sample.txt"})],
                usage=TokenUsage(prompt_tokens=95, completion_tokens=20, total_tokens=115),
                latency_ms=(time.perf_counter() - start_time) * 1000,
                model=self.model,
            )

        # Trigger python tool if code requested
        if ("python" in user_text or "code" in user_text or "script" in user_text) and "python_exec" in available_tool_names:
            return LLMResponse(
                content="I will execute Python code to answer your question.",
                tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="python_exec", arguments={"code": "result = sum(range(1, 11))"})],
                usage=TokenUsage(prompt_tokens=110, completion_tokens=30, total_tokens=140),
                latency_ms=(time.perf_counter() - start_time) * 1000,
                model=self.model,
            )

        # Default conversational response
        return LLMResponse(
            content=f"Loki Mock Agent response to: '{user_text if user_text else 'Hello'}'. All systems operational.",
            tool_calls=[],
            usage=TokenUsage(prompt_tokens=60, completion_tokens=25, total_tokens=85),
            latency_ms=(time.perf_counter() - start_time) * 1000,
            model=self.model,
        )

    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[Any]:
        response = await self.chat_complete(messages, tools, temperature, max_tokens, **kwargs)
        if response.content:
            for word in response.content.split(" "):
                yield word + " "
        if response.tool_calls:
            for tc in response.tool_calls:
                yield tc
        yield response
