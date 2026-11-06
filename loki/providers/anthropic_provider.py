"""
Anthropic Claude Messages API provider adapter.
"""

from typing import Any, AsyncIterator, Dict, List, Optional
import json
import time
import httpx

from loki.providers.base import BaseLLMProvider
from loki.types import LLMResponse, Message, Role, TokenUsage, ToolCall


class AnthropicProvider(BaseLLMProvider):
    """
    Adapter for Anthropic Claude Messages API (claude-3-5-sonnet, claude-3-haiku, etc.)
    """

    def __init__(
        self,
        model: str = "claude-3-5-sonnet-20241022",
        api_key: Optional[str] = None,
        base_url: str = "https://api.anthropic.com/v1",
        timeout: float = 60.0,
        **kwargs: Any,
    ):
        super().__init__(model=model, **kwargs)
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _convert_schema_to_anthropic(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        fn = schema.get("function", schema)
        return {
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        }

    def _format_messages(self, messages: List[Message]) -> tuple[Optional[str], List[Dict[str, Any]]]:
        system_prompt = None
        formatted: List[Dict[str, Any]] = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system_prompt = msg.content
            elif msg.role == Role.USER:
                formatted.append({"role": "user", "content": msg.content or ""})
            elif msg.role == Role.ASSISTANT:
                content_blocks: List[Dict[str, Any]] = []
                if msg.content:
                    content_blocks.append({"type": "text", "text": msg.content})
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        content_blocks.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        })
                formatted.append({"role": "assistant", "content": content_blocks if content_blocks else ""})
            elif msg.role == Role.TOOL:
                formatted.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.tool_call_id or "unknown",
                            "content": msg.content or "",
                        }
                    ],
                })

        return system_prompt, formatted

    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.perf_counter()
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for AnthropicProvider.")

        system_prompt, anthropic_messages = self._format_messages(messages)
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens or 4096,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = [self._convert_schema_to_anthropic(t) for t in tools]

        url = f"{self.base_url}/messages"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []

        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.get("id", "call_default"),
                        name=block.get("name", ""),
                        arguments=block.get("input", {}),
                    )
                )

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("input_tokens", 0),
            completion_tokens=usage_data.get("output_tokens", 0),
            total_tokens=usage_data.get("input_tokens", 0) + usage_data.get("output_tokens", 0),
        )

        latency = (time.perf_counter() - start_time) * 1000
        return LLMResponse(
            content="\n".join(text_parts),
            tool_calls=tool_calls,
            usage=usage,
            latency_ms=latency,
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
        resp = await self.chat_complete(messages, tools, temperature, max_tokens, **kwargs)
        if resp.content:
            yield resp.content
        yield resp
