"""
OpenAI & OpenAI-compatible provider adapter (supports Ollama, DeepSeek, vLLM, etc.)
"""

from typing import Any, AsyncIterator, Dict, List, Optional
import json
import time
import httpx

from loki.providers.base import BaseLLMProvider
from loki.types import LLMResponse, Message, Role, TokenUsage, ToolCall


class OpenAICompatibleProvider(BaseLLMProvider):
    """
    Adapter for any OpenAI chat completions compatible API endpoint.
    Works for OpenAI, Ollama (/v1), LocalAI, vLLM, DeepSeek, Groq, etc.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        **kwargs: Any,
    ):
        super().__init__(model=model, **kwargs)
        self.api_key = api_key or "no-key"
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _format_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        formatted = []
        for msg in messages:
            entry: Dict[str, Any] = {"role": msg.role.value, "content": msg.content or ""}
            if msg.name:
                entry["name"] = msg.name
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else str(tc.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            if msg.tool_call_id:
                entry["tool_call_id"] = msg.tool_call_id
            formatted.append(entry)
        return formatted

    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.perf_counter()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": self._format_messages(messages),
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]["message"]
        content = choice.get("content") or ""
        raw_tool_calls = choice.get("tool_calls") or []

        parsed_tool_calls: List[ToolCall] = []
        for tc in raw_tool_calls:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except Exception:
                    args = {"raw": raw_args}
            else:
                args = raw_args
            parsed_tool_calls.append(
                ToolCall(id=tc.get("id", "call_default"), name=fn_name, arguments=args)
            )

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )

        latency = (time.perf_counter() - start_time) * 1000
        return LLMResponse(
            content=content,
            tool_calls=parsed_tool_calls,
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
        # For full streaming agent loop or fallback
        resp = await self.chat_complete(messages, tools, temperature, max_tokens, **kwargs)
        if resp.content:
            yield resp.content
        yield resp
