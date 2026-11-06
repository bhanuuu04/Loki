"""
Google Gemini native REST API provider adapter.
"""

from typing import Any, AsyncIterator, Dict, List, Optional
import json
import time
import uuid
import httpx

from loki.providers.base import BaseLLMProvider
from loki.types import LLMResponse, Message, Role, TokenUsage, ToolCall


class GeminiProvider(BaseLLMProvider):
    """
    Adapter for Google Gemini REST API (gemini-1.5-flash, gemini-2.0-flash, etc.)
    Uses direct httpx requests for high speed and minimal dependencies.
    """

    def __init__(
        self,
        model: str = "gemini-2.5-flash",
        api_key: Optional[str] = None,
        timeout: float = 60.0,
        **kwargs: Any,
    ):
        super().__init__(model=model, **kwargs)
        self.api_key = api_key
        self.timeout = timeout

    def _convert_schema_to_gemini(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Convert standard JSON Schema to Gemini Function Declaration format."""
        fn = schema.get("function", schema)
        gemini_decl: Dict[str, Any] = {
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
        }
        parameters = fn.get("parameters", {})
        if parameters:
            gemini_decl["parameters"] = parameters
        return gemini_decl

    def _format_payload(
        self, messages: List[Message], tools: Optional[List[Dict[str, Any]]] = None, temperature: float = 0.2
    ) -> Dict[str, Any]:
        system_instruction = None
        contents: List[Dict[str, Any]] = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system_instruction = {"parts": [{"text": msg.content or ""}]}
            elif msg.role == Role.USER:
                contents.append({"role": "user", "parts": [{"text": msg.content or ""}]})
            elif msg.role == Role.ASSISTANT:
                parts: List[Dict[str, Any]] = []
                if msg.content:
                    parts.append({"text": msg.content})
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append({"functionCall": {"name": tc.name, "args": tc.arguments}})
                contents.append({"role": "model", "parts": parts if parts else [{"text": ""}]})
            elif msg.role == Role.TOOL:
                # Gemini function response part
                tool_content = msg.content
                try:
                    response_json = json.loads(tool_content) if isinstance(tool_content, str) else tool_content
                except Exception:
                    response_json = {"output": tool_content}

                contents.append({
                    "role": "function",
                    "parts": [{
                        "functionResponse": {
                            "name": msg.name or "tool",
                            "response": {"result": response_json},
                        }
                    }]
                })

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system_instruction:
            payload["system_instruction"] = system_instruction
        if tools:
            declarations = [self._convert_schema_to_gemini(t) for t in tools]
            payload["tools"] = [{"function_declarations": declarations}]

        return payload

    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.perf_counter()
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is required for GeminiProvider.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = self._format_payload(messages, tools, temperature)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            return LLMResponse(content="", model=self.model)

        candidate = candidates[0]
        parts = candidate.get("content", {}).get("parts", [])

        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []

        for p in parts:
            if "text" in p:
                text_parts.append(p["text"])
            elif "functionCall" in p:
                fc = p["functionCall"]
                tool_calls.append(
                    ToolCall(
                        id=f"call_{uuid.uuid4().hex[:8]}",
                        name=fc.get("name", ""),
                        arguments=fc.get("args", {}),
                    )
                )

        usage_meta = data.get("usageMetadata", {})
        usage = TokenUsage(
            prompt_tokens=usage_meta.get("promptTokenCount", 0),
            completion_tokens=usage_meta.get("candidatesTokenCount", 0),
            total_tokens=usage_meta.get("totalTokenCount", 0),
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
