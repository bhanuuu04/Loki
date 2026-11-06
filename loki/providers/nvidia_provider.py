"""
NVIDIA NIM (NVIDIA Inference Microservice) Provider Adapter.
Supports NVIDIA-hosted endpoints (integrate.api.nvidia.com) and self-hosted NIM containers.
"""

from typing import Any, AsyncIterator, Dict, List, Optional
import json
import time
import asyncio
import httpx

from loki.providers.base import BaseLLMProvider
from loki.types import LLMResponse, Message, Role, TokenUsage, ToolCall
from loki.config import settings


# Models known to have native function/tool calling support in NVIDIA NIM
KNOWN_TOOL_SUPPORTED_FAMILIES = (
    "llama-3.1",
    "llama-3.2",
    "llama-3.3",
    "mistral-large",
    "mixtral",
    "nemotron",
    "qwen2.5",
    "command-r",
)


class NvidiaNimProvider(BaseLLMProvider):
    """
    First-class provider for NVIDIA NIM endpoints.
    Features:
      - Hosted (integrate.api.nvidia.com) and self-hosted NIM support.
      - Dynamic model ID support without hardcoded restrictions.
      - Capability detection & graceful tool-call fallback.
      - Automatic retries with exponential backoff on rate limits / 5xx.
      - Full streaming and usage tracking.
    """

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        retry_attempts: int = 3,
        **kwargs: Any,
    ):
        model_name = model or settings.nvidia_nim_model or "meta/llama-3.3-70b-instruct"
        super().__init__(model=model_name, **kwargs)
        self.api_key = api_key or settings.nvidia_nim_api_key or "no-key"
        self.base_url = (base_url or settings.nvidia_nim_base_url or "https://integrate.api.nvidia.com/v1").rstrip("/")
        self.timeout = timeout
        self.retry_attempts = retry_attempts

    def supports_function_calling(self) -> bool:
        """Heuristic check on whether the active model supports function calling."""
        m_lower = self.model.lower()
        return any(fam in m_lower for fam in KNOWN_TOOL_SUPPORTED_FAMILIES)

    async def list_models(self) -> List[Dict[str, Any]]:
        """Query endpoint for list of all available models."""
        url = f"{self.base_url}/models"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", [])
        except Exception as e:
            return [{"id": self.model, "status": f"Query failed: {str(e)}"}]

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

    async def _post_with_retry(self, url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Execute HTTP POST with exponential backoff for rate limits or server blips."""
        last_exception = None
        for attempt in range(1, self.retry_attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        backoff = 1.5 ** attempt
                        await asyncio.sleep(backoff)
                        continue
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPStatusError as hse:
                last_exception = hse
                if hse.response.status_code in (429, 500, 502, 503, 504):
                    await asyncio.sleep(1.5 ** attempt)
                    continue
                raise
            except Exception as e:
                last_exception = e
                await asyncio.sleep(1.0 * attempt)

        if last_exception:
            raise last_exception
        raise RuntimeError("NVIDIA NIM request failed after retry attempts.")

    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = 2048,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.perf_counter()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": self._format_messages(messages),
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        # Check capability before including tools
        include_tools = bool(tools and self.supports_function_calling())
        if include_tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"

        try:
            data = await self._post_with_retry(url, payload, headers)
        except httpx.HTTPStatusError as err:
            # If rejected due to tools parameter, retry without tools payload
            if tools and "tool" in err.response.text.lower():
                payload.pop("tools", None)
                payload.pop("tool_choice", None)
                data = await self._post_with_retry(url, payload, headers)
            else:
                raise

        choice = data.get("choices", [{}])[0].get("message", {})
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
                ToolCall(id=tc.get("id", f"nim_call_{time.time()}"), name=fn_name, arguments=args)
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
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        payload = {
            "model": self.model,
            "messages": self._format_messages(messages),
            "temperature": temperature,
            "stream": True,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if tools and self.supports_function_calling():
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line.replace("data: ", "").strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        text = delta.get("content")
                        if text:
                            yield text
                    except Exception:
                        pass
