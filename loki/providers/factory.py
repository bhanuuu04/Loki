"""
Factory to instantiate LLM providers dynamically.
"""

from typing import Any, Optional
from loki.config import settings
from loki.providers.base import BaseLLMProvider
from loki.providers.mock_provider import MockProvider
from loki.providers.openai_provider import OpenAICompatibleProvider
from loki.providers.gemini_provider import GeminiProvider
from loki.providers.anthropic_provider import AnthropicProvider
from loki.providers.nvidia_provider import NvidiaNimProvider


def get_provider(
    provider_or_model: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> BaseLLMProvider:
    """
    Instantiate an LLM provider based on a string descriptor.
    Examples:
        - "mock" -> MockProvider
        - "gemini/gemini-2.5-flash" -> GeminiProvider
        - "openai/gpt-4o" -> OpenAICompatibleProvider
        - "ollama/llama3.1" -> OpenAICompatibleProvider pointed to localhost:11434
        - "anthropic/claude-3-5-sonnet-20241022" -> AnthropicProvider
    """
    descriptor = provider_or_model or settings.default_provider or "mock"

    if "/" in descriptor:
        provider_name, model_name = descriptor.split("/", 1)
    else:
        provider_name = descriptor.lower()
        model_name = settings.default_model

    provider_name = provider_name.lower().strip()

    if provider_name == "mock":
        return MockProvider(model=model_name or "mock-agent-v1", **kwargs)

    elif provider_name in ("nvidia", "nvidia_nim", "nim"):
        return NvidiaNimProvider(
            model=model_name or settings.nvidia_nim_model or "meta/llama-3.3-70b-instruct",
            api_key=api_key or settings.nvidia_nim_api_key,
            base_url=settings.nvidia_nim_base_url,
            **kwargs,
        )

    elif provider_name in ("openai", "gpt"):
        return OpenAICompatibleProvider(
            model=model_name or "gpt-4o-mini",
            api_key=api_key or settings.openai_api_key,
            base_url=settings.openai_base_url,
            **kwargs,
        )

    elif provider_name in ("gemini", "google"):
        return GeminiProvider(
            model=model_name or "gemini-2.5-flash",
            api_key=api_key or settings.gemini_api_key,
            **kwargs,
        )

    elif provider_name in ("anthropic", "claude"):
        return AnthropicProvider(
            model=model_name or "claude-3-5-sonnet-20241022",
            api_key=api_key or settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
            **kwargs,
        )

    elif provider_name == "ollama":
        return OpenAICompatibleProvider(
            model=model_name or "llama3",
            api_key="ollama",
            base_url=settings.ollama_base_url,
            **kwargs,
        )

    # Fallback to OpenAI compatible endpoint
    return OpenAICompatibleProvider(
        model=model_name or descriptor,
        api_key=api_key or settings.openai_api_key,
        base_url=settings.openai_base_url,
        **kwargs,
    )
