"""
Base abstraction for multi-provider LLM adapters in Loki.
"""

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, List, Optional
from loki.types import LLMResponse, Message


class BaseLLMProvider(ABC):
    """Abstract interface that all LLM providers must implement."""

    def __init__(self, model: str, **kwargs: Any):
        self.model = model
        self.extra_config = kwargs

    @abstractmethod
    async def chat_complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Execute a non-streaming chat completion with optional tool declarations."""
        pass

    @abstractmethod
    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[Any]:
        """Stream chunks from the model. Yields text chunks, tool call fragments, or final response."""
        pass
