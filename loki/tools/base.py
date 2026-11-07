"""
Base tool interfaces and decorators for Loki.
Supports capability metadata tagging for security enforcement.
"""

from typing import Any, Callable, Dict, List, Optional, Set, Union, get_type_hints
from enum import Enum
import inspect
import functools
import time
from pydantic import BaseModel, Field
from loki.types import ToolResult


class ToolCapability(str, Enum):
    NETWORK = "network"
    TARGET_INTERACTION = "target_interaction"
    SYSTEM = "system"
    SHELL = "shell"
    PYTHON = "python"
    FILESYSTEM = "filesystem"
    UTILITY = "utility"


class ToolMetadata(BaseModel):
    """Structured security and capability metadata for tool governance."""
    tool_name: str
    category: str = "general"
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_process_execution: bool = False
    target_parameter_schema: Optional[Dict[str, Any]] = None
    required_permission_level: str = "standard"  # standard, elevated, admin
    risk_classification: str = "low"  # low, medium, high, critical
    expected_side_effects: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False


def _py_type_to_json_schema(py_type: Any) -> Dict[str, Any]:
    """Map python types to JSON Schema types."""
    if py_type in (str, Optional[str]):
        return {"type": "string"}
    elif py_type in (int, Optional[int]):
        return {"type": "integer"}
    elif py_type in (float, Optional[float]):
        return {"type": "number"}
    elif py_type in (bool, Optional[bool]):
        return {"type": "boolean"}
    elif py_type in (list, List, Optional[list], Optional[List]):
        return {"type": "array", "items": {"type": "string"}}
    elif py_type in (dict, Dict, Optional[dict], Optional[Dict]):
        return {"type": "object"}
    return {"type": "string"}


class Tool:
    """Encapsulates a callable tool that an LLM agent can invoke."""

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        parameters_schema: Optional[Dict[str, Any]] = None,
        capabilities: Optional[List[Union[ToolCapability, str]]] = None,
        metadata: Optional[ToolMetadata] = None,
    ):
        self.name = name
        self.description = description
        self.func = func
        self.is_async = inspect.iscoroutinefunction(func)
        self.parameters_schema = parameters_schema or self._generate_schema_from_func(func)
        self.capabilities: Set[str] = {
            c.value if isinstance(c, ToolCapability) else str(c)
            for c in (capabilities or [])
        }
        self.metadata = metadata or self._derive_metadata()

    def _derive_metadata(self) -> ToolMetadata:
        """Derive default structured security metadata from capabilities."""
        is_net = (
            ToolCapability.NETWORK.value in self.capabilities
            or ToolCapability.TARGET_INTERACTION.value in self.capabilities
        )
        is_fs = ToolCapability.FILESYSTEM.value in self.capabilities
        is_proc = any(
            c in self.capabilities
            for c in (ToolCapability.SYSTEM.value, ToolCapability.SHELL.value, ToolCapability.PYTHON.value)
        )
        risk = "medium" if is_proc else ("medium" if is_net else "low")
        return ToolMetadata(
            tool_name=self.name,
            category="recon" if is_net else ("system" if is_proc else "utility"),
            requires_network=is_net,
            requires_filesystem=is_fs,
            requires_process_execution=is_proc,
            risk_classification=risk,
            requires_human_approval=(risk == "critical"),
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        """Convenience property for accessing parameter schema."""
        return self.parameters_schema

    def has_capability(self, cap: Union[ToolCapability, str]) -> bool:
        """Check if tool possesses specified security or operational capability."""
        val = cap.value if isinstance(cap, ToolCapability) else str(cap)
        return val in self.capabilities

    def _generate_schema_from_func(self, fn: Callable[..., Any]) -> Dict[str, Any]:
        """Automatically derive JSON Schema parameters from Python type hints."""
        sig = inspect.signature(fn)
        type_hints = get_type_hints(fn) if hasattr(fn, "__annotations__") else {}
        
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            py_type = type_hints.get(param_name, str)
            param_schema = _py_type_to_json_schema(py_type)
            properties[param_name] = param_schema

            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def to_openai_schema(self) -> Dict[str, Any]:
        """Export tool definition in standard OpenAI function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            },
        }

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Allow Tool instances to be called directly like normal functions."""
        return self.func(*args, **kwargs)

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with arguments and measure latency."""
        start_time = time.perf_counter()
        try:
            if self.is_async:
                output = await self.func(**kwargs)
            else:
                output = self.func(**kwargs)
            
            # Format Pydantic models to dict if returned
            if isinstance(output, BaseModel):
                output = output.model_dump()

            latency_ms = (time.perf_counter() - start_time) * 1000
            return ToolResult(
                call_id="",
                tool_name=self.name,
                output=output,
                is_error=False,
                execution_time_ms=latency_ms,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return ToolResult(
                call_id="",
                tool_name=self.name,
                output=f"Error executing {self.name}: {type(e).__name__}: {str(e)}",
                is_error=True,
                execution_time_ms=latency_ms,
            )


def tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    capabilities: Optional[List[Union[ToolCapability, str]]] = None,
    metadata: Optional[ToolMetadata] = None,
):
    """
    Decorator to convert a standard Python function into a Loki Tool.
    """
    def decorator(fn: Callable[..., Any]) -> Tool:
        tool_name = name or fn.__name__
        tool_desc = description or (fn.__doc__ or f"Tool {tool_name}").strip()
        return Tool(
            name=tool_name,
            description=tool_desc,
            func=fn,
            capabilities=capabilities,
            metadata=metadata,
        )

    return decorator
