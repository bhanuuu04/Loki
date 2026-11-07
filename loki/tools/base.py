"""
Base tool interfaces and decorators for Loki.
"""

from typing import Any, Callable, Dict, List, Optional, get_type_hints
import inspect
import functools
import time
from pydantic import BaseModel
from loki.types import ToolResult


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
    ):
        self.name = name
        self.description = description
        self.func = func
        self.is_async = inspect.iscoroutinefunction(func)
        self.parameters_schema = parameters_schema or self._generate_schema_from_func(func)

    @property
    def parameters(self) -> Dict[str, Any]:
        """Convenience property for accessing parameter schema."""
        return self.parameters_schema

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


def tool(name: Optional[str] = None, description: Optional[str] = None):
    """
    Decorator to convert a standard Python function into a Loki Tool.
    
    Usage:
        @tool(name="calculator", description="Performs basic arithmetic")
        def calculate(expression: str) -> str:
            return str(eval(expression))
    """
    def decorator(fn: Callable[..., Any]) -> Tool:
        tool_name = name or fn.__name__
        tool_desc = description or (fn.__doc__ or f"Tool {tool_name}").strip()
        return Tool(name=tool_name, description=tool_desc, func=fn)

    return decorator
