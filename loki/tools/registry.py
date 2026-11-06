"""
Tool Registry for managing and invoking tools in Loki.
"""

from typing import Any, Dict, List, Optional
from loki.tools.base import Tool
from loki.types import ToolCall, ToolResult


class ToolRegistry:
    """Manages collection of tools available to an agent runtime."""

    def __init__(self, tools: Optional[List[Tool]] = None):
        self._tools: Dict[str, Tool] = {}
        if tools:
            for t in tools:
                self.register(t)

    def register(self, tool_instance: Tool) -> None:
        self._tools[tool_instance.name] = tool_instance

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Tool]:
        return list(self._tools.values())

    def get_schemas(self) -> List[Dict[str, Any]]:
        return [t.to_openai_schema() for t in self._tools.values()]

    async def execute_call(self, tool_call: ToolCall) -> ToolResult:
        tool_obj = self.get(tool_call.name)
        if not tool_obj:
            return ToolResult(
                call_id=tool_call.id,
                tool_name=tool_call.name,
                output=f"Error: Tool '{tool_call.name}' not found in registry. Available tools: {list(self._tools.keys())}",
                is_error=True,
            )

        args = tool_call.arguments or {}
        result = await tool_obj.execute(**args)
        result.call_id = tool_call.id
        return result
