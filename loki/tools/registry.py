from __future__ import annotations

"""
Tool Registry for managing and invoking tools in Loki 2.0.
All executions strictly route through the ExecutionGateway.
"""

from typing import TYPE_CHECKING, Any, Dict, List, Optional
from loki.tools.base import Tool
from loki.types import ToolCall, ToolResult

if TYPE_CHECKING:
    from loki.security.gateway import ExecutionGateway


class ToolRegistry:
    """Manages collection of tools available to an agent runtime."""

    def __init__(
        self,
        tools: Optional[List[Tool]] = None,
        gateway: Optional[Any] = None,
    ):
        self._tools: Dict[str, Tool] = {}
        if gateway is not None:
            self.gateway = gateway
        else:
            from loki.security.gateway import ExecutionGateway
            self.gateway = ExecutionGateway.get_default()

        if tools:
            for t in tools:
                self.register(t)

    def set_gateway(self, gateway: Any) -> None:
        """Update or assign an execution gateway."""
        self.gateway = gateway

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
        """
        Mandatory single path for tool invocation.
        Directs execution strictly through the ExecutionGateway.
        """
        tool_obj = self.get(tool_call.name)
        return await self.gateway.execute(tool_call=tool_call, tool_instance=tool_obj)
