"""
Context and message history management for Loki agents.
"""

from typing import List, Optional
from loki.types import Message, Role, ToolCall, ToolResult


class AgentContext:
    """Maintains working memory and message history for an agent run."""

    def __init__(self, system_prompt: Optional[str] = None):
        self.messages: List[Message] = []
        if system_prompt:
            self.messages.append(Message(role=Role.SYSTEM, content=system_prompt))

    def add_user_message(self, content: str) -> Message:
        msg = Message(role=Role.USER, content=content)
        self.messages.append(msg)
        return msg

    def add_assistant_message(
        self, content: Optional[str] = None, tool_calls: Optional[List[ToolCall]] = None
    ) -> Message:
        msg = Message(role=Role.ASSISTANT, content=content or "", tool_calls=tool_calls)
        self.messages.append(msg)
        return msg

    def add_tool_result(self, result: ToolResult) -> Message:
        output_str = str(result.output) if not isinstance(result.output, str) else result.output
        msg = Message(
            role=Role.TOOL,
            content=output_str,
            name=result.tool_name,
            tool_call_id=result.call_id,
        )
        self.messages.append(msg)
        return msg

    def get_messages(self) -> List[Message]:
        return list(self.messages)

    def clear(self, keep_system: bool = True) -> None:
        if keep_system and self.messages and self.messages[0].role == Role.SYSTEM:
            self.messages = [self.messages[0]]
        else:
            self.messages = []
