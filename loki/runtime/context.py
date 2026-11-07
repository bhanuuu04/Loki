"""
Context and message history management for Loki agents with Context Compaction.
"""

from typing import List, Optional
from loki.types import Message, Role, ToolCall, ToolResult


class AgentContext:
    """Maintains working memory, token budgeting, and message history for an agent run."""

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        max_messages_before_compaction: int = 24,
        max_estimated_tokens: int = 12000,
    ):
        self.messages: List[Message] = []
        self.max_messages_before_compaction = max_messages_before_compaction
        self.max_estimated_tokens = max_estimated_tokens

        if system_prompt:
            self.messages.append(Message(role=Role.SYSTEM, content=system_prompt))

    def set_system_prompt(self, content: str) -> Message:
        """
        Replace the active system instruction without discarding conversation history.

        This refreshes runtime facts such as the current authorized scope when
        a previously saved session is resumed.
        """
        if self.messages and self.messages[0].role == Role.SYSTEM:
            self.messages[0].content = content
            return self.messages[0]

        message = Message(role=Role.SYSTEM, content=content)
        self.messages.insert(0, message)
        return message

    def add_user_message(self, content: str) -> Message:
        msg = Message(role=Role.USER, content=content)
        self.messages.append(msg)
        self._check_auto_compaction()
        return msg

    def add_assistant_message(
        self, content: Optional[str] = None, tool_calls: Optional[List[ToolCall]] = None
    ) -> Message:
        msg = Message(role=Role.ASSISTANT, content=content or "", tool_calls=tool_calls)
        self.messages.append(msg)
        self._check_auto_compaction()
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
        self._check_auto_compaction()
        return msg

    def get_messages(self) -> List[Message]:
        return list(self.messages)

    def estimate_tokens(self) -> int:
        """Rough token count estimation based on 4 characters per token."""
        total_chars = sum(len(m.content or "") for m in self.messages)
        for m in self.messages:
            if m.tool_calls:
                for tc in m.tool_calls:
                    total_chars += len(tc.name) + len(str(tc.arguments))
        return max(1, total_chars // 4)

    def _check_auto_compaction(self) -> None:
        """Triggers compaction if message count or estimated token limits are breached."""
        if len(self.messages) > self.max_messages_before_compaction or self.estimate_tokens() > self.max_estimated_tokens:
            self.compact_context()

    def compact_context(self, preserve_recent: int = 6) -> None:
        """
        Compacts long conversation history by condensing older exchanges
        while strictly preserving the system prompt and the most recent N messages.
        """
        if len(self.messages) <= preserve_recent + 2:
            return

        has_system = self.messages[0].role == Role.SYSTEM
        start_idx = 1 if has_system else 0
        end_idx = len(self.messages) - preserve_recent

        if end_idx <= start_idx:
            return

        middle_messages = self.messages[start_idx:end_idx]

        # Synthesize concise compaction summary of middle messages
        summary_lines = []
        for m in middle_messages:
            if m.role == Role.TOOL and m.name:
                preview = (m.content or "").replace("\n", " ")[:120]
                summary_lines.append(f"- Tool '{m.name}' returned: {preview}...")
            elif m.role == Role.ASSISTANT and m.content:
                preview = m.content.replace("\n", " ")[:120]
                summary_lines.append(f"- Assistant noted: {preview}...")

        summary_text = (
            f"[Context Compaction: Compacted {len(middle_messages)} earlier interactions to preserve context window]\n"
            + "\n".join(summary_lines[:8])
        )

        compacted_msg = Message(role=Role.USER, content=summary_text)

        new_messages = []
        if has_system:
            new_messages.append(self.messages[0])
        new_messages.append(compacted_msg)
        new_messages.extend(self.messages[end_idx:])

        self.messages = new_messages

    def clear(self, keep_system: bool = True) -> None:
        if keep_system and self.messages and self.messages[0].role == Role.SYSTEM:
            self.messages = [self.messages[0]]
        else:
            self.messages = []
