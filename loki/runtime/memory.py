"""
Session memory and state persistence for Loki agents.
"""

from typing import Dict, List, Optional
import json
from pathlib import Path
from loki.runtime.context import AgentContext
from loki.types import Message


class MemoryStore:
    """In-memory and file-backed session store."""

    def __init__(self, persistence_dir: Optional[str] = None):
        self._sessions: Dict[str, List[Message]] = {}
        self.persistence_dir = Path(persistence_dir) if persistence_dir else None
        if self.persistence_dir:
            self.persistence_dir.mkdir(parents=True, exist_ok=True)

    def save_session(self, session_id: str, context: AgentContext) -> None:
        self._sessions[session_id] = context.get_messages()
        if self.persistence_dir:
            file_path = self.persistence_dir / f"{session_id}.json"
            data = [m.model_dump() for m in self._sessions[session_id]]
            file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_session(self, session_id: str, system_prompt: Optional[str] = None) -> AgentContext:
        ctx = AgentContext(system_prompt=system_prompt)
        # Check memory first
        if session_id in self._sessions:
            ctx.messages = list(self._sessions[session_id])
            return ctx

        # Check disk
        if self.persistence_dir:
            file_path = self.persistence_dir / f"{session_id}.json"
            if file_path.exists():
                try:
                    data = json.loads(file_path.read_text(encoding="utf-8"))
                    ctx.messages = [Message(**item) for item in data]
                    self._sessions[session_id] = ctx.messages
                    return ctx
                except Exception:
                    pass

        return ctx

    def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        if self.persistence_dir:
            file_path = self.persistence_dir / f"{session_id}.json"
            if file_path.exists():
                file_path.unlink()
