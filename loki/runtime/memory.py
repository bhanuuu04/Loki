"""
Session memory and state persistence for Loki agents for Loki 2.0.
Supports SQLite transactional backing store, session recovery,
and atomic file persistence.
"""

from typing import Dict, List, Optional
import json
import os
from pathlib import Path

from loki.runtime.context import AgentContext
from loki.types import Message
from loki.assessment.db import DatabaseManager


class MemoryStore:
    """In-memory, SQLite-backed, and atomic file-backed session store."""

    def __init__(self, persistence_dir: Optional[str] = None, db_manager: Optional[DatabaseManager] = None):
        self._sessions: Dict[str, List[Message]] = {}
        self.persistence_dir = Path(persistence_dir) if persistence_dir else None
        if self.persistence_dir:
            self.persistence_dir.mkdir(parents=True, exist_ok=True)
            self.db = db_manager or DatabaseManager(db_path=str(self.persistence_dir.parent / "data" / "loki.db"))
        else:
            self.db = db_manager or DatabaseManager()

    def _safe_filepath(self, session_id: str) -> Optional[Path]:
        if not self.persistence_dir:
            return None
        clean_id = Path(session_id).name.replace("..", "").replace("/", "").replace("\\", "")
        return (self.persistence_dir / f"{clean_id}.json").resolve()

    def save_session(self, session_id: str, context: AgentContext) -> None:
        messages = context.get_messages()
        self._sessions[session_id] = messages

        # 1. Transactional SQLite persistence
        try:
            self.db.save_messages(session_id, messages)
        except Exception:
            pass

        # 2. Atomic disk backup
        filepath = self._safe_filepath(session_id)
        if filepath:
            data = [m.model_dump() for m in messages]
            temp_file = filepath.with_suffix(".tmp")
            temp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temp_file.replace(filepath)

    def load_session(self, session_id: str, system_prompt: Optional[str] = None) -> AgentContext:
        ctx = AgentContext(system_prompt=system_prompt)

        # 1. Check in-memory cache
        if session_id in self._sessions:
            ctx.messages = list(self._sessions[session_id])
            return ctx

        # 2. Check SQLite store
        try:
            db_msgs = self.db.load_messages(session_id)
            if db_msgs:
                ctx.messages = db_msgs
                self._sessions[session_id] = ctx.messages
                return ctx
        except Exception:
            pass

        # 3. Check disk file
        filepath = self._safe_filepath(session_id)
        if filepath and filepath.exists():
            try:
                data = json.loads(filepath.read_text(encoding="utf-8"))
                ctx.messages = [Message(**item) for item in data]
                self._sessions[session_id] = ctx.messages
                return ctx
            except Exception:
                pass

        return ctx

    def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        try:
            with self.db._get_connection() as conn:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
        except Exception:
            pass

        filepath = self._safe_filepath(session_id)
        if filepath and filepath.exists():
            try:
                filepath.unlink()
            except Exception:
                pass
