"""
Persistent storage and repository for assessments and security findings for Loki 2.0.
Combines ACID SQLite transactional storage with atomic, safe file backups
and path traversal protection.
"""

from typing import Any, Dict, List, Optional
import json
import os
from pathlib import Path
import tempfile
import time

from loki.assessment.models import (
    AssessmentSession,
    DiscoveredAsset,
    SecurityFinding,
    SeverityLevel,
)
from loki.security.scope_manager import ScopeConfig
from loki.assessment.db import DatabaseManager


class AssessmentStore:
    """
    Manages active and historical security assessments using SQLite transactions
    and crash-safe atomic file writing.
    """

    def __init__(self, storage_dir: Optional[str] = None, db_manager: Optional[DatabaseManager] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else Path.cwd() / "assessments"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.db = db_manager or DatabaseManager(
            db_path=str(self.storage_dir.parent / "data" / "loki.db")
        )
        self._cache: Dict[str, AssessmentSession] = {}

    def _safe_filepath(self, session_id: str) -> Path:
        """Sanitizes filename and prevents directory traversal attacks."""
        clean_id = Path(session_id).name.replace("..", "").replace("/", "").replace("\\", "")
        if not clean_id:
            clean_id = "default_session"
        target_path = (self.storage_dir / f"{clean_id}.json").resolve()
        if not str(target_path).startswith(str(self.storage_dir.resolve())):
            raise ValueError(f"Path traversal detected in session_id: {session_id}")
        return target_path

    def _atomic_write_file(self, filepath: Path, content: str) -> None:
        """Performs atomic file write to prevent corrupted state on sudden crash."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        temp_file = filepath.with_suffix(".tmp")
        temp_file.write_text(content, encoding="utf-8")
        temp_file.replace(filepath)

    def create_assessment(
        self,
        session_id: str,
        name: str,
        scope: ScopeConfig,
    ) -> AssessmentSession:
        session = AssessmentSession(
            session_id=session_id,
            assessment_name=name,
            scope=scope,
        )
        self.save_assessment(session)
        return session

    def save_assessment(self, session: AssessmentSession) -> None:
        """Saves assessment to both SQLite database and atomic JSON file."""
        session.updated_at = time.time()
        self._cache[session.session_id] = session

        # 1. Transactional SQLite write
        try:
            self.db.save_assessment(session)
        except Exception:
            pass

        # 2. Crash-safe atomic disk backup
        filepath = self._safe_filepath(session.session_id)
        self._atomic_write_file(filepath, session.model_dump_json(indent=2))

    def load_assessment(self, session_id: str) -> Optional[AssessmentSession]:
        """Loads assessment from cache, SQLite, or disk."""
        if session_id in self._cache:
            return self._cache[session_id]

        # Try SQLite first
        session = None
        try:
            session = self.db.load_assessment(session_id)
        except Exception:
            pass

        if session:
            self._cache[session_id] = session
            return session

        # Fallback to disk JSON file
        try:
            filepath = self._safe_filepath(session_id)
            if filepath.exists():
                data = json.loads(filepath.read_text(encoding="utf-8"))
                session = AssessmentSession(**data)
                self._cache[session_id] = session
                return session
        except Exception:
            pass

        return None

    def list_assessments(self) -> List[Dict[str, Any]]:
        """Query assessment history from SQLite with fallback to disk."""
        try:
            db_results = self.db.list_assessments()
            if db_results:
                return db_results
        except Exception:
            pass

        results = []
        for file in self.storage_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                results.append({
                    "session_id": data.get("session_id"),
                    "assessment_name": data.get("assessment_name"),
                    "status": data.get("status"),
                    "total_findings": len(data.get("findings", [])),
                    "created_at": data.get("created_at"),
                })
            except Exception:
                continue
        return results

    def add_finding(self, session_id: str, finding: SecurityFinding) -> None:
        session = self.load_assessment(session_id)
        if session:
            existing = next((f for f in session.findings if f.finding_id == finding.finding_id), None)
            if not existing:
                session.findings.append(finding)
                self.save_assessment(session)

    def record_asset(self, session_id: str, asset: DiscoveredAsset) -> None:
        session = self.load_assessment(session_id)
        if session:
            session.assets[asset.identifier] = asset
            self.save_assessment(session)

    def index_evidence(
        self,
        session_id: str,
        tool_name: str,
        raw_output: str,
        task_id: Optional[str] = None,
        command_args: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Stores evidence into SQLite evidence index."""
        return self.db.index_evidence(
            session_id=session_id,
            tool_name=tool_name,
            raw_output=raw_output,
            task_id=task_id,
            command_args=command_args,
            metadata=metadata,
        )
