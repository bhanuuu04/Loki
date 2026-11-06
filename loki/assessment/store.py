"""
Persistent storage and repository for assessments and security findings.
"""

from typing import Any, Dict, List, Optional
import json
import time
from pathlib import Path

from loki.assessment.models import (
    AssessmentSession,
    DiscoveredAsset,
    SecurityFinding,
    SeverityLevel,
)
from loki.security.scope_manager import ScopeConfig


class AssessmentStore:
    """Manages active and historical security assessments on disk."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else Path.cwd() / "assessments"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, AssessmentSession] = {}

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
        session.updated_at = time.time()
        self._cache[session.session_id] = session
        filepath = self.storage_dir / f"{session.session_id}.json"
        filepath.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    def load_assessment(self, session_id: str) -> Optional[AssessmentSession]:
        if session_id in self._cache:
            return self._cache[session_id]

        filepath = self.storage_dir / f"{session_id}.json"
        if filepath.exists():
            data = json.loads(filepath.read_text(encoding="utf-8"))
            session = AssessmentSession(**data)
            self._cache[session_id] = session
            return session
        return None

    def list_assessments(self) -> List[Dict[str, Any]]:
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
            # Check if finding already exists by ID
            existing = next((f for f in session.findings if f.finding_id == finding.finding_id), None)
            if not existing:
                session.findings.append(finding)
                self.save_assessment(session)

    def record_asset(self, session_id: str, asset: DiscoveredAsset) -> None:
        session = self.load_assessment(session_id)
        if session:
            session.assets[asset.identifier] = asset
            self.save_assessment(session)
