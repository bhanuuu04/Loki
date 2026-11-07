"""
SQLite-backed ACID transactional persistence engine for Loki 2.0.
Provides transactional storage for assessments, assets, findings, evidence indexing,
session conversation history, and plan checkpoints.
"""

from typing import Any, Dict, List, Optional
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from loki.assessment.models import (
    AssessmentSession,
    DiscoveredAsset,
    FindingLifecycle,
    ReproductionRecord,
    SecurityFinding,
    SeverityLevel,
    ConfidenceLevel,
)
from loki.security.scope_manager import ScopeConfig
from loki.security.policy_engine import ExecutionMode
from loki.types import Message, Role, ToolCall


class DatabaseManager:
    """Manages SQLite database lifecycle, schema migrations, and transactions."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            data_dir = Path.cwd() / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "loki.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_db(self) -> None:
        """Initialize database schema with strict constraints and indexes."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assessments (
                    session_id TEXT PRIMARY KEY,
                    assessment_name TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    execution_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    ip_address TEXT,
                    open_ports TEXT,
                    services TEXT,
                    technologies TEXT,
                    endpoints TEXT,
                    first_seen REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES assessments(session_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_asset TEXT NOT NULL,
                    affected_endpoint TEXT,
                    category TEXT NOT NULL,
                    cwe_id TEXT,
                    cve_id TEXT,
                    cvss_score REAL NOT NULL DEFAULT 0.0,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    evidence TEXT,
                    evidence_hash TEXT,
                    reproduction_json TEXT,
                    false_positive_score REAL NOT NULL DEFAULT 0.0,
                    false_positive_reasons TEXT,
                    remediation TEXT,
                    references_json TEXT,
                    discovered_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES assessments(session_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    task_id TEXT,
                    tool_name TEXT NOT NULL,
                    command_args TEXT,
                    output_hash TEXT,
                    raw_output TEXT,
                    metadata_json TEXT,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES assessments(session_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    name TEXT,
                    tool_calls_json TEXT,
                    tool_call_id TEXT,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
                CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
                CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
            """)

    # -------------------------------------------------------------
    # ASSESSMENT TRANSACTIONS
    # -------------------------------------------------------------
    def save_assessment(self, session: AssessmentSession) -> None:
        """Upsert assessment session within an atomic transaction."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assessments (session_id, assessment_name, scope_json, execution_mode, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    assessment_name=excluded.assessment_name,
                    scope_json=excluded.scope_json,
                    execution_mode=excluded.execution_mode,
                    status=excluded.status,
                    updated_at=excluded.updated_at;
                """,
                (
                    session.session_id,
                    session.assessment_name,
                    session.scope.model_dump_json(),
                    session.execution_mode.value,
                    session.status,
                    session.created_at,
                    session.updated_at,
                ),
            )

            # Sync assets
            for asset in session.assets.values():
                conn.execute(
                    """
                    INSERT INTO assets (asset_id, session_id, identifier, ip_address, open_ports, services, technologies, endpoints, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        ip_address=excluded.ip_address,
                        open_ports=excluded.open_ports,
                        services=excluded.services,
                        technologies=excluded.technologies,
                        endpoints=excluded.endpoints;
                    """,
                    (
                        asset.asset_id,
                        session.session_id,
                        asset.identifier,
                        asset.ip_address,
                        json.dumps(asset.open_ports),
                        json.dumps(asset.services),
                        json.dumps(asset.technologies),
                        json.dumps(asset.endpoints),
                        asset.first_seen,
                    ),
                )

            # Sync findings
            for finding in session.findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        finding_id, session_id, title, description, affected_asset, affected_endpoint,
                        category, cwe_id, cve_id, cvss_score, severity, confidence, lifecycle,
                        evidence, evidence_hash, reproduction_json, false_positive_score,
                        false_positive_reasons, remediation, references_json, discovered_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        title=excluded.title,
                        description=excluded.description,
                        affected_endpoint=excluded.affected_endpoint,
                        cvss_score=excluded.cvss_score,
                        severity=excluded.severity,
                        confidence=excluded.confidence,
                        lifecycle=excluded.lifecycle,
                        evidence=excluded.evidence,
                        evidence_hash=excluded.evidence_hash,
                        reproduction_json=excluded.reproduction_json,
                        false_positive_score=excluded.false_positive_score,
                        false_positive_reasons=excluded.false_positive_reasons,
                        remediation=excluded.remediation,
                        updated_at=excluded.updated_at;
                    """,
                    (
                        finding.finding_id,
                        session.session_id,
                        finding.title,
                        finding.description,
                        finding.affected_asset,
                        finding.affected_endpoint,
                        finding.category,
                        finding.cwe_id,
                        finding.cve_id,
                        finding.cvss_score,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.lifecycle.value,
                        finding.evidence,
                        finding.evidence_hash,
                        finding.reproduction.model_dump_json() if finding.reproduction else None,
                        finding.false_positive_risk_score,
                        json.dumps(finding.false_positive_reasons),
                        finding.remediation,
                        json.dumps(finding.references),
                        finding.discovered_at,
                        finding.updated_at,
                    ),
                )

    def load_assessment(self, session_id: str) -> Optional[AssessmentSession]:
        """Load complete assessment session with all assets and findings."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM assessments WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                return None

            scope_dict = json.loads(row["scope_json"])
            scope = ScopeConfig(**scope_dict)

            # Load assets
            assets_dict: Dict[str, DiscoveredAsset] = {}
            for a_row in conn.execute("SELECT * FROM assets WHERE session_id = ?", (session_id,)).fetchall():
                asset = DiscoveredAsset(
                    asset_id=a_row["asset_id"],
                    identifier=a_row["identifier"],
                    ip_address=a_row["ip_address"],
                    open_ports=json.loads(a_row["open_ports"] or "[]"),
                    services=json.loads(a_row["services"] or "{}"),
                    technologies=json.loads(a_row["technologies"] or "[]"),
                    endpoints=json.loads(a_row["endpoints"] or "[]"),
                    first_seen=a_row["first_seen"],
                )
                assets_dict[asset.identifier] = asset

            # Load findings
            findings_list: List[SecurityFinding] = []
            for f_row in conn.execute("SELECT * FROM findings WHERE session_id = ?", (session_id,)).fetchall():
                repro_raw = f_row["reproduction_json"]
                repro = ReproductionRecord(**json.loads(repro_raw)) if repro_raw else None
                finding = SecurityFinding(
                    finding_id=f_row["finding_id"],
                    title=f_row["title"],
                    description=f_row["description"],
                    affected_asset=f_row["affected_asset"],
                    affected_endpoint=f_row["affected_endpoint"],
                    category=f_row["category"],
                    cwe_id=f_row["cwe_id"],
                    cve_id=f_row["cve_id"],
                    cvss_score=f_row["cvss_score"],
                    severity=SeverityLevel(f_row["severity"]),
                    confidence=ConfidenceLevel(f_row["confidence"]),
                    lifecycle=FindingLifecycle(f_row["lifecycle"]),
                    evidence=f_row["evidence"] or "",
                    evidence_hash=f_row["evidence_hash"],
                    reproduction=repro,
                    false_positive_risk_score=f_row["false_positive_score"],
                    false_positive_reasons=json.loads(f_row["false_positive_reasons"] or "[]"),
                    remediation=f_row["remediation"] or "",
                    references=json.loads(f_row["references_json"] or "[]"),
                    discovered_at=f_row["discovered_at"],
                    updated_at=f_row["updated_at"],
                )
                findings_list.append(finding)

            return AssessmentSession(
                session_id=row["session_id"],
                assessment_name=row["assessment_name"],
                scope=scope,
                execution_mode=ExecutionMode(row["execution_mode"]),
                status=row["status"],
                assets=assets_dict,
                findings=findings_list,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_assessments(self) -> List[Dict[str, Any]]:
        """List summary of all historical assessments."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT a.session_id, a.assessment_name, a.status, a.created_at,
                       COUNT(f.finding_id) as total_findings
                FROM assessments a
                LEFT JOIN findings f ON a.session_id = f.session_id
                GROUP BY a.session_id
                ORDER BY a.created_at DESC;
                """
            ).fetchall()
            return [
                {
                    "session_id": r["session_id"],
                    "assessment_name": r["assessment_name"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                    "total_findings": r["total_findings"],
                }
                for r in rows
            ]

    # -------------------------------------------------------------
    # EVIDENCE INDEXING
    # -------------------------------------------------------------
    def index_evidence(
        self,
        session_id: str,
        tool_name: str,
        raw_output: str,
        task_id: Optional[str] = None,
        command_args: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Store and index tool execution evidence with cryptographic hash."""
        evidence_id = str(uuid.uuid4())
        import hashlib
        out_hash = hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO evidence (evidence_id, session_id, task_id, tool_name, command_args, output_hash, raw_output, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    session_id,
                    task_id,
                    tool_name,
                    json.dumps(command_args or []),
                    out_hash,
                    raw_output,
                    json.dumps(metadata or {}),
                    time.time(),
                ),
            )
        return evidence_id

    def get_evidence(self, session_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve one evidence record scoped to its owning assessment."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT evidence_id, session_id, task_id, tool_name, command_args, "
                "output_hash, raw_output, metadata_json, created_at "
                "FROM evidence WHERE evidence_id = ? AND session_id = ?",
                (evidence_id, session_id),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["command_args"] = json.loads(result.get("command_args") or "[]")
        except (TypeError, ValueError):
            result["command_args"] = []
        try:
            result["metadata"] = json.loads(result.get("metadata_json") or "{}")
        except (TypeError, ValueError):
            result["metadata"] = {}
        return result

    # -------------------------------------------------------------
    # CONVERSATION SESSION MEMORY
    # -------------------------------------------------------------
    def save_messages(self, session_id: str, messages: List[Message]) -> None:
        """Replace or save conversation message history for a session."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            for m in messages:
                tool_calls_json = None
                if m.tool_calls:
                    tool_calls_json = json.dumps([tc.model_dump() for tc in m.tool_calls])
                conn.execute(
                    """
                    INSERT INTO messages (session_id, role, content, name, tool_calls_json, tool_call_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        m.role.value,
                        m.content,
                        m.name,
                        tool_calls_json,
                        m.tool_call_id,
                        time.time(),
                    ),
                )

    def load_messages(self, session_id: str) -> List[Message]:
        """Load conversation message history for a session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE session_id = ? ORDER BY id ASC", (session_id,)
            ).fetchall()
            messages: List[Message] = []
            for r in rows:
                tool_calls = None
                if r["tool_calls_json"]:
                    tc_list = json.loads(r["tool_calls_json"])
                    tool_calls = [ToolCall(**item) for item in tc_list]
                messages.append(
                    Message(
                        role=Role(r["role"]),
                        content=r["content"],
                        name=r["name"],
                        tool_calls=tool_calls,
                        tool_call_id=r["tool_call_id"],
                    )
                )
            return messages

    # -------------------------------------------------------------
    # CHECKPOINTS
    # -------------------------------------------------------------
    def save_checkpoint(self, checkpoint_id: str, plan_id: str, session_id: str, plan_json: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (checkpoint_id, plan_id, session_id, plan_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(checkpoint_id) DO UPDATE SET plan_json=excluded.plan_json;
                """,
                (checkpoint_id, plan_id, session_id, plan_json, time.time()),
            )

    def load_latest_checkpoint(self, session_id: str) -> Optional[str]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT plan_json FROM checkpoints WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            return row["plan_json"] if row else None
