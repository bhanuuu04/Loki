import pytest
from pathlib import Path
from loki.assessment.db import DatabaseManager
from loki.assessment.store import AssessmentStore
from loki.assessment.models import (
    AssessmentSession,
    DiscoveredAsset,
    SecurityFinding,
    SeverityLevel,
)
from loki.security.scope_manager import ScopeConfig
from loki.runtime.context import AgentContext
from loki.runtime.memory import MemoryStore
from loki.types import Role, ToolResult


def test_sqlite_transactional_writes(tmp_path):
    db_file = tmp_path / "test_loki.db"
    db = DatabaseManager(db_path=str(db_file))

    scope = ScopeConfig(assessment_name="ACID Test", targets=["target.test"])
    session = AssessmentSession(
        session_id="sess_acid_01",
        assessment_name="ACID Assessment",
        scope=scope,
    )
    asset = DiscoveredAsset(
        identifier="target.test",
        ip_address="192.168.1.100",
        open_ports=[80, 443],
    )
    session.assets[asset.identifier] = asset
    finding = SecurityFinding(
        title="Missing CSP Header",
        description="CSP header is absent",
        affected_asset="target.test",
        severity=SeverityLevel.LOW,
    )
    session.findings.append(finding)

    # Save to SQLite
    db.save_assessment(session)

    # Load back and verify integrity
    loaded = db.load_assessment("sess_acid_01")
    assert loaded is not None
    assert loaded.assessment_name == "ACID Assessment"
    assert "target.test" in loaded.assets
    assert loaded.assets["target.test"].open_ports == [80, 443]
    assert len(loaded.findings) == 1
    assert loaded.findings[0].title == "Missing CSP Header"


def test_atomic_file_write_and_traversal_prevention(tmp_path):
    store = AssessmentStore(storage_dir=str(tmp_path / "assessments"))
    scope = ScopeConfig(assessment_name="Safety Test", targets=["safe.local"])
    session = store.create_assessment("sess_safe_01", "Safety Assessment", scope)

    # Verify atomic file exists and is readable
    target_file = tmp_path / "assessments" / "sess_safe_01.json"
    assert target_file.exists()

    # Traversal attempt should be sanitized
    safe_path = store._safe_filepath("../../etc/passwd")
    assert ".." not in safe_path.name
    assert str(safe_path).startswith(str(tmp_path.resolve()))


def test_evidence_indexing_with_hash(tmp_path):
    db_file = tmp_path / "evidence_test.db"
    db = DatabaseManager(db_path=str(db_file))

    scope = ScopeConfig(assessment_name="Evidence Test", targets=["host.local"])
    session = AssessmentSession(session_id="sess_01", assessment_name="Evidence Test", scope=scope)
    db.save_assessment(session)

    raw_data = "Nmap scan report for host.local (10.0.0.1)\nPORT 80/tcp open"
    evidence_id = db.index_evidence(
        session_id="sess_01",
        tool_name="nmap",
        raw_output=raw_data,
        command_args=["-p80", "10.0.0.1"],
    )
    assert evidence_id is not None
    assert len(evidence_id) >= 10


def test_context_compaction_preserves_system_prompt_and_recent_history():
    ctx = AgentContext(system_prompt="You are Loki.", max_messages_before_compaction=8)

    # Add 12 user/assistant/tool messages
    for i in range(6):
        ctx.add_user_message(f"User message {i}")
        ctx.add_tool_result(ToolResult(call_id=f"c{i}", tool_name="test_tool", output=f"Output {i}"))
        ctx.add_assistant_message(f"Assistant thought {i}")

    # Messages should automatically be compacted
    messages = ctx.get_messages()
    assert messages[0].role == Role.SYSTEM
    assert messages[0].content == "You are Loki."

    # Look for context compaction summary marker
    has_compaction_marker = any("Context Compaction:" in (m.content or "") for m in messages)
    assert has_compaction_marker

    # Most recent message should be preserved
    assert "Assistant thought 5" in messages[-1].content or "Output 5" in messages[-1].content


def test_audit_logger_redaction_and_tamper_evidence(tmp_path):
    """Test that AuditLogger redacts sensitive tokens and detects log tampering."""
    from loki.security.audit_logger import AuditLogger, AuditEntry

    log_dir = tmp_path / "audit_test"
    logger = AuditLogger(log_dir=str(log_dir))

    # Entry with sensitive credentials
    entry1 = AuditEntry(
        assessment_name="Audit Redaction Test",
        target="target.local",
        tool_name="curl",
        command_args=[
            "curl -H 'Authorization: Bearer secret_api_key_123456'",
            "--data password=super_secret_pass",
        ],
        risk_level="low",
        is_authorized=True,
        status="executed",
    )
    logger.log(entry1)

    # Verify redaction
    entries = logger.get_entries("Audit Redaction Test")
    assert len(entries) == 1
    assert "secret_api_key" not in entries[0].command_args[0]
    assert "[REDACTED_BEARER_TOKEN]" in entries[0].command_args[0]
    assert "super_secret_pass" not in entries[0].command_args[1]

    # Entry 2
    entry2 = AuditEntry(
        assessment_name="Audit Redaction Test",
        target="target.local",
        tool_name="nmap",
        command_args=["nmap -sV target.local"],
        risk_level="low",
        is_authorized=True,
        status="executed",
    )
    logger.log(entry2)

    # Verify cryptographic hash chain
    is_valid, count, err = logger.verify_audit_integrity()
    assert is_valid is True
    assert count == 2
    assert err is None

    # Tamper with file
    lines = logger.log_file.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("target.local", "tampered.local")
    logger.log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify tamper is caught
    tampered_valid, _, tamper_err = logger.verify_audit_integrity()
    assert tampered_valid is False
    assert "tamper" in tamper_err.lower() or "broken" in tamper_err.lower()
