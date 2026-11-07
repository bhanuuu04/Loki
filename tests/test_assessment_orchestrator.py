import pytest
import asyncio
from loki.assessment.orchestrator import (
    AssessmentOrchestrator,
    AssessmentPlan,
    AssessmentTask,
    AssessmentPhase,
    TaskStatus,
)
from loki.types import ToolResult


@pytest.mark.asyncio
async def test_orchestrator_phase_dag_and_dependencies():
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id="sess_dag_test",
        assessment_name="Standard Flow",
        target="target.local",
    )
    plan = orch.plan

    # Initial executable tasks should only be root tasks without unsatisfied dependencies
    next_tasks = orch.get_next_tasks()
    assert len(next_tasks) == 1
    root_task = next_tasks[0]
    assert root_task.phase == AssessmentPhase.RECONNAISSANCE
    assert len(root_task.dependencies) == 0

    # Mark root task as COMPLETED
    root_task.status = TaskStatus.COMPLETED

    # Now dependent tasks (Subdomain enum and Header audit) should be executable
    next_tasks_2 = orch.get_next_tasks()
    task_names = [t.name for t in next_tasks_2]
    assert "Subdomain Enumeration" in task_names
    assert "HTTP Security Header Audit" in task_names


@pytest.mark.asyncio
async def test_orchestrator_checkpoints_and_session_resumption():
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id="sess_resume_test",
        assessment_name="Resumable Assessment",
        target="example.com",
    )

    # Execute first task
    tasks = orch.get_next_tasks()
    task1 = tasks[0]
    task1.status = TaskStatus.COMPLETED

    # Checkpoint state
    snapshot = orch.checkpoint()
    assert snapshot["session_id"] == "sess_resume_test"

    # Simulate process crash / new orchestrator instance restoring from checkpoint
    new_orch = AssessmentOrchestrator()
    new_orch.restore_checkpoint(snapshot)

    assert new_orch.plan is not None
    assert new_orch.plan.is_resumed is True
    restored_task1 = new_orch.plan.tasks[task1.task_id]
    assert restored_task1.status == TaskStatus.COMPLETED

    # Dependency resolution continues seamlessly from restored state
    next_resumed_tasks = new_orch.get_next_tasks()
    assert len(next_resumed_tasks) >= 1


@pytest.mark.asyncio
async def test_orchestrator_retry_logic():
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id="sess_retry_test",
        assessment_name="Retry Test",
        target="retry.local",
    )

    task = AssessmentTask(
        phase=AssessmentPhase.ENUMERATION,
        name="Flaky Tool Task",
        tool_name="flaky_tool",
        max_retries=2,
    )
    orch.plan.tasks[task.task_id] = task

    class MockFlakyGateway:
        def __init__(self):
            self.attempts = 0
        async def execute(self, *args, **kwargs):
            self.attempts += 1
            if self.attempts < 3:
                return ToolResult(call_id="c", tool_name="flaky_tool", output="Network glitch", is_error=True)
            return ToolResult(call_id="c", tool_name="flaky_tool", output="Success on attempt 3", is_error=False)

    flaky_gw = MockFlakyGateway()
    orch.gateway = flaky_gw

    # Attempt 1 -> Fails, queued for retry
    await orch.execute_task(task)
    assert task.status == TaskStatus.PENDING
    assert task.retry_count == 1

    # Attempt 2 -> Fails, queued for retry
    await orch.execute_task(task)
    assert task.status == TaskStatus.PENDING
    assert task.retry_count == 2

    # Attempt 3 -> Success!
    await orch.execute_task(task)
    assert task.status == TaskStatus.COMPLETED
    assert "Success on attempt 3" in task.result_summary


def test_coverage_tracking():
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id="sess_cov_test",
        assessment_name="Coverage Test",
        target="test.com",
    )
    plan = orch.plan
    assert plan.coverage.coverage_percentage == 0.0

    total = len(plan.tasks)
    # Mark half tasks completed
    half = total // 2
    for i, t in enumerate(plan.tasks.values()):
        if i < half:
            t.status = TaskStatus.COMPLETED

    orch._update_coverage()
    assert plan.coverage.coverage_percentage > 0.0


@pytest.mark.asyncio
async def test_durable_assessment_recovery_sqlite(tmp_path):
    """Test durable assessment recovery after simulating a full process restart."""
    from loki.assessment.db import DatabaseManager
    from loki.assessment.models import AssessmentSession
    from loki.security.scope_manager import ScopeConfig

    db_path = tmp_path / "durable_test.db"
    db = DatabaseManager(db_path=str(db_path))

    session_id = "sess_durable_recov_01"
    session = AssessmentSession(
        session_id=session_id,
        assessment_name="Durable Audit Session",
        scope=ScopeConfig(assessment_name="Durable Audit Session", targets=["durable.internal"]),
    )
    db.save_assessment(session)

    # Create orchestrator with database manager
    orch = AssessmentOrchestrator.create_standard_plan(
        session_id=session_id,
        assessment_name="Durable Audit",
        target="durable.internal",
        db_manager=db,
    )

    class MockToolGateway:
        async def execute(self, *args, **kwargs):
            return ToolResult(
                call_id="call_mock_durable",
                tool_name="dns_lookup",
                output="192.168.1.100 Host active",
                is_error=False,
                execution_time_ms=12.5,
            )

    orch.gateway = MockToolGateway()

    # Execute first task
    next_tasks = orch.get_next_tasks()
    t1 = next_tasks[0]
    await orch.execute_task(t1)

    assert t1.status == TaskStatus.COMPLETED
    assert len(t1.evidence_ids) >= 1
    real_evidence_id = t1.evidence_ids[0]

    # Verify evidence was actually indexed into the SQLite evidence table
    with db._get_connection() as conn:
        ev_row = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?", (real_evidence_id,)).fetchone()
        assert ev_row is not None
        assert ev_row["tool_name"] == "dns_lookup"
        assert "192.168.1.100" in ev_row["raw_output"]

    # Save checkpoint to SQLite
    orch.checkpoint()

    # -------------------------------------------------------------
    # SIMULATE PROCESS RESTART: Destroy in-memory object & reload from DB
    # -------------------------------------------------------------
    del orch

    restored_orch = AssessmentOrchestrator.load_from_db(
        session_id=session_id,
        db_manager=db,
    )

    assert restored_orch is not None
    assert restored_orch.plan is not None
    assert restored_orch.plan.is_resumed is True
    assert restored_orch.plan.session_id == session_id
    assert restored_orch.plan.tasks[t1.task_id].status == TaskStatus.COMPLETED
    assert restored_orch.plan.tasks[t1.task_id].evidence_ids[0] == real_evidence_id
