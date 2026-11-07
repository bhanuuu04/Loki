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
