"""
Structured Assessment Planning & Orchestration Engine for Loki 2.0.
Deterministic state machine managing phases, task dependency DAGs,
execution checkpoints, time budgets, retries, and coverage tracking.
Keeps deterministic execution state separate from LLM reasoning.
"""

from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import asyncio
import time
import uuid
from pydantic import BaseModel, Field

from loki.types import ToolCall, ToolResult
from loki.security.gateway import ExecutionGateway


class AssessmentPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    REPORTING = "reporting"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class AssessmentTask(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phase: AssessmentPhase
    name: str
    description: str = ""
    dependencies: List[str] = Field(default_factory=list)  # task_ids
    status: TaskStatus = TaskStatus.PENDING
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 2
    time_budget_seconds: float = 60.0
    evidence_ids: List[str] = Field(default_factory=list)
    result_summary: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    duration_ms: float = 0.0


class CoverageTracker(BaseModel):
    targets_total: int = 0
    targets_covered: List[str] = Field(default_factory=list)
    discovered_assets_count: int = 0
    ports_scanned_count: int = 0
    endpoints_tested_count: int = 0
    phases_completed: List[AssessmentPhase] = Field(default_factory=list)
    coverage_percentage: float = 0.0

    def recalculate(self, total_tasks: int, completed_tasks: int) -> float:
        if total_tasks > 0:
            self.coverage_percentage = round((completed_tasks / total_tasks) * 100.0, 1)
        else:
            self.coverage_percentage = 0.0
        return self.coverage_percentage


class AssessmentPlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    assessment_name: str
    target: str
    tasks: Dict[str, AssessmentTask] = Field(default_factory=dict)
    phase_order: List[AssessmentPhase] = [
        AssessmentPhase.RECONNAISSANCE,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.VULNERABILITY_ANALYSIS,
        AssessmentPhase.REPORTING,
    ]
    current_phase: AssessmentPhase = AssessmentPhase.RECONNAISSANCE
    overall_time_budget_seconds: float = 1800.0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    is_resumed: bool = False
    coverage: CoverageTracker = Field(default_factory=CoverageTracker)


class AssessmentOrchestrator:
    """
    Deterministic Assessment Planning Engine.
    Executes a structured task DAG with phase boundaries, dependency resolution,
    checkpoints, retries, time budgets, and evidence tracking.
    """

    def __init__(
        self,
        plan: Optional[AssessmentPlan] = None,
        gateway: Optional[ExecutionGateway] = None,
    ):
        self.plan = plan
        self.gateway = gateway or ExecutionGateway.get_default()
        self._checkpoints: List[Dict[str, Any]] = []

    @classmethod
    def create_standard_plan(
        cls,
        session_id: str,
        assessment_name: str,
        target: str,
        time_budget_seconds: float = 1800.0,
    ) -> "AssessmentOrchestrator":
        """Factory creating a standard assessment DAG across all 4 phases."""
        plan_id = str(uuid.uuid4())
        plan = AssessmentPlan(
            plan_id=plan_id,
            session_id=session_id,
            assessment_name=assessment_name,
            target=target,
            overall_time_budget_seconds=time_budget_seconds,
        )

        # 1. Recon Phase
        t1 = AssessmentTask(
            phase=AssessmentPhase.RECONNAISSANCE,
            name="DNS Lookup and IP Resolution",
            description=f"Resolve DNS and identify authoritative IP addresses for {target}",
            tool_name="dns_lookup",
            tool_args={"host": target},
            time_budget_seconds=30.0,
        )
        t2 = AssessmentTask(
            phase=AssessmentPhase.RECONNAISSANCE,
            name="Subdomain Enumeration",
            description=f"Passive and active subdomain discovery for {target}",
            tool_name="enumerate_subdomains",
            tool_args={"domain": target},
            dependencies=[t1.task_id],
            time_budget_seconds=60.0,
        )

        # 2. Enumeration Phase
        t3 = AssessmentTask(
            phase=AssessmentPhase.ENUMERATION,
            name="HTTP Security Header Audit",
            description=f"Audit security headers and server banner on http://{target}",
            tool_name="audit_http_security_headers",
            tool_args={"url": f"http://{target}"},
            dependencies=[t1.task_id],
            time_budget_seconds=45.0,
        )

        # 3. Vulnerability Analysis Phase
        t4 = AssessmentTask(
            phase=AssessmentPhase.VULNERABILITY_ANALYSIS,
            name="Knowledge Base Correlation",
            description="Lookup CWE and OWASP prevention patterns for identified attack surface",
            tool_name="lookup_owasp_guidelines",
            tool_args={"category": "A05"},
            dependencies=[t3.task_id],
            time_budget_seconds=30.0,
        )

        # 4. Reporting Phase
        t5 = AssessmentTask(
            phase=AssessmentPhase.REPORTING,
            name="Assessment Report Generation",
            description=f"Generate multi-format assessment report for session {session_id}",
            tool_name="generate_assessment_report",
            tool_args={"session_id": session_id},
            dependencies=[t4.task_id],
            time_budget_seconds=30.0,
        )

        for t in (t1, t2, t3, t4, t5):
            plan.tasks[t.task_id] = t

        plan.coverage.targets_total = 1
        return cls(plan=plan)

    def get_next_tasks(self) -> List[AssessmentTask]:
        """Returns all executable tasks whose dependencies are satisfied and are PENDING."""
        if not self.plan:
            return []

        executable: List[AssessmentTask] = []
        for task in self.plan.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue

            # Check if all dependencies are COMPLETED
            deps_satisfied = True
            for dep_id in task.dependencies:
                dep_task = self.plan.tasks.get(dep_id)
                if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                    deps_satisfied = False
                    break

            if deps_satisfied:
                executable.append(task)

        return executable

    def is_assessment_complete(self) -> bool:
        """Check if all tasks are in a terminal state (COMPLETED, FAILED, SKIPPED)."""
        if not self.plan:
            return True
        return all(
            t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED)
            for t in self.plan.tasks.values()
        )

    def checkpoint(self) -> Dict[str, Any]:
        """Create a point-in-time snapshot of the assessment state."""
        if not self.plan:
            return {}
        data = self.plan.model_dump()
        self._checkpoints.append(data)
        return data

    def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> None:
        """Restore plan state from checkpoint snapshot."""
        self.plan = AssessmentPlan(**checkpoint_data)
        self.plan.is_resumed = True

    async def execute_task(
        self,
        task: AssessmentTask,
        tool_resolver: Optional[Callable[[str], Any]] = None,
    ) -> AssessmentTask:
        """
        Execute an assessment task deterministically with timeout, retries,
        gateway validation, and checkpointing.
        """
        if not self.plan:
            raise ValueError("No assessment plan loaded.")

        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        start_mono = time.perf_counter()

        # Check overall assessment time budget
        if self.plan.start_time:
            elapsed = time.time() - self.plan.start_time
            if elapsed > self.plan.overall_time_budget_seconds:
                task.status = TaskStatus.BLOCKED
                task.error_message = f"Assessment exceeded overall time budget of {self.plan.overall_time_budget_seconds}s."
                return task

        # Check if task has a tool to run
        if not task.tool_name:
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            return task

        tool_inst = tool_resolver(task.tool_name) if tool_resolver else None

        # Execute via ExecutionGateway
        call_id = f"task_{task.task_id[:8]}"
        tool_call = ToolCall(id=call_id, name=task.tool_name, arguments=task.tool_args)

        try:
            # Enforce task time budget via asyncio.wait_for
            res: ToolResult = await asyncio.wait_for(
                self.gateway.execute(tool_call, tool_inst),
                timeout=task.time_budget_seconds,
            )

            if res.is_error:
                # Retry logic
                if task.retry_count < task.max_retries:
                    task.retry_count += 1
                    task.status = TaskStatus.PENDING  # Queue for retry
                    task.error_message = f"Attempt {task.retry_count} failed: {res.output}. Retrying..."
                else:
                    task.status = TaskStatus.FAILED
                    task.error_message = f"Max retries ({task.max_retries}) exceeded: {res.output}"
            else:
                task.status = TaskStatus.COMPLETED
                task.result_summary = str(res.output)[:500]
                task.evidence_ids.append(call_id)

        except asyncio.TimeoutError:
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.PENDING
                task.error_message = f"Task timed out after {task.time_budget_seconds}s. Retrying..."
            else:
                task.status = TaskStatus.FAILED
                task.error_message = f"Task timed out after {task.time_budget_seconds}s and reached max retries."
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error_message = f"Execution exception: {type(e).__name__}: {str(e)}"

        task.completed_at = time.time()
        task.duration_ms = (time.perf_counter() - start_mono) * 1000

        # Update coverage
        self._update_coverage()
        # Save checkpoint after each task execution
        self.checkpoint()

        return task

    def _update_coverage(self) -> None:
        if not self.plan:
            return
        total = len(self.plan.tasks)
        completed = sum(1 for t in self.plan.tasks.values() if t.status == TaskStatus.COMPLETED)
        self.plan.coverage.recalculate(total, completed)

        # Check phase completion
        for phase in self.plan.phase_order:
            phase_tasks = [t for t in self.plan.tasks.values() if t.phase == phase]
            if phase_tasks and all(t.status == TaskStatus.COMPLETED for t in phase_tasks):
                if phase not in self.plan.coverage.phases_completed:
                    self.plan.coverage.phases_completed.append(phase)
