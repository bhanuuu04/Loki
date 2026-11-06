"""
Evaluation Runner for benchmarking Loki agents.
"""

from typing import Any, Dict, List, Optional
import asyncio
import time
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table
from rich import box
import sys

# Ensure stdout/stderr handles UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from loki.eval.dataset import BenchmarkSuite
from loki.eval.graders import (
    BaseGrader,
    CodeAssertGrader,
    ContainsGrader,
    ExactMatchGrader,
    RegexGrader,
)
from loki.runtime.agent import LokiAgent
from loki.types import EvalCase, EvalResult, GraderType, RunResult


class BenchmarkSummary(BaseModel):
    suite_name: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    pass_rate: float
    total_duration_ms: float
    avg_latency_per_case_ms: float
    total_tokens: int
    results: List[EvalResult] = Field(default_factory=list)


class EvalRunner:
    """Orchestrates benchmark runs and generates comprehensive scorecards."""

    def __init__(self, agent: LokiAgent):
        self.agent = agent
        self.graders: Dict[GraderType, BaseGrader] = {
            GraderType.EXACT_MATCH: ExactMatchGrader(),
            GraderType.CONTAINS: ContainsGrader(),
            GraderType.REGEX: RegexGrader(),
            GraderType.CODE_ASSERT: CodeAssertGrader(),
        }

    async def run_case(self, case: EvalCase) -> EvalResult:
        """Run a single benchmark case through the agent and grade it."""
        start_time = time.perf_counter()
        
        # Execute agent
        run_res: RunResult = await self.agent.run(prompt=case.prompt)
        duration_ms = (time.perf_counter() - start_time) * 1000

        # Select grader
        grader = self.graders.get(case.grader_type, ContainsGrader())
        passed, score, reason = await grader.grade(case, run_res)

        return EvalResult(
            case_id=case.id,
            passed=passed,
            score=score,
            reason=reason,
            run_result=run_res,
            duration_ms=duration_ms,
        )

    async def run_suite(
        self, suite: BenchmarkSuite, concurrency: int = 1
    ) -> BenchmarkSummary:
        """Run all test cases in the benchmark suite."""
        start_time = time.perf_counter()
        results: List[EvalResult] = []

        if concurrency > 1:
            semaphore = asyncio.Semaphore(concurrency)

            async def _bounded_run(c: EvalCase):
                async with semaphore:
                    return await self.run_case(c)

            results = await asyncio.gather(*[_bounded_run(c) for c in suite.cases])
        else:
            for case in suite.cases:
                res = await self.run_case(case)
                results.append(res)

        total_duration = (time.perf_counter() - start_time) * 1000
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        pass_rate = (passed / len(results) * 100) if results else 0.0
        total_tokens = sum(r.run_result.total_usage.total_tokens for r in results)
        avg_latency = total_duration / len(results) if results else 0.0

        return BenchmarkSummary(
            suite_name=suite.name,
            total_cases=len(results),
            passed_cases=passed,
            failed_cases=failed,
            pass_rate=round(pass_rate, 2),
            total_duration_ms=round(total_duration, 2),
            avg_latency_per_case_ms=round(avg_latency, 2),
            total_tokens=total_tokens,
            results=results,
        )

    def print_summary(self, summary: BenchmarkSummary) -> None:
        """Display rich terminal scorecard."""
        console = Console(force_terminal=True)

        console.print(
            f"\n[bold cyan]Loki Benchmark Results: {summary.suite_name}[/bold cyan]"
        )

        table = Table(
            title=f"Accuracy: {summary.pass_rate}% ({summary.passed_cases}/{summary.total_cases} Passed)",
            box=box.ASCII_DOUBLE_HEAD,
        )
        table.add_column("Case ID", style="dim", width=18)
        table.add_column("Status", width=10)
        table.add_column("Score", justify="right", width=8)
        table.add_column("Steps", justify="right", width=6)
        table.add_column("Tokens", justify="right", width=8)
        table.add_column("Time (ms)", justify="right", width=10)
        table.add_column("Reason", style="italic")

        for r in summary.results:
            status_text = "[green]PASSED[/green]" if r.passed else "[red]FAILED[/red]"
            table.add_row(
                r.case_id,
                status_text,
                f"{r.score:.2f}",
                str(len(r.run_result.steps)),
                str(r.run_result.total_usage.total_tokens),
                f"{r.duration_ms:.1f}",
                r.reason[:60] + ("..." if len(r.reason) > 60 else ""),
            )

        console.print(table)
        console.print(
            f"[bold]Total Tokens:[/bold] {summary.total_tokens} | [bold]Total Time:[/bold] {summary.total_duration_ms:.1f}ms | [bold]Avg Latency:[/bold] {summary.avg_latency_per_case_ms:.1f}ms\n"
        )
