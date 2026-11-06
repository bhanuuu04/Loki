import pytest
from loki.eval.dataset import BenchmarkSuite
from loki.eval.runner import EvalRunner
from loki.runtime.agent import LokiAgent
from loki.types import EvalCase, GraderType


@pytest.mark.asyncio
async def test_eval_suite_execution():
    agent = LokiAgent(provider="mock")
    suite = BenchmarkSuite(
        name="Test Suite",
        cases=[
            EvalCase(
                id="test_calc",
                name="Math Calculation",
                prompt="calculate 25 * 4",
                expected_output="100",
                grader_type=GraderType.CONTAINS,
            )
        ],
    )

    runner = EvalRunner(agent=agent)
    summary = await runner.run_suite(suite)

    assert summary.total_cases == 1
    assert summary.passed_cases == 1
    assert summary.pass_rate == 100.0
    assert summary.results[0].passed
