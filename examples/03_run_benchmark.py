"""
Example 03: Running Benchmark Evaluation Suite
Demonstrates the EvalRunner scoring an agent against test cases.
"""

import asyncio
from pathlib import Path
from loki import LokiAgent
from loki.eval import BenchmarkSuite, EvalRunner


async def main():
    agent = LokiAgent(provider="mock")
    suite_path = Path(__file__).parent.parent / "benchmarks" / "sample_suite.json"

    suite = BenchmarkSuite.from_json(str(suite_path))
    runner = EvalRunner(agent=agent)

    print(f"Starting Benchmark: {suite.name}")
    summary = await runner.run_suite(suite)

    # Render terminal scorecard
    runner.print_summary(summary)


if __name__ == "__main__":
    asyncio.run(main())
