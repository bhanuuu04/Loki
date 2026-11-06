"""
Example 01: Simple Agent Execution
Demonstrates running LokiAgent with the built-in Mock provider (or Gemini / OpenAI).
"""

import asyncio
from loki import LokiAgent


async def main():
    # Create an agent using the deterministic Mock provider (no API key needed)
    # To use Gemini or OpenAI: LokiAgent(provider="gemini/gemini-2.5-flash") or "openai/gpt-4o-mini"
    agent = LokiAgent(provider="mock")

    prompt = "Can you calculate 25 * 4 using the calculator tool?"
    print(f"User Prompt: {prompt}\n")

    result = await agent.run(prompt)

    print(f"Run ID: {result.run_id}")
    print(f"Status: {result.status.value}")
    print(f"Total Steps: {len(result.steps)}")
    print(f"Total Tokens: {result.total_usage.total_tokens}")
    print(f"Total Latency: {result.total_latency_ms:.2f} ms\n")

    for step in result.steps:
        print(f"--- Step {step.step_number} ---")
        if step.thought:
            print(f"Thought: {step.thought}")
        for tc in step.tool_calls:
            print(f"Tool Call: {tc.name} with {tc.arguments}")
        for res in step.tool_results:
            print(f"Tool Output: {res.output}")

    print("\n--- Final Response ---")
    print(result.final_response)


if __name__ == "__main__":
    asyncio.run(main())
