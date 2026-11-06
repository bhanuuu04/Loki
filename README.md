# Loki: Full-Stack Agent Harness Platform

**Loki** is a modern, lightweight, full-stack AI agent execution runtime and evaluation harness built with Python, FastAPI, and Pydantic. It provides multi-provider LLM support (Gemini, OpenAI, Anthropic, Ollama, and offline Mocks), an event-driven tool engine, an evaluation and benchmarking harness, an interactive CLI, and a real-time Web UI.

---

## Architecture Overview

```
+─────────────────────────────────────────────────────────────+
|                         LOKI PLATFORM                       |
+─────────────────────────────────────────────────────────────+
|                                                             |
|  [ Web UI / SSE ] ─── [ REST API (FastAPI) ] ─── [ CLI ]    |
|                             │                               |
|                             ▼                               |
|                 [ LokiAgent Runtime Loop ]                  |
|               (ReAct / Thought-Action Cycle)                |
|                             │                               |
|        ┌────────────────────┴────────────────────┐          |
|        ▼                                         ▼          |
| [ Multi-Provider Layer ]                [ Tool Registry ]   |
|   - Google Gemini REST                   - Calculator       |
|   - OpenAI / Compatible                  - Python REPL      |
|   - Anthropic Claude                     - Shell / Exec     |
|   - Ollama (Local)                       - Filesystem       |
|   - Deterministic Mock                   - HTTP Get         |
|                                          - Custom @tool     |
|                                                             |
| ─────────────────────────────────────────────────────────── |
|                 [ Evaluation & Benchmark Suite ]            |
|       - Dataset Loaders (JSON / Suite definitions)          |
|       - Graders: ExactMatch, Contains, Regex, CodeAssert    |
|       - Scorecard: Accuracy, Latency, Token telemetry       |
+─────────────────────────────────────────────────────────────+
```

---

## Features

- **Autonomous Agent Loop**: Step-by-step ReAct orchestration with step budgeting, event callbacks, and error sandboxing.
- **Multi-Provider LLM Abstraction**: Unified interface with native REST integrations for:
  - **Google Gemini** (`gemini/gemini-2.5-flash`, `gemini-1.5-pro`)
  - **OpenAI & OpenAI-compatible** (`openai/gpt-4o`, `openai/gpt-4o-mini`, DeepSeek, vLLM)
  - **Anthropic Claude** (`anthropic/claude-3-5-sonnet`)
  - **Local Ollama** (`ollama/llama3.1`)
  - **Deterministic Mock Provider** (zero-API-key testing and offline evals)
- **Typed Tool Engine**:
  - Convert any Python function into an agent tool using `@tool` decorator.
  - Automatic JSON Schema generation from type hints and docstrings.
  - Built-in sandboxed tools: `calculator`, `python_exec`, `run_command`, `read_file`, `write_file`, `list_dir`, `http_get`.
- **Benchmark Evaluation Harness (`loki.eval`)**:
  - Run agents against structured test suites.
  - Rule-based and assertion graders with latency and token telemetry.
  - Rich terminal scorecards and JSON export.
- **FastAPI Server & Web UI**:
  - SSE real-time streaming of agent thoughts and tool executions.
  - Clean dashboard for running agent queries, inspecting registered tools, and triggering benchmark runs.
- **Interactive CLI**:
  - `loki run <prompt>` - Run a single query with visual step progression.
  - `loki chat` - Interactive terminal REPL.
  - `loki eval <suite.json>` - Run benchmark evaluation suites.
  - `loki serve` - Launch Web UI & API.

---

## Quick Start

### 1. Installation

```bash
# Clone and enter workspace
git clone <repo-url> Loki
cd Loki

# Install in editable mode
pip install -e .
```

### 2. Run with Built-in Mock (No API key needed)

```bash
python -m loki.cli.main run "Calculate 25 * 4 using the calculator tool"
```

### 3. Start Interactive Chat REPL

```bash
python -m loki.cli.main chat --provider mock
```

### 4. Run Benchmark Evaluation Suite

```bash
python -m loki.cli.main eval benchmarks/sample_suite.json
```

### 5. Launch the Web UI

```bash
python -m loki.cli.main serve --port 8000
```
Open **http://127.0.0.1:8000** in your browser.

---

## Python SDK Usage

### Running an Agent

```python
import asyncio
from loki import LokiAgent

async def main():
    # Uses mock by default, or set provider="gemini/gemini-2.5-flash"
    agent = LokiAgent(provider="mock")
    result = await agent.run("Calculate (150 * 4) + (250 / 5)")
    
    print("Answer:", result.final_response)
    print("Steps taken:", len(result.steps))
    print("Tokens consumed:", result.total_usage.total_tokens)

asyncio.run(main())
```

### Creating Custom Tools

```python
from loki import LokiAgent, tool

@tool(name="crypto_price", description="Get simulated live cryptocurrency price in USD.")
def get_crypto_price(symbol: str) -> str:
    prices = {"BTC": "$91,240.00", "ETH": "$3,450.00", "SOL": "$210.00"}
    return prices.get(symbol.upper(), "Unknown ticker")

agent = LokiAgent(provider="mock", tools=[get_crypto_price])
```

### Running Benchmark Evals in Code

```python
import asyncio
from loki import LokiAgent
from loki.eval import BenchmarkSuite, EvalRunner

async def evaluate():
    agent = LokiAgent(provider="mock")
    suite = BenchmarkSuite.from_json("benchmarks/sample_suite.json")
    
    runner = EvalRunner(agent=agent)
    summary = await runner.run_suite(suite)
    runner.print_summary(summary)

asyncio.run(evaluate())
```

---

## Running Unit Tests

```bash
pytest -v
```
