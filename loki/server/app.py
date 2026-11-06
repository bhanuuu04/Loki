"""
FastAPI application for Loki Agent Harness.
"""

from typing import Any, Dict, Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json
import asyncio

from loki.runtime.agent import LokiAgent
from loki.eval.dataset import BenchmarkSuite
from loki.eval.runner import EvalRunner
from loki.types import EvalCase, GraderType

app = FastAPI(title="Loki Agent Harness API", version="0.1.0")

STATIC_DIR = Path(__file__).parent / "static"


class AgentRunRequest(BaseModel):
    prompt: str
    model: Optional[str] = "mock"
    session_id: Optional[str] = None
    temperature: Optional[float] = 0.2
    max_steps: Optional[int] = 10


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Web UI index.html not found.")
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/tools")
async def list_tools():
    # Instantiate agent to inspect registry
    agent = LokiAgent(provider="mock")
    tools = []
    for t in agent.registry.list_tools():
        tools.append({
            "name": t.name,
            "description": t.description,
            "parameters_schema": t.parameters_schema,
        })
    return tools


@app.post("/api/agent/run")
async def run_agent(req: AgentRunRequest):
    agent = LokiAgent(
        provider=req.model or "mock",
        temperature=req.temperature or 0.2,
        max_steps=req.max_steps or 10,
    )
    result = await agent.run(prompt=req.prompt, session_id=req.session_id)
    return result.model_dump()


@app.get("/api/agent/stream")
async def stream_agent(prompt: str, model: str = "mock"):
    agent = LokiAgent(provider=model)

    async def event_generator():
        async for evt in agent.stream_events(prompt=prompt):
            data = json.dumps(evt.model_dump())
            yield f"event: {evt.event_type.value}\ndata: {data}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/eval/run")
async def run_eval():
    agent = LokiAgent(provider="mock")
    # Sample benchmark suite covering core agent capabilities
    suite = BenchmarkSuite(
        name="Loki Built-in Verification Suite",
        description="Core arithmetic, reasoning, and tool accuracy checks.",
        cases=[
            EvalCase(
                id="math_basic",
                name="Basic Arithmetic",
                prompt="Calculate (150 * 4) + (250 / 5) using the calculator tool",
                expected_output="650",
                grader_type=GraderType.CONTAINS,
            ),
            EvalCase(
                id="file_inspect",
                name="File Operation",
                prompt="Read the sample.txt file and tell me what is inside",
                expected_output="completed successfully",
                grader_type=GraderType.CONTAINS,
            ),
            EvalCase(
                id="python_exec",
                name="Python Execution",
                prompt="Execute python code to calculate the sum of numbers from 1 to 10",
                expected_output="completed successfully",
                grader_type=GraderType.CONTAINS,
            ),
            EvalCase(
                id="general_query",
                name="General Reasoning",
                prompt="Say hello and describe your operational state",
                expected_output="operational",
                grader_type=GraderType.CONTAINS,
            ),
        ],
    )

    runner = EvalRunner(agent=agent)
    summary = await runner.run_suite(suite)
    return summary.model_dump()
