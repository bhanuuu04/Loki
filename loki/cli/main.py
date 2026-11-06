"""
Loki Command-Line Interface (CLI).
"""

import argparse
import asyncio
import sys
import os
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from loki.runtime.agent import LokiAgent
from loki.eval.dataset import BenchmarkSuite
from loki.eval.runner import EvalRunner
from loki.types import AgentEvent, EventType, RunResult

# Ensure stdout/stderr handles UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True)


def _render_event(evt: AgentEvent):
    """Pretty prints execution events in the terminal in real-time."""
    if evt.event_type == EventType.STEP_START:
        step_num = evt.data.get("step_number")
        console.print(f"\n[bold yellow]--- Step {step_num} ---[/bold yellow]")

    elif evt.event_type == EventType.THOUGHT:
        thought = evt.data.get("thought", "")
        console.print(Panel(thought, title="[magenta]Agent Thought / Response[/magenta]", border_style="magenta"))

    elif evt.event_type == EventType.TOOL_CALL_START:
        tname = evt.data.get("tool_name")
        args = evt.data.get("arguments")
        console.print(f"[cyan]>> Invoking Tool:[/cyan] [bold]{tname}[/bold] with args: {args}")

    elif evt.event_type == EventType.TOOL_CALL_END:
        tname = evt.data.get("tool_name")
        out = evt.data.get("output")
        time_ms = evt.data.get("execution_time_ms", 0)
        console.print(f"[green]+ Tool Result ({tname}) [{time_ms:.1f}ms]:[/green] {out}")

    elif evt.event_type == EventType.ERROR:
        err = evt.data.get("error")
        console.print(f"[bold red]! Error:[/bold red] {err}")


async def _run_prompt(prompt: str, provider: str, max_steps: int):
    console.print(f"[bold cyan]Loki Harness Starting[/bold cyan] (Model/Provider: [green]{provider}[/green])")
    agent = LokiAgent(provider=provider, max_steps=max_steps)
    agent.add_listener(_render_event)

    result = await agent.run(prompt=prompt)
    console.print("\n" + "=" * 50)
    console.print(Panel(result.final_response, title="[bold green]Final Answer[/bold green]", border_style="green"))
    console.print(
        f"[dim]Status: {result.status.value} | Total Steps: {len(result.steps)} | Tokens: {result.total_usage.total_tokens} | Time: {result.total_latency_ms:.1f}ms[/dim]\n"
    )


async def _chat_loop(provider: str, max_steps: int):
    console.print("[bold cyan]Loki Interactive REPL[/bold cyan] (Type 'exit' or 'quit' to end)")
    agent = LokiAgent(provider=provider, max_steps=max_steps)
    agent.add_listener(_render_event)

    session_id = "repl_session"

    while True:
        try:
            user_input = console.input("\n[bold blue]user>[/bold blue] ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                console.print("[dim]Goodbye![/dim]")
                break

            await agent.run(prompt=user_input, session_id=session_id)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session terminated.[/dim]")
            break


async def _run_eval(suite_path: str, provider: str):
    agent = LokiAgent(provider=provider)
    suite = BenchmarkSuite.from_json(suite_path)
    runner = EvalRunner(agent=agent)
    console.print(f"[bold]Executing benchmark suite:[/bold] {suite.name} ({len(suite.cases)} cases)...")
    summary = await runner.run_suite(suite)
    runner.print_summary(summary)


def cli_entrypoint():
    parser = argparse.ArgumentParser(description="Loki: Full-Stack Agent Harness Platform")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run agent on a single prompt")
    run_parser.add_argument("prompt", type=str, help="User prompt to execute")
    run_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider/model (e.g., mock, gemini/gemini-2.5-flash, openai/gpt-4o-mini)")
    run_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    # Command: chat
    chat_parser = subparsers.add_parser("chat", help="Start an interactive chat session")
    chat_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider/model")
    chat_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    # Command: eval
    eval_parser = subparsers.add_parser("eval", help="Run benchmark evaluation suites")
    eval_parser.add_argument("suite", type=str, help="Path to benchmark JSON file")
    eval_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider/model")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Launch FastAPI server and Web UI")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind")

    # Command: tools
    tools_parser = subparsers.add_parser("tools", help="List registered tools")

    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(_run_prompt(args.prompt, args.provider, args.max_steps))
    elif args.command == "chat":
        asyncio.run(_chat_loop(args.provider, args.max_steps))
    elif args.command == "eval":
        asyncio.run(_run_eval(args.suite, args.provider))
    elif args.command == "serve":
        console.print(f"[bold green]Starting Loki Platform at http://{args.host}:{args.port}[/bold green]")
        uvicorn.run("loki.server.app:app", host=args.host, port=args.port, reload=False)
    elif args.command == "tools":
        agent = LokiAgent()
        for t in agent.registry.list_tools():
            console.print(f"[bold cyan]{t.name}[/bold cyan] - {t.description}")
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_entrypoint()
