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
from rich.table import Table
from rich import box

from loki import __version__
from loki.config import settings
from loki.runtime.agent import LokiAgent
from loki.eval.dataset import BenchmarkSuite
from loki.eval.runner import EvalRunner
from loki.types import AgentEvent, EventType, RunResult
from loki.cli.doctor import LokiDoctor
from loki.cli.setup import run_setup_wizard
from loki.cli.interface import LokiConversationalCLI
from loki.providers.factory import get_provider
from loki.providers.compatibility import ModelCompatibilityTester

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


async def _test_model(provider_str: str):
    console.print(f"[bold cyan]Running Model Compatibility Suite for:[/bold cyan] {provider_str}")
    provider = get_provider(provider_str)
    tester = ModelCompatibilityTester(provider)
    report = await tester.run_suite()

    table = Table(title=f"Compatibility: {report.overall_status} ({report.model_id})", box=box.ASCII_DOUBLE_HEAD)
    table.add_column("Capability / Probe", width=35)
    table.add_column("Status", width=12)
    table.add_column("Latency (ms)", justify="right", width=14)
    table.add_column("Details")

    for t in report.tests:
        status_styled = "[bold green]PASS[/bold green]" if t.passed else ("[bold red]FAIL[/bold red]" if t.critical else "[bold yellow]UNSUPPORTED[/bold yellow]")
        table.add_row(t.name, status_styled, str(t.latency_ms), t.details)

    console.print(table)
    console.print(f"\n[bold]Overall Status:[/bold] {report.overall_status}\n")


async def _list_models(provider_str: str):
    provider = get_provider(provider_str)
    if hasattr(provider, "list_models"):
        models = await provider.list_models()
        console.print(f"\n[bold cyan]Available Models from {provider_str}:[/bold cyan]")
        for m in models:
            m_id = m.get("id") or m.get("name") or str(m)
            console.print(f" • [green]{m_id}[/green]")
        console.print("")
    else:
        console.print(f"Model listing not directly supported by {type(provider).__name__}. Active model: {provider.model}")


def cli_entrypoint():
    parser = argparse.ArgumentParser(description=f"Loki: Full-Stack Agent Harness Platform (v{__version__})")
    parser.add_argument("-v", "--version", action="version", version=f"Loki {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: setup
    subparsers.add_parser("setup", help="Run interactive first-time setup wizard")

    # Command: doctor
    subparsers.add_parser("doctor", help="Run complete system health and platform diagnostics")

    # Command: version
    subparsers.add_parser("version", help="Show Loki version")

    # Command: config
    subparsers.add_parser("config", help="Inspect current configuration and active provider settings")

    # Command: start (alias for serve)
    start_parser = subparsers.add_parser("start", help="Start the Loki API and Web UI dashboard")
    start_parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    start_parser.add_argument("--port", type=int, default=8000, help="Port to bind")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Launch FastAPI server and Web UI")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run agent on a single prompt")
    run_parser.add_argument("prompt", type=str, help="User prompt to execute")
    run_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider (e.g. nvidia, mock, gemini, openai)")
    run_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    # Command: chat
    chat_parser = subparsers.add_parser("chat", help="Start an interactive chat session")
    chat_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider")
    chat_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    # Command: eval
    eval_parser = subparsers.add_parser("eval", help="Run benchmark evaluation suites")
    eval_parser.add_argument("suite", type=str, help="Path to benchmark JSON file")
    eval_parser.add_argument("--provider", "-p", default="mock", help="LLM Provider")

    # Command: models
    models_parser = subparsers.add_parser("models", help="Model discovery and compatibility testing")
    models_subparsers = models_parser.add_subparsers(dest="models_command", help="Model subcommands")
    
    m_list_parser = models_subparsers.add_parser("list", help="List available models")
    m_list_parser.add_argument("--provider", "-p", default="nvidia", help="Provider to query")

    m_test_parser = models_subparsers.add_parser("test", help="Test model compatibility & capabilities")
    m_test_parser.add_argument("--provider", "-p", default="mock", help="Provider/model to probe (e.g. nvidia, mock, openai)")

    # Command: tools
    subparsers.add_parser("tools", help="List all registered tools")

    args = parser.parse_args()

    if args.command == "setup":
        asyncio.run(run_setup_wizard())

    elif args.command == "doctor":
        items = asyncio.run(LokiDoctor.run_diagnostics())
        LokiDoctor.display_report(items)

    elif args.command == "version":
        console.print(f"[bold cyan]Loki[/bold cyan] version [bold green]{__version__}[/bold green]")

    elif args.command == "config":
        console.print("\n[bold cyan]─── LOKI ACTIVE CONFIGURATION ───[/bold cyan]")
        cfg = settings.model_dump()
        for k, v in cfg.items():
            if "api_key" in k and v:
                v = f"********{v[-4:]}" if len(str(v)) > 4 else "********"
            console.print(f" [bold]{k}:[/bold] {v}")
        console.print("")

    elif args.command in ("start", "serve"):
        console.print(f"[bold green]Starting Loki Platform at http://{args.host}:{args.port}[/bold green]")
        uvicorn.run("loki.server.app:app", host=args.host, port=args.port, reload=False)

    elif args.command == "run":
        asyncio.run(_run_prompt(args.prompt, args.provider, args.max_steps))

    elif args.command == "chat":
        cli = LokiConversationalCLI(provider=args.provider, max_steps=args.max_steps)
        asyncio.run(cli.start())

    elif args.command == "eval":
        asyncio.run(_run_eval(args.suite, args.provider))

    elif args.command == "models":
        if args.models_command == "list":
            asyncio.run(_list_models(args.provider))
        elif args.models_command == "test":
            asyncio.run(_test_model(args.provider))
        else:
            models_parser.print_help()

    elif args.command == "tools":
        agent = LokiAgent()
        console.print(f"\n[bold cyan]Registered Tools ({len(agent.registry.list_tools())}):[/bold cyan]")
        for t in agent.registry.list_tools():
            console.print(f" • [bold green]{t.name}[/bold green]: {t.description}")
        console.print("")

    else:
        # Default behavior when running `loki` without arguments:
        # Check if first-run setup is recommended
        env_file = Path.cwd() / ".env"
        if not env_file.exists():
            console.print(
                Panel(
                    "[bold green]Welcome to Loki![/bold green] It looks like this is your first time running.\n"
                    "Let's configure your AI provider (NVIDIA NIM, Gemini, OpenAI, or offline Mock).",
                    title="[bold cyan]First-Run Welcome[/bold cyan]",
                    border_style="cyan",
                )
            )
            from rich.prompt import Confirm
            try:
                run_wizard = Confirm.ask("Would you like to run the setup wizard now?", default=True)
                if run_wizard:
                    asyncio.run(run_setup_wizard())
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Skipping setup wizard.[/dim]")

        # Launch Conversational Interface
        cli = LokiConversationalCLI()
        asyncio.run(cli.start())


if __name__ == "__main__":
    cli_entrypoint()
