"""
Loki Command-Line Interface (CLI).
Direct, streamlined, and robust CLI entry point for the Loki platform.
"""

from typing import Optional
import argparse
import asyncio
import sys
import os
from pathlib import Path
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
from loki.cli.model_cmd import run_model_command
from loki.security_bootstrap import ensure_security_secrets
from loki.providers.factory import get_provider
from loki.providers.compatibility import ModelCompatibilityTester

# Ensure cross-platform UTF-8 terminal I/O on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True)


def _render_event(evt: AgentEvent) -> None:
    """Pretty prints execution events in the terminal in real-time."""
    if evt.event_type == EventType.STEP_START:
        step_num = evt.data.get("step_number")
        console.print(f"\n[bold yellow]--- Step {step_num} ---[/bold yellow]")

    elif evt.event_type == EventType.THOUGHT:
        thought = evt.data.get("thought", "")
        if thought:
            console.print(Panel(thought, title="[magenta]Agent Thought[/magenta]", border_style="magenta"))

    elif evt.event_type == EventType.TOOL_CALL_START:
        tname = evt.data.get("tool_name")
        args = evt.data.get("arguments")
        console.print(f"[cyan]>> Tool Invoke:[/cyan] [bold]{tname}[/bold] {args}")

    elif evt.event_type == EventType.TOOL_CALL_END:
        tname = evt.data.get("tool_name")
        out = evt.data.get("output")
        time_ms = evt.data.get("execution_time_ms", 0)
        console.print(f"[green]+ Result ({tname}) [{time_ms:.1f}ms]:[/green] {out}")

    elif evt.event_type == EventType.ERROR:
        err = evt.data.get("error")
        console.print(f"[bold red]! Error:[/bold red] {err}")


async def _run_prompt(prompt: str, provider: str, max_steps: int) -> None:
    console.print(f"[bold cyan]Loki Harness Starting[/bold cyan] (Provider: [green]{provider}[/green])")
    agent = LokiAgent(provider=provider, max_steps=max_steps)
    agent.add_listener(_render_event)

    result = await agent.run(prompt=prompt)
    console.print("\n" + "=" * 50)
    console.print(Panel(result.final_response, title="[bold green]Final Answer[/bold green]", border_style="green"))
    console.print(
        f"[dim]Status: {result.status.value} | Steps: {len(result.steps)} | Tokens: {result.total_usage.total_tokens} | Latency: {result.total_latency_ms:.1f}ms[/dim]\n"
    )


async def _run_eval(suite_path: str, provider: str) -> None:
    agent = LokiAgent(provider=provider)
    suite = BenchmarkSuite.from_json(suite_path)
    runner = EvalRunner(agent=agent)
    console.print(f"[bold]Executing benchmark suite:[/bold] {suite.name} ({len(suite.cases)} cases)...")
    summary = await runner.run_suite(suite)
    runner.print_summary(summary)


async def _test_model(provider_str: str) -> None:
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


async def _list_models(provider_str: str) -> None:
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


def cli_entrypoint() -> None:
    parser = argparse.ArgumentParser(
        prog="loki",
        description=f"Loki: Autonomous AI Cybersecurity & Systems Research Agent (v{__version__})",
    )
    parser.add_argument("-v", "--version", action="version", version=f"Loki {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run (execute single prompt)
    run_parser = subparsers.add_parser("run", help="Run agent on a single prompt and exit")
    run_parser.add_argument("prompt", type=str, help="Prompt or task instructions")
    run_parser.add_argument("--provider", "-p", default=settings.default_provider, help="LLM Provider")
    run_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    # Command: model (interactive arrow-key switcher or --list / --test)
    model_parser = subparsers.add_parser("model", aliases=["models"], help="Select or inspect AI model")
    model_parser.add_argument("model_id", nargs="?", default=None, help="Optional model identifier to set directly")
    model_parser.add_argument("--list", "-l", action="store_true", help="List available models")
    model_parser.add_argument("--test", "-t", action="store_true", help="Test model compatibility & tool calling")
    model_parser.add_argument("--provider", "-p", default=settings.default_provider, help="Provider to query")

    # Command: setup (interactive setup wizard, onboard alias)
    setup_parser = subparsers.add_parser("setup", aliases=["onboard"], help="Interactive setup & configuration wizard")
    setup_parser.add_argument("--reset", action="store_true", help="Reset configuration and re-configure")

    # Command: doctor (diagnostics)
    subparsers.add_parser("doctor", help="Run platform diagnostics and system health check")

    # Command: serve (starts web dashboard / API server, start alias)
    serve_parser = subparsers.add_parser("serve", aliases=["start"], help="Start the Loki API and Web UI dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind")

    # Command: tools (list tools)
    subparsers.add_parser("tools", help="List all registered tools in catalog")

    # Command: eval (benchmarks)
    eval_parser = subparsers.add_parser("eval", help="Run benchmark evaluation suites")
    eval_parser.add_argument("suite", type=str, help="Path to benchmark JSON file")
    eval_parser.add_argument("--provider", "-p", default=settings.default_provider, help="LLM Provider")

    # Command: config (view config)
    subparsers.add_parser("config", help="Inspect current configuration and active provider settings")

    # Command: chat (alias for interactive conversation)
    chat_parser = subparsers.add_parser("chat", help="Start interactive conversational session")
    chat_parser.add_argument("--provider", "-p", default=settings.default_provider, help="LLM Provider")
    chat_parser.add_argument("--max-steps", "-m", type=int, default=10, help="Maximum step cycles")

    args = parser.parse_args()

    # Generate/load operator credentials automatically for commands that create or
    # operate an assessment. Doctor/config/model inspection remain side-effect free.
    if args.command in (None, "chat", "run", "eval", "serve", "start"):
        try:
            ensure_security_secrets()
        except (OSError, PermissionError, RuntimeError) as exc:
            console.print(f"[bold red]Security bootstrap failed:[/bold red] {exc}")
            return

    # Route subcommands
    if args.command in ("setup", "onboard"):
        reset_flag = getattr(args, "reset", False)
        asyncio.run(run_setup_wizard(reset=reset_flag))

    elif args.command in ("model", "models"):
        if getattr(args, "list", False):
            asyncio.run(_list_models(args.provider))
        elif getattr(args, "test", False):
            asyncio.run(_test_model(args.provider))
        elif getattr(args, "model_id", None):
            from loki.cli.env_utils import update_env_file
            update_env_file({"LOKI_MODEL": args.model_id, "NVIDIA_NIM_MODEL": args.model_id})
            console.print(f"[bold green]✔ Model updated to:[/bold green] [bold cyan]{args.model_id}[/bold cyan]")
        else:
            run_model_command()

    elif args.command == "doctor":
        items = asyncio.run(LokiDoctor.run_diagnostics())
        LokiDoctor.display_report(items)

    elif args.command == "config":
        console.print("\n[bold cyan]─── LOKI ACTIVE CONFIGURATION ───[/bold cyan]")
        cfg = settings.model_dump()
        for k, v in cfg.items():
            if "api_key" in k and v:
                v = f"********{v[-4:]}" if len(str(v)) > 4 else "********"
            console.print(f" [bold]{k}:[/bold] {v}")
        console.print("")

    elif args.command in ("serve", "start"):
        console.print(f"[bold green]Starting Loki Platform at http://{args.host}:{args.port}[/bold green]")
        uvicorn.run("loki.server.app:app", host=args.host, port=args.port, reload=False)

    elif args.command == "run":
        asyncio.run(_run_prompt(args.prompt, args.provider, args.max_steps))

    elif args.command == "chat":
        cli = LokiConversationalCLI(provider=args.provider, max_steps=args.max_steps)
        asyncio.run(cli.start())

    elif args.command == "eval":
        asyncio.run(_run_eval(args.suite, args.provider))

    elif args.command == "tools":
        agent = LokiAgent()
        tools = agent.registry.list_tools()
        console.print(f"\n[bold cyan]Registered Tools ({len(tools)}):[/bold cyan]")
        for t in tools:
            console.print(f" • [bold green]{t.name}[/bold green]: {t.description}")
        console.print("")

    else:
        # Default behavior: running `loki` with no subcommands
        env_file = Path.cwd() / ".env"
        if not env_file.exists():
            console.print(
                Panel(
                    "[bold green]Welcome to Loki![/bold green] Let's configure your AI provider.",
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

        # Launch conversational interface directly
        cli = LokiConversationalCLI()
        asyncio.run(cli.start())


if __name__ == "__main__":
    cli_entrypoint()
