"""
Hermes-Style Interactive Conversational Terminal Interface for Loki.
Direct, clean, and unique terminal interface with high-fidelity telemetry,
banner art, and real-time execution feedback.
"""

from typing import Any, Dict, Optional
import asyncio
import os
import sys
import time
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.rule import Rule
from rich import box
from rich.prompt import Confirm

from loki import __version__
from loki.config import settings
from loki.runtime.agent import LokiAgent
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode
from loki.tools.security_tools import scope_mgr
from loki.providers.factory import get_provider
from loki.cli.model_cmd import choose_model_interactive
from loki.cli.env_utils import update_env_file
from loki.types import AgentEvent, EventType, RunResult, RunStatus

console = Console(force_terminal=True)

HERMES_BANNER = r"""[bold cyan]
  ██╗      ██████╗ ██╗  ██╗██╗    ██████╗      ██████╗ 
  ██║     ██╔═══██╗██║ ██╔╝██║    ╚════██╗    ██╔═████╗
  ██║     ██║   ██║█████═╝ ██║     █████╔╝    ██║██╔██║
  ██║     ██║   ██║██╔═██╗ ██║    ██╔═══╝     ████╔╝██║
  ███████╗╚██████╔╝██║ ╚██╗██║    ███████╗██╗ ╚██████╔╝
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝    ╚══════╝╚═╝  ╚═════╝ 
[/bold cyan]"""


class LokiConversationalCLI:
    """Hermes-style interactive conversational terminal interface."""

    def __init__(
        self,
        provider: str = settings.default_provider,
        model: str = settings.default_model,
        mode: ExecutionMode = ExecutionMode.SAFE,
    ):
        self.provider_name = provider
        self.model_name = model
        self.mode = mode
        self.session_id = f"cli_{int(time.time())}"
        self.total_tokens_used = 0
        self.turn_count = 0
        self._status_spinner = None

        self.scope_manager = scope_mgr
        if "127.0.0.1" not in self.scope_manager.config.targets:
            self.scope_manager.update_targets(
                add_targets=["127.0.0.1", "localhost"],
                author="cli_init",
                reason="Default local loopback authorization",
            )

        self.agent = LokiAgent(
            provider=get_provider(self.provider_name, model=self.model_name),
            max_steps=settings.max_steps,
        )
        self.agent.gateway.policy_engine.set_mode(
            self.mode, operator_confirmed=(self.mode == ExecutionMode.NOMERCY)
        )
        self.agent.add_listener(self._on_agent_event)

    def _safe_print(self, renderable: Any) -> None:
        """
        Safely prints to console while status spinner is active.
        Prevents Windows CMD/PowerShell cursor collisions and ghost text.
        """
        if self._status_spinner:
            try:
                self._status_spinner.stop()
                console.print(renderable)
                self._status_spinner.start()
            except Exception:
                console.print(renderable)
        else:
            console.print(renderable)

    def _format_tool_call(self, tname: str, args: Dict[str, Any]) -> str:
        """Formats tool invocation into a clean human-readable action."""
        if tname == "run_command":
            cmd = args.get("command", "")
            return f"[bold cyan]⚡ Shell Command:[/bold cyan] [bold white]$ {cmd}[/bold white]"
        elif tname == "python_exec":
            code = args.get("code", "").strip()
            lines = [l for l in code.splitlines() if l.strip()]
            preview = lines[0][:75] if len(lines) == 1 else f"{len(lines)} lines of Python"
            return f"[bold cyan]⚡ Python Script:[/bold cyan] [dim]{preview}[/dim]"
        elif tname == "enumerate_subdomains":
            domain = args.get("domain", "")
            return f"[bold cyan]⚡ Reconnaissance:[/bold cyan] [bold white]{domain}[/bold white]"
        elif tname == "authorize_target":
            target = args.get("target", "")
            return f"[bold cyan]⚡ Scope Check:[/bold cyan] [bold white]{target}[/bold white]"
        elif tname == "dns_lookup":
            domain = args.get("host", args.get("domain", ""))
            return f"[bold cyan]⚡ DNS Query:[/bold cyan] [bold white]{domain}[/bold white]"
        elif tname == "search_security_tool_catalog":
            query = args.get("query", "")
            return f"[bold cyan]⚡ Tool Catalog Search:[/bold cyan] [bold white]'{query}'[/bold white]"
        elif tname == "audit_http_security_headers":
            url = args.get("url", "")
            return f"[bold cyan]⚡ Auditing Headers:[/bold cyan] [bold white]{url}[/bold white]"
        elif tname == "check_scope_authorization":
            target = args.get("target", "")
            return f"[bold cyan]⚡ Scope Check:[/bold cyan] [bold white]{target}[/bold white]"
        elif tname == "record_security_finding":
            title = args.get("title", "")
            sev = args.get("severity", "")
            return f"[bold cyan]⚡ Recording Finding:[/bold cyan] [bold yellow][{sev.upper()}][/bold yellow] [bold white]{title}[/bold white]"
        else:
            compact = ", ".join(f"{k}={repr(v)[:40]}" for k, v in args.items())
            return f"[bold cyan]⚡ Tool ({tname}):[/bold cyan] [dim]{compact}[/dim]"

    def _format_tool_result(self, tname: str, output: Any, time_ms: float) -> str:
        """Formats tool completion output into clean visual lines."""
        raw_str = str(output).strip()
        clean_str = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw_str).strip()

        if tname == "run_command":
            if "exit code: 0" in clean_str.lower():
                content = clean_str
                if "STDOUT:\n" in content:
                    content = content.split("STDOUT:\n", 1)[1]
                lines = [l for l in content.splitlines() if l.strip()]
                if not lines:
                    return f" [green]✔ Completed[/green] [dim]({time_ms:.1f}ms, no output)[/dim]"
                elif len(lines) == 1:
                    return f" [green]✔ Completed[/green] [dim]({time_ms:.1f}ms): {lines[0][:120]}[/dim]"
                else:
                    return f" [green]✔ Completed[/green] [dim]({time_ms:.1f}ms): {lines[0][:90]} (+{len(lines)-1} lines)[/dim]"
            else:
                lines = [l for l in clean_str.splitlines() if l.strip()]
                err_summary = lines[0] if lines else "Non-zero exit"
                return f" [yellow]! Notice[/yellow] [dim]({time_ms:.1f}ms): {err_summary[:120]}[/dim]"

        if tname == "enumerate_subdomains":
            lines = [l for l in clean_str.splitlines() if l.strip()]
            header = lines[0] if lines else "Complete"
            return f" [green]✔ {header}[/green] [dim]({time_ms:.1f}ms)[/dim]"

        lines = [l for l in clean_str.splitlines() if l.strip()]
        if not lines:
            return f" [green]✔ {tname} completed[/green] [dim]({time_ms:.1f}ms)[/dim]"
        preview = lines[0][:120]
        if len(lines) > 1:
            preview += f" [dim](+{len(lines)-1} more lines)[/dim]"
        return f" [green]✔ {tname} completed[/green] [dim]({time_ms:.1f}ms):[/dim] {preview}"

    def _on_agent_event(self, evt: AgentEvent) -> None:
        """Displays real-time tool progress and thoughts cleanly without terminal tearing."""
        if evt.event_type == EventType.TOOL_CALL_START:
            tname = evt.data.get("tool_name", "")
            args = evt.data.get("arguments", {})
            call_line = self._format_tool_call(tname, args)
            self._safe_print(f" {call_line}")
            if self._status_spinner:
                self._status_spinner.update(f"[bold cyan]Running {tname}...[/bold cyan]")

        elif evt.event_type == EventType.TOOL_CALL_END:
            tname = evt.data.get("tool_name", "")
            res = evt.data.get("output", "")
            time_ms = evt.data.get("execution_time_ms", 0.0)
            res_line = self._format_tool_result(tname, res, time_ms)
            self._safe_print(res_line)
            if self._status_spinner:
                self._status_spinner.update("[bold cyan]Analyzing observations...[/bold cyan]")

        elif evt.event_type == EventType.STEP_START:
            step_num = evt.data.get("step_number", 1)
            if self._status_spinner:
                self._status_spinner.update(f"[bold cyan]Reasoning cycle (step {step_num})...[/bold cyan]")

        elif evt.event_type == EventType.THOUGHT:
            thought = evt.data.get("thought", "").strip()
            if thought and len(thought) > 10:
                preview = thought.replace("\n", " ")[:130]
                self._safe_print(f" [dim italic]Thinking: {preview}...[/dim italic]")

        elif evt.event_type == EventType.ERROR:
            err = evt.data.get("error")
            self._safe_print(f" [bold red]! Error:[/bold red] {err}")

    def display_header(self) -> None:
        """Renders the unique Hermes-style intro banner and telemetry grid."""
        console.print(HERMES_BANNER)
        console.print(
            " [bold white]LOKI 2.0[/bold white] [dim]•[/dim] "
            "[bold cyan]AUTONOMOUS CYBERSECURITY RESEARCH AGENT[/bold cyan] [dim]•[/dim] "
            f"[dim]v{__version__}[/dim]\n"
        )

        # Hermes Telemetry Card
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        # Left Column
        left_text = (
            f" [dim]Provider:[/dim] [bold green]{self.provider_name}[/bold green]\n"
            f" [dim]AI Model:[/dim] [bold cyan]{self.model_name}[/bold cyan]\n"
            f" [dim]Policy Mode:[/dim] [bold yellow]{self.mode.value.upper()}[/bold yellow]"
        )

        # Right Column
        targets_count = len(self.scope_manager.config.targets)
        right_text = (
            f" [dim]Target Scope:[/dim] [bold green]{targets_count} Authorized[/bold green]\n"
            f" [dim]Execution Gateway:[/dim] [bold green]ENFORCED (Single Choke-Point)[/bold green]\n"
            f" [dim]Session ID:[/dim] [dim]{self.session_id}[/dim]"
        )

        grid.add_row(left_text, right_text)

        telemetry_panel = Panel(
            grid,
            title="[bold cyan]SYSTEM TELEMETRY[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
        console.print(telemetry_panel)

        console.print(
            " [dim]Quick Commands:[/dim] "
            "[cyan]/help[/cyan] [dim]•[/dim] "
            "[cyan]/model[/cyan] [dim]•[/dim] "
            "[cyan]/scope[/cyan] [dim]•[/dim] "
            "[cyan]/tools[/cyan] [dim]•[/dim] "
            "[cyan]/mode[/cyan] [dim]•[/dim] "
            "[cyan]/clear[/cyan] [dim]•[/dim] "
            "[cyan]exit[/cyan]\n"
        )

    def handle_command(self, cmd: str) -> bool:
        """Processes slash commands. Returns False if user requested exit, True otherwise."""
        parts = cmd.strip().split(maxsplit=1)
        sub = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if sub in ("/exit", "/quit", "/q", "exit", "quit"):
            console.print("[dim]Exiting Loki session. Goodbye![/dim]\n")
            return False

        elif sub == "/help":
            console.print("\n[bold cyan]Available Commands:[/bold cyan]")
            table = Table(box=box.SIMPLE)
            table.add_column("Command", style="green", width=22)
            table.add_column("Description")
            table.add_row("/model [id]", "Interactively pick or switch active AI model")
            table.add_row("/provider [name]", "Switch provider (nvidia, mock, gemini, openai, ollama)")
            table.add_row("/mode [safe|audit|nomercy]", "Switch assessment intensity; NOMERCY requires operator confirmation")
            table.add_row("/scope [add|exclude target]", "Inspect or update authorized target scope")
            table.add_row("/tools", "List registered security tools")
            table.add_row("/status", "Show active session telemetry & token usage")
            table.add_row("/history", "View conversation history")
            table.add_row("/reset", "Clear conversation memory and start fresh session")
            table.add_row("/clear", "Clear terminal screen")
            table.add_row("/exit, /quit", "End session")
            console.print(table)
            console.print("")

        elif sub == "/model":
            if not arg:
                selected = choose_model_interactive(
                    current_model=self.model_name,
                    api_key=settings.nvidia_nim_api_key,
                    base_url=settings.nvidia_nim_base_url,
                )
                self.model_name = selected
            else:
                self.model_name = arg

            self.agent.provider = get_provider(self.provider_name, model=self.model_name)
            update_env_file({"LOKI_MODEL": self.model_name, "NVIDIA_NIM_MODEL": self.model_name})
            console.print(f"[bold green]✔ Model updated to:[/bold green] [bold cyan]{self.model_name}[/bold cyan]")

        elif sub == "/provider":
            if not arg:
                console.print(f"Active provider: [green]{self.provider_name}[/green]. Choices: nvidia, mock, gemini, openai, ollama")
            else:
                self.provider_name = arg.lower()
                self.agent.provider = get_provider(self.provider_name, model=self.model_name)
                update_env_file({"LOKI_PROVIDER": self.provider_name})
                console.print(f"[bold green]✔ Provider updated to:[/bold green] {self.provider_name}")

        elif sub == "/mode":
            if not arg:
                console.print(
                    f"Current mode: [yellow]{self.mode.value.upper()}[/yellow]. "
                    "Options: safe, audit, nomercy"
                )
            else:
                try:
                    requested_mode = ExecutionMode.parse(arg)
                except ValueError:
                    console.print("[yellow]Usage: /mode safe | audit | nomercy[/yellow]")
                    return True

                if requested_mode == ExecutionMode.NOMERCY:
                    confirmed = Confirm.ask(
                        "[bold red]NOMERCY enables high-intensity testing and credential-audit tools "
                        "against explicitly authorized targets. Destructive and DoS actions remain blocked. "
                        "Do you confirm?[/bold red]",
                        default=False,
                    )
                    if not confirmed:
                        console.print("[yellow]Mode unchanged. NOMERCY requires explicit operator confirmation.[/yellow]")
                        return True

                self.agent.gateway.policy_engine.set_mode(
                    requested_mode,
                    operator_confirmed=(requested_mode == ExecutionMode.NOMERCY),
                )
                self.mode = requested_mode
                console.print(
                    f"[bold green]✔ Execution mode updated to:[/bold green] {self.mode.value.upper()}"
                )

        elif sub == "/scope":
            if not arg:
                targets = self.scope_manager.config.targets
                exclusions = self.scope_manager.config.excluded_targets
                console.print(f"\n[bold cyan]Authorized Scope Targets ({len(targets)}) [v{self.scope_manager.config.version}]:[/bold cyan]")
                for t in targets:
                    console.print(f" • [green]{t}[/green]")
                if exclusions:
                    console.print(f"\n[bold red]Excluded Scope Targets ({len(exclusions)}):[/bold red]")
                    for e in exclusions:
                        console.print(f" • [red]{e}[/red]")
                console.print("\n[dim]Commands: /scope add <host|ip|cidr> | /scope exclude <host|ip>[/dim]\n")
            elif arg.startswith("exclude ") or arg.startswith("rm "):
                target_to_ex = arg.split(maxsplit=1)[1].strip()
                clean = self.scope_manager.normalize_target(target_to_ex)
                if clean:
                    self.scope_manager.update_targets(add_exclusions=[clean], author="cli_user")
                    console.print(f"[bold red]✔ Added to excluded scope:[/bold red] [bold red]{clean}[/bold red]")
            else:
                target_to_add = arg.replace("add", "", 1).strip() if arg.startswith("add ") else arg.strip()
                clean = self.scope_manager.normalize_target(target_to_add)
                if clean:
                    self.scope_manager.update_targets(add_targets=[clean], author="cli_user")
                    console.print(f"[bold green]✔ Added to authorized scope (v{self.scope_manager.config.version}):[/bold green] [bold cyan]{clean}[/bold cyan]")

        elif sub == "/tools":
            tools = self.agent.registry.list_tools()
            console.print(f"\n[bold cyan]Registered Tools ({len(tools)}):[/bold cyan]")
            for t in tools:
                console.print(f" • [green]{t.name}[/green]: {t.description}")
            console.print("")

        elif sub == "/status":
            console.print(f"\n[bold cyan]Session Telemetry ({self.session_id}):[/bold cyan]")
            console.print(f" • Conversation Turns: {self.turn_count}")
            console.print(f" • Total Tokens Used: {self.total_tokens_used}")
            console.print(f" • Active Provider: {self.provider_name}")
            console.print(f" • Active Model: {self.model_name}")
            console.print(f" • Execution Mode: {self.mode.value.upper()}\n")

        elif sub == "/reset":
            self.session_id = f"cli_{int(time.time())}"
            self.turn_count = 0
            self.total_tokens_used = 0
            console.print("[bold green]✔ Session memory reset. Starting new conversation.[/bold green]\n")

        elif sub == "/clear":
            console.clear()
            self.display_header()

        elif sub == "/history":
            msgs = self.agent.memory_store.load_session(self.session_id).get_messages()
            console.print(f"\n[bold cyan]Session History ({len(msgs)} messages):[/bold cyan]")
            for m in msgs:
                if m.role.value == "system":
                    continue
                role_color = "blue" if m.role.value == "user" else "green"
                txt = (m.content or "").strip()
                preview = txt[:120] + "..." if len(txt) > 120 else txt
                console.print(f"[[{role_color}]{m.role.value.upper()}[/{role_color}]]: {preview}")
            console.print("")

        else:
            console.print(f"[red]Unknown command:[/red] '{sub}'. Type [bold]/help[/bold] for available commands.")

        return True

    async def start(self) -> None:
        """Starts the interactive Hermes-style conversation loop."""
        self.display_header()

        while True:
            try:
                # Hermes-style interactive prompt
                user_input = console.input(f"[bold cyan]loki[/bold cyan][dim]@{self.session_id[-6:]}[/dim] [bold yellow]❯[/bold yellow] ").strip()
                if not user_input:
                    continue

                # Handle slash commands and direct exit/quit words
                if user_input.startswith("/") or user_input.lower() in ("exit", "quit"):
                    should_continue = self.handle_command(user_input)
                    if not should_continue:
                        break
                    continue

                # Conversation step
                self.turn_count += 1
                console.print("")

                # Run agent with active status spinner
                with console.status("[bold cyan]Loki is thinking...[/bold cyan]", spinner="dots") as status:
                    self._status_spinner = status
                    try:
                        result: RunResult = await self.agent.run(
                            prompt=user_input,
                            session_id=self.session_id,
                        )
                    finally:
                        self._status_spinner = None

                self.total_tokens_used += result.total_usage.total_tokens

                # Display error panel if run failed
                if result.status == RunStatus.ERROR or result.error_message:
                    err_text = result.error_message or result.final_response or "Unknown runtime error."
                    console.print(
                        Panel(
                            f"[bold red]Execution Notice:[/bold red] {err_text}\n\n"
                            f"[yellow]Quick Actions:[/yellow]\n"
                            f" • Switch model: [bold cyan]/model[/bold cyan]\n"
                            f" • Switch to mock provider: [bold cyan]/provider mock[/bold cyan]\n"
                            f" • Run diagnostics: [bold cyan]loki doctor[/bold cyan]",
                            title="[bold red]Action Required[/bold red]",
                            border_style="red",
                        )
                    )
                elif result.final_response:
                    console.print(f"\n[dim]───[/dim] [bold cyan]✦ Loki Analysis[/bold cyan] [dim]({result.total_latency_ms:.0f}ms • {result.total_usage.total_tokens} tokens)[/dim] [dim]──────────────────────────────────────[/dim]")
                    console.print(Markdown(result.final_response))
                    console.print(f"[dim]────────────────────────────────────────────────────────────────────────────[/dim]\n")
                else:
                    console.print("[dim](No response content returned)[/dim]")

            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session terminated.[/dim]")
                break
            except Exception as e:
                console.print(f"\n[bold red]Error in conversation loop:[/bold red] {type(e).__name__}: {str(e)}\n")
