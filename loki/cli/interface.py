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
from loki.tools.security_tools import scope_mgr, kali_tool_index
from loki.knowledge.tool_registry.performance_memory import tool_performance_memory, classify_task
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
            f" [dim]Policy Mode:[/dim] [bold yellow]{self.mode.value.upper()}[/bold yellow]\n"
        )

        # Right Column
        targets_count = len(self.scope_manager.config.targets)
        right_text = (
            f" [dim]Target Scope:[/dim] [bold green]{targets_count} Authorized[/bold green]\n"
            f" [dim]Execution Gateway:[/dim] [bold green]ENFORCED (Single Choke-Point)[/bold green]\n"
            f" [dim]Lab Verification:[/dim] [bold]{'ENABLED' if self.scope_manager.config.lab_mode_enabled else 'disabled'}[/bold]\n"
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
            table.add_row("/lab [status|enable|disable]", "Enable canary-only proof-of-access tools for a disposable lab")
            table.add_row("/tools", "List registered security tools")
            table.add_row("/tool search <query>", "Search the synced Kali Linux tool catalogue")
            table.add_row("/tool info <name>", "Inspect a Kali tool, package, or executable alias")
            table.add_row("/tool installed", "List Kali tools detected on the Loki host")
            table.add_row("/tool performance [task]", "View learned tool effectiveness and priorities")
            table.add_row("/tool sync", "Sync the official Kali tools catalogue")
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


        elif sub == "/lab":
            action = arg.strip().lower() or "status"
            ctx = self.agent.security_context

            if action == "status":
                enabled = bool(self.scope_manager.config.lab_mode_enabled)
                active = ctx.active_assessment_id or "none"
                console.print(
                    f"Lab verification: [{'green' if enabled else 'yellow'}]"
                    f"{'ENABLED' if enabled else 'disabled'}[/] | "
                    f"Assessment: [cyan]{active}[/cyan]"
                )
                if not enabled:
                    console.print(
                        "[dim]To enable: switch to /mode nomercy, add only disposable lab targets "
                        "to /scope, then run /lab enable.[/dim]"
                    )
            elif action == "enable":
                if self.mode != ExecutionMode.NOMERCY:
                    console.print("[yellow]Switch to /mode nomercy before enabling lab verification.[/yellow]")
                    return True
                if self.scope_manager.config.lab_mode_enabled:
                    console.print("[green]Lab verification is already enabled.[/green]")
                    return True
                if not self.scope_manager.config.targets:
                    console.print("[red]Add at least one explicitly authorized lab target with /scope first.[/red]")
                    return True
                confirmed = Confirm.ask(
                    "[bold red]Enable lab proof-of-access for the currently scoped disposable test environment? "
                    "Only use systems you own or have explicit permission to test. Continue?[/bold red]",
                    default=False,
                )
                if not confirmed:
                    console.print("[yellow]Lab verification remains disabled.[/yellow]")
                    return True

                updated_scope = self.scope_manager.config.model_copy(deep=True)
                updated_scope.lab_mode_enabled = True
                self.scope_manager.set_config(
                    updated_scope,
                    author="interactive_operator",
                    reason="Operator explicitly enabled NOMERCY lab proof-of-access",
                )

                try:
                    assessment_id = ctx.active_assessment_id or f"lab_{self.session_id}"
                    session = ctx.assessment_store.load_assessment(assessment_id)
                    if session is None:
                        session = ctx.assessment_store.create_assessment(
                            session_id=assessment_id,
                            name=updated_scope.assessment_name or "Loki Lab Assessment",
                            scope=updated_scope,
                        )
                    session.scope = updated_scope
                    session.execution_mode = ExecutionMode.NOMERCY
                    ctx.assessment_store.save_assessment(session)
                    ctx.active_assessment_id = assessment_id
                except Exception as exc:
                    rollback_scope = self.scope_manager.config.model_copy(deep=True)
                    rollback_scope.lab_mode_enabled = False
                    self.scope_manager.set_config(
                        rollback_scope,
                        author="interactive_operator",
                        reason="Lab assessment initialization failed; lab mode rolled back",
                    )
                    console.print(f"[bold red]Could not initialize lab assessment:[/bold red] {type(exc).__name__}")
                    return True

                console.print(
                    f"[bold green]Lab proof-of-access enabled for {len(updated_scope.targets)} scoped target(s).[/bold green]"
                )
                console.print(
                    f"[dim]Active evidence session: {ctx.active_assessment_id}. "
                    "Only exact seeded canary records can be extracted.[/dim]"
                )
            elif action == "disable":
                updated_scope = self.scope_manager.config.model_copy(deep=True)
                updated_scope.lab_mode_enabled = False
                self.scope_manager.set_config(
                    updated_scope,
                    author="interactive_operator",
                    reason="Operator disabled lab proof-of-access",
                )
                console.print("[green]Lab proof-of-access disabled.[/green]")
            else:
                console.print("[yellow]Usage: /lab status | /lab enable | /lab disable[/yellow]")

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
            console.print(f"\n[bold cyan]Registered Runtime Tools ({len(tools)}):[/bold cyan]")
            for t in tools:
                console.print(f" • [green]{t.name}[/green]: {t.description}")
            if kali_tool_index.records:
                console.print(f"\n[bold cyan]Kali Catalogue:[/bold cyan] {len(kali_tool_index.records)} cached source entries.")
            else:
                console.print("\n[yellow]Kali catalogue not synced. Run /tool sync or loki tools --sync-kali.[/yellow]")
            console.print("")

        elif sub == "/tool":
            tool_parts = arg.split(maxsplit=1)
            action = tool_parts[0].lower() if tool_parts else "help"
            value = tool_parts[1].strip() if len(tool_parts) > 1 else ""

            if action == "sync":
                try:
                    metadata = kali_tool_index.sync_from_kali()
                    console.print(
                        f"[bold green]Kali catalogue synced: {metadata['tool_count']} source entries.[/bold green]"
                    )
                    console.print(f"[dim]Cached at: {kali_tool_index.cache_path}[/dim]")
                except Exception as exc:
                    console.print(f"[bold red]Kali catalogue sync failed:[/bold red] {exc}")
                    if kali_tool_index.records:
                        console.print("[yellow]Previous cached catalogue remains available.[/yellow]")

            elif action == "search":
                if not value:
                    console.print("[yellow]Usage: /tool search <task, category, package, or executable>[/yellow]")
                    return True
                matches = kali_tool_index.search(value, limit=12)
                if not matches:
                    console.print("[yellow]No Kali catalogue matches. Sync with /tool sync first.[/yellow]")
                else:
                    table = Table(title=f"Kali Tool Matches ({len(matches)})", box=box.SIMPLE)
                    table.add_column("Tool", style="green")
                    table.add_column("Category")
                    table.add_column("Host Status")
                    table.add_column("Package(s)")
                    table.add_column("Executables")
                    for item in matches:
                        table.add_row(
                            item["name"],
                            item["category"],
                            "Installed" if item["is_installed"] else "Not detected",
                            ", ".join(item["packages"][:3]) or "—",
                            ", ".join(item["binaries"][:4]) or "—",
                        )
                    console.print(table)

            elif action == "installed":
                matches = kali_tool_index.search("", installed_only=True, limit=20)
                if not matches:
                    console.print("[yellow]No installed Kali catalogue binaries detected, or the index is not synced.[/yellow]")
                else:
                    for item in matches:
                        console.print(
                            f" • [green]{item['name']}[/green] — {item['installed_path']} "
                            f"[dim]({item['category']})[/dim]"
                        )
                    console.print("[dim]Showing up to 20 detected entries. This checks host PATH, not the Docker image.[/dim]")

            elif action == "performance":
                task_type = classify_task(value) if value else None
                console.print(
                    Panel(
                        tool_performance_memory.summary(task_type),
                        title=f"Tool Effectiveness Memory{f' — {task_type}' if task_type else ''}",
                        border_style="cyan",
                    )
                )

            elif action == "reset-memory":
                from rich.prompt import Confirm
                if Confirm.ask(
                    "Clear Loki's local tool-effectiveness memory? This does not delete chat history or findings",
                    default=False,
                ):
                    tool_performance_memory.clear()
                    console.print("[bold green]✔ Tool-effectiveness memory cleared.[/bold green]")
                else:
                    console.print("[dim]Memory was not changed.[/dim]")

            elif action == "info":
                if not value:
                    console.print("[yellow]Usage: /tool info <tool, package, or executable>[/yellow]")
                    return True
                item = kali_tool_index.get_tool(value)
                if not item:
                    console.print(f"[yellow]No Kali catalogue entry found for '{value}'.[/yellow]")
                else:
                    console.print(Panel(
                        f"[bold]{item['name']}[/bold] ({item['category']})\n\n"
                        f"{item.get('local_package_description') or item['summary']}\n\n"
                        f"Packages: {', '.join(item['packages']) or 'not listed'}\n"
                        f"Executables: {', '.join(item['binaries']) or 'not listed'}\n"
                        f"Host path: {item['installed_path'] or 'not detected'}\n"
                        f"Documentation: {item['documentation_url'] or item['source_url']}",
                        title="Kali Tool Details",
                        border_style="cyan",
                    ))

            else:
                console.print(
                    "[cyan]Kali catalogue commands:[/cyan]\n"
                    "  /tool sync\n"
                    "  /tool search <query>\n"
                    "  /tool info <name>\n"
                    "  /tool installed\n"
                    "  /tool performance [task]\n"
                    "  /tool reset-memory"
                )

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
