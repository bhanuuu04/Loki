"""
Hermes-Style Interactive Conversational Terminal Interface for Loki.
"""

import asyncio
import os
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.live import Live
from rich import box

from loki import __version__
from loki.config import settings
from loki.runtime.agent import LokiAgent
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode
from loki.providers.factory import get_provider
from loki.cli.model_cmd import choose_model_interactive
from loki.cli.env_utils import update_env_file
from loki.types import AgentEvent, EventType, RunResult, RunStatus

console = Console(force_terminal=True)


BANNER = f"""
[bold cyan]╦  ╔═╗╦╔═╦[/bold cyan]   [bold white]AI Cybersecurity Agent[/bold white]
[bold cyan]║  ║ ║╠╩╗║[/bold cyan]   [dim]v{__version__} • Standalone Runtime[/dim]
[bold cyan]╩═╝╚═╝╩ ╩╩[/bold cyan]   [dim]Type /help for slash commands[/dim]
"""


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

        self.scope_manager = ScopeManager(
            ScopeConfig(
                assessment_name="Loki Interactive Assessment",
                targets=["127.0.0.1", "localhost"],
            )
        )

        self.agent = LokiAgent(
            provider=get_provider(self.provider_name, model=self.model_name),
            max_steps=settings.max_steps,
        )
        self.agent.add_listener(self._on_agent_event)

    def _on_agent_event(self, evt: AgentEvent):
        """Displays real-time tool progress and thoughts."""
        if evt.event_type == EventType.TOOL_CALL_START:
            tname = evt.data.get("tool_name")
            args = evt.data.get("arguments")
            console.print(f" [cyan]⚡ Running tool:[/cyan] [bold]{tname}[/bold] [dim]{args}[/dim]")

        elif evt.event_type == EventType.TOOL_CALL_END:
            tname = evt.data.get("tool_name")
            res = evt.data.get("output")
            time_ms = evt.data.get("execution_time_ms", 0)
            res_str = str(res)
            if len(res_str) > 160:
                res_str = res_str[:160] + "..."
            console.print(f" [green]✔ Tool completed:[/green] [dim]{tname} ({time_ms:.1f}ms): {res_str}[/dim]")

        elif evt.event_type == EventType.ERROR:
            err = evt.data.get("error")
            console.print(f" [bold red]! Error:[/bold red] {err}")

    def display_header(self):
        console.print(BANNER)
        console.print(
            f" [dim]Provider:[/dim] [green]{self.provider_name}[/green] │ "
            f"[dim]Model:[/dim] [green]{self.model_name}[/green] │ "
            f"[dim]Mode:[/dim] [yellow]{self.mode.value.upper()}[/yellow] │ "
            f"[dim]Session:[/dim] [dim]{self.session_id}[/dim]\n"
        )

    def handle_command(self, cmd: str) -> bool:
        """
        Processes slash commands. Returns False if user requested exit, True otherwise.
        """
        parts = cmd.strip().split(maxsplit=1)
        sub = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if sub in ("/exit", "/quit", "/q"):
            console.print("[dim]Exiting Loki session. Goodbye![/dim]\n")
            return False

        elif sub == "/help":
            console.print("\n[bold cyan]Available Slash Commands:[/bold cyan]")
            table = Table(box=box.SIMPLE)
            table.add_column("Command", style="green", width=18)
            table.add_column("Description")
            table.add_row("/help", "Show this cheat sheet")
            table.add_row("/model <id>", "Switch active AI model on the fly")
            table.add_row("/provider <name>", "Switch LLM provider (nvidia, mock, gemini, openai, ollama)")
            table.add_row("/mode <name>", "Switch execution mode (safe, aggressive, advanced_audit)")
            table.add_row("/scope <target>", "Inspect or add target host/IP to authorized scope")
            table.add_row("/tools", "List all available security and system tools")
            table.add_row("/status", "Show active session telemetry, tokens, and health")
            table.add_row("/history", "View conversation history for this session")
            table.add_row("/clear", "Clear terminal screen")
            table.add_row("/exit, /quit", "End conversational session")
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
                console.print(f"[bold green]✔ Provider updated to:[/bold green] {self.provider_name}")

        elif sub == "/mode":
            if arg.lower() in ("safe", "aggressive", "advanced_audit"):
                self.mode = ExecutionMode(arg.lower())
                console.print(f"[bold green]✔ Execution mode updated to:[/bold green] {self.mode.value.upper()}")
            else:
                console.print(f"Current mode: [yellow]{self.mode.value}[/yellow]. Options: safe, aggressive, advanced_audit")

        elif sub == "/scope":
            if not arg:
                targets = self.scope_manager.config.targets
                console.print(f"\n[bold cyan]Authorized Target Scope ({len(targets)}):[/bold cyan]")
                for t in targets:
                    console.print(f" • [green]{t}[/green]")
                console.print("[dim]Use /scope add <host|ip|cidr> to authorize new targets.[/dim]\n")
            else:
                target_to_add = arg.replace("add", "").strip() if arg.startswith("add ") else arg.strip()
                if target_to_add:
                    if target_to_add not in self.scope_manager.config.targets:
                        self.scope_manager.config.targets.append(target_to_add)
                        self.scope_manager._init_rules()
                    console.print(f"[bold green]✔ Added to authorized scope:[/bold green] [bold cyan]{target_to_add}[/bold cyan]")

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

        elif sub == "/clear":
            os.system("cls" if os.name == "nt" else "clear")
            self.display_header()

        elif sub == "/history":
            msgs = self.agent.memory_store.load_session(self.session_id).get_messages()
            console.print(f"\n[bold cyan]Session History ({len(msgs)} messages):[/bold cyan]")
            for m in msgs:
                if m.role.value == "system":
                    continue
                role_color = "blue" if m.role.value == "user" else "green"
                txt = m.content or ""
                preview = txt[:120] + "..." if len(txt) > 120 else txt
                console.print(f"[[{role_color}]{m.role.value.upper()}[/{role_color}]]: {preview}")
            console.print("")

        else:
            console.print(f"[red]Unknown command:[/red] '{sub}'. Type [bold]/help[/bold] for available commands.")

        return True

    async def start(self):
        """Starts the interactive Hermes-style conversation loop."""
        self.display_header()

        while True:
            try:
                user_input = console.input("[bold blue]loki>[/bold blue] ").strip()
                if not user_input:
                    continue

                # Handle slash commands
                if user_input.startswith("/"):
                    should_continue = self.handle_command(user_input)
                    if not should_continue:
                        break
                    continue

                # Conversation step
                self.turn_count += 1
                console.print("")

                # Run agent with active status spinner
                with console.status("[bold cyan]Loki is thinking...[/bold cyan]", spinner="dots"):
                    result: RunResult = await self.agent.run(
                        prompt=user_input,
                        session_id=self.session_id,
                    )

                self.total_tokens_used += result.total_usage.total_tokens

                # Display error panel if run failed
                if result.status == RunStatus.ERROR or result.error_message:
                    err_text = result.error_message or result.final_response or "Unknown runtime error."
                    console.print(
                        Panel(
                            f"[bold red]Execution Error:[/bold red] {err_text}\n\n"
                            f"[yellow]Troubleshooting Tips:[/yellow]\n"
                            f" • Check your API key or reconfigure: [bold cyan]loki onboard[/bold cyan]\n"
                            f" • Switch model: [bold cyan]/model[/bold cyan] or [bold cyan]loki model[/bold cyan]\n"
                            f" • Use offline mock provider: [bold cyan]/provider mock[/bold cyan]\n"
                            f" • Run environment diagnostics: [bold cyan]loki doctor[/bold cyan]",
                            title="[bold red]Agent Encountered an Issue[/bold red]",
                            border_style="red",
                        )
                    )
                elif result.final_response:
                    console.print(Markdown(result.final_response))
                else:
                    console.print("[dim](No response content returned)[/dim]")

                console.print("")

            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session terminated.[/dim]")
                break
            except Exception as e:
                console.print(f"\n[bold red]Error in conversation loop:[/bold red] {type(e).__name__}: {str(e)}\n")
