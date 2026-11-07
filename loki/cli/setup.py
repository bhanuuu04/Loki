"""
Loki First-Run Interactive Onboarding & Setup Wizard.
Guides the user through setting up NVIDIA NIM or alternative providers.
Supports arrow-key navigation for provider and model selection.
"""

import os
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from loki.config import settings
from loki.cli.menu import select_from_menu
from loki.cli.model_cmd import choose_model_interactive
from loki.cli.env_utils import update_env_file, reset_configuration
from loki.providers.nvidia_provider import NvidiaNimProvider
from loki.providers.compatibility import ModelCompatibilityTester
from loki.security_bootstrap import ensure_security_secrets

console = Console(force_terminal=True)


async def run_setup_wizard(reset: bool = False):
    if reset:
        reset_configuration()
        console.print("[yellow]✔ Existing configuration has been reset to defaults.[/yellow]\n")

    console.print("\n" + "=" * 60, style="bold cyan")
    console.print("       LOKI ONBOARDING — INTERACTIVE SETUP WIZARD       ", style="bold cyan")
    console.print("=" * 60 + "\n", style="bold cyan")

    console.print("Loki requires an AI model to power its reasoning and cybersecurity analysis.\n"
                  "[bold green]NVIDIA NIM[/bold green] is the recommended first-class provider for high performance.\n")

    provider_options = [
        "nvidia",
        "mock",
        "gemini",
        "openai",
        "ollama",
    ]
    provider_descriptions = [
        "NVIDIA NIM (Recommended - Llama 3.3 70B, Nemotron, Mistral Large)",
        "Offline Mock (Runs 100% offline without API keys for testing)",
        "Google Gemini (Gemini 2.5 Flash / Pro via API key)",
        "OpenAI (GPT-4o / GPT-4o-mini via API key)",
        "Local Ollama (Local llama3 via localhost:11434)",
    ]

    selected_provider_idx = select_from_menu(
        title="Select AI Provider",
        options=provider_options,
        default_index=0,
        descriptions=provider_descriptions,
    )
    provider_choice = provider_options[selected_provider_idx]

    env_updates = {"LOKI_PROVIDER": provider_choice}

    if provider_choice == "nvidia":
        console.print("\n[bold]NVIDIA NIM Configuration[/bold]")
        console.print("Get your API key at: [link=https://build.nvidia.com]https://build.nvidia.com[/link]\n")

        api_key = Prompt.ask(
            "Enter your NVIDIA NIM API Key (e.g. nvapi-...)",
            default=settings.nvidia_nim_api_key or "",
        ).strip()

        base_url = Prompt.ask(
            "Enter NVIDIA NIM Base URL",
            default=settings.nvidia_nim_base_url or "https://integrate.api.nvidia.com/v1",
        ).strip()

        # Arrow-key navigable model selection with live discovery
        console.print("\n[dim]Loading available models...[/dim]")
        model_id = choose_model_interactive(
            current_model=settings.nvidia_nim_model or "meta/llama-3.3-70b-instruct",
            api_key=api_key,
            base_url=base_url,
        )

        env_updates["NVIDIA_NIM_API_KEY"] = api_key
        env_updates["NVIDIA_NIM_BASE_URL"] = base_url
        env_updates["NVIDIA_NIM_MODEL"] = model_id
        env_updates["LOKI_MODEL"] = model_id

        # Write to .env
        update_env_file(env_updates)
        console.print("\n[green]✔ Configuration written to .env[/green]")

        # Connectivity test
        if api_key:
            test_now = Confirm.ask("\nWould you like to test NVIDIA NIM connectivity now?", default=True)
            if test_now:
                console.print("\n[cyan]Probing NVIDIA NIM endpoint...[/cyan]")
                provider = NvidiaNimProvider(model=model_id, api_key=api_key, base_url=base_url)
                tester = ModelCompatibilityTester(provider)
                report = await tester.run_suite()

                if report.overall_status in ("COMPATIBLE", "PARTIAL"):
                    console.print(f"[bold green]✔ NVIDIA NIM connection successful! Status: {report.overall_status}[/bold green]")
                else:
                    console.print(f"[bold yellow]! Warning: Connectivity probe reported: {report.overall_status}[/bold yellow]")
                    for t in report.tests:
                        if not t.passed:
                            console.print(f"  - {t.name}: {t.details}")

    elif provider_choice == "mock":
        console.print("\n[yellow]Offline Mock Provider selected. No API keys needed.[/yellow]")
        update_env_file(env_updates)

    else:
        update_env_file(env_updates)
        console.print(f"\n[green]✔ Provider '{provider_choice}' configured in .env.[/green]")

    console.print("\n" + "=" * 60, style="bold green")
    console.print("               ONBOARDING COMPLETE!                       ", style="bold green")
    console.print("=" * 60 + "\n", style="bold green")

    console.print("Launch Loki anytime with:\n")
    console.print("  [bold cyan]loki[/bold cyan]                Launch conversational chat", style="white")
    console.print("  [bold cyan]loki model[/bold cyan]          Switch AI models with arrow keys", style="white")
    console.print("  [bold cyan]loki onboard --reset[/bold cyan] Restart setup wizard and reset configuration", style="white")
    console.print("  [bold cyan]loki doctor[/bold cyan]         Run system health diagnostic\n", style="white")
