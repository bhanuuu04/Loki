"""
Loki First-Run Interactive Setup Wizard.
Guides the user through setting up NVIDIA NIM or alternative providers.
"""

import os
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from loki.config import settings
from loki.providers.nvidia_provider import NvidiaNimProvider
from loki.providers.compatibility import ModelCompatibilityTester

console = Console(force_terminal=True)


def update_env_file(key_values: dict) -> None:
    """Updates or adds key-value pairs in the local .env file preserving other content."""
    env_path = Path.cwd() / ".env"
    existing_lines = []
    existing_keys = set()

    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    k = stripped.split("=", 1)[0].strip()
                    existing_keys.add(k)
                    if k in key_values:
                        existing_lines.append(f"{k}={key_values[k]}\n")
                    else:
                        existing_lines.append(line)
                else:
                    existing_lines.append(line)

    for k, v in key_values.items():
        if k not in existing_keys:
            existing_lines.append(f"{k}={v}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(existing_lines)


async def run_setup_wizard():
    console.print("\n" + "=" * 60, style="bold cyan")
    console.print("       LOKI AGENT HARNESS — FIRST-RUN SETUP WIZARD       ", style="bold cyan")
    console.print("=" * 60 + "\n", style="bold cyan")

    console.print("Loki requires an LLM provider to power its autonomous agent reasoning.\n"
                  "[bold green]NVIDIA NIM[/bold green] is the recommended first-class provider for performance and scale.\n")

    provider_choice = Prompt.ask(
        "Select LLM Provider",
        choices=["nvidia", "mock", "gemini", "openai", "ollama"],
        default="nvidia",
    )

    env_updates = {"LOKI_PROVIDER": provider_choice}

    if provider_choice == "nvidia":
        console.print("\n[bold]NVIDIA NIM Configuration[/bold]")
        console.print("Get your API key at: [link=https://build.nvidia.com]https://build.nvidia.com[/link]\n")

        api_key = Prompt.ask(
            "Enter your NVIDIA NIM API Key",
            password=True,
            default=settings.nvidia_nim_api_key or "",
        ).strip()

        base_url = Prompt.ask(
            "Enter NVIDIA NIM Base URL",
            default=settings.nvidia_nim_base_url or "https://integrate.api.nvidia.com/v1",
        ).strip()

        model_id = Prompt.ask(
            "Select or enter NVIDIA NIM Model ID",
            default=settings.nvidia_nim_model or "meta/llama-3.3-70b-instruct",
        ).strip()

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
        console.print("\n[yellow]Mock Provider selected. Runs 100% offline without API keys.[/yellow]")
        update_env_file(env_updates)

    else:
        update_env_file(env_updates)
        console.print(f"\n[green]✔ Provider '{provider_choice}' configured in .env.[/green]")

    console.print("\n" + "=" * 60, style="bold green")
    console.print("                 SETUP COMPLETE!                          ", style="bold green")
    console.print("=" * 60 + "\n", style="bold green")

    console.print("You can now start chatting with Loki immediately:\n")
    console.print("  [bold cyan]loki[/bold cyan]                Launch interactive Hermes-style chat", style="white")
    console.print("  [bold cyan]loki doctor[/bold cyan]         Verify system health diagnostics", style="white")
    console.print("  [bold cyan]loki start[/bold cyan]          Start Web UI on http://127.0.0.1:8000\n", style="white")
