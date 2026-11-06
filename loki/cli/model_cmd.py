"""
Interactive Model Selection and Switching for Loki.
"""

from typing import List, Optional
from rich.console import Console
from rich.prompt import Prompt

from loki.config import settings
from loki.cli.menu import select_from_menu
from loki.cli.env_utils import update_env_file

console = Console(force_terminal=True)

NVIDIA_FEATURED_MODELS = [
    ("meta/llama-3.3-70b-instruct", "Recommended - SOTA 70B reasoning, tool-use & coding"),
    ("nvidia/llama-3.1-nemotron-70b-instruct", "NVIDIA fine-tuned reasoning & instruction following"),
    ("mistralai/mistral-large-2-instruct", "Advanced 128k context, strong tool calling & analysis"),
    ("google/gemma-2-27b-it", "Fast, high-efficiency instruction model"),
    ("qwen/qwen2.5-72b-instruct", "Exceptional code synthesis, math, and system auditing"),
    ("meta/llama-3.1-8b-instruct", "Ultra-fast, lowest latency for quick evaluations"),
    ("[Enter Custom Model ID]", "Type your own specific NIM or OpenAI model identifier"),
]


def choose_model_interactive(current_model: Optional[str] = None) -> str:
    """
    Renders an arrow-key navigable model selection menu.
    Returns the selected model ID string.
    """
    options = [m[0] for m in NVIDIA_FEATURED_MODELS]
    descriptions = [m[1] for m in NVIDIA_FEATURED_MODELS]

    # Find default index
    default_idx = 0
    if current_model:
        for idx, (m_id, _) in enumerate(NVIDIA_FEATURED_MODELS):
            if m_id.lower() == current_model.lower():
                default_idx = idx
                break

    selected_idx = select_from_menu(
        title="Select AI Model",
        options=options,
        default_index=default_idx,
        descriptions=descriptions,
    )

    selected_option = options[selected_idx]

    if selected_option == "[Enter Custom Model ID]":
        custom_id = Prompt.ask(
            "Enter your custom Model ID",
            default=current_model or "meta/llama-3.3-70b-instruct",
        ).strip()
        return custom_id

    return selected_option


def run_model_command():
    """CLI entrypoint for `loki model`."""
    console.print("\n[bold cyan]Loki AI Model Manager[/bold cyan]")
    current_model = settings.nvidia_nim_model or settings.default_model
    console.print(f"Current active model: [bold green]{current_model}[/bold green]\n")

    selected_model = choose_model_interactive(current_model=current_model)

    # Save to .env
    update_env_file({
        "NVIDIA_NIM_MODEL": selected_model,
        "LOKI_MODEL": selected_model,
    })

    console.print(f"\n[bold green]✔ Model updated successfully to:[/bold green] [bold cyan]{selected_model}[/bold cyan]")
    console.print("Run [bold]loki[/bold] to chat with this model immediately.\n")
