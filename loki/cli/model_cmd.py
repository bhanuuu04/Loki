"""
Interactive Model Selection and Switching for Loki.
Fetches live models from NVIDIA NIM when available and provides an extensive catalog.
"""

from typing import List, Optional, Tuple
import httpx
from rich.console import Console
from rich.prompt import Prompt

from loki.config import settings
from loki.cli.menu import select_from_menu
from loki.cli.env_utils import update_env_file

console = Console(force_terminal=True)

# Comprehensive catalog of prominent NVIDIA NIM models
FALLBACK_NVIDIA_MODELS: List[Tuple[str, str]] = [
    ("meta/llama-3.3-70b-instruct", "Recommended - SOTA 70B reasoning, tool-use & coding"),
    ("nvidia/llama-3.1-nemotron-70b-instruct", "NVIDIA fine-tuned reasoning & instruction following"),
    ("mistralai/mistral-large-2-instruct", "Advanced 128k context, strong tool calling & analysis"),
    ("deepseek-ai/deepseek-r1", "DeepSeek reasoning model with step-by-step thinking"),
    ("qwen/qwen2.5-72b-instruct", "Exceptional code synthesis, math, and system auditing"),
    ("meta/llama-3.1-70b-instruct", "High-capacity Llama 3.1 70B general reasoning"),
    ("meta/llama-3.1-8b-instruct", "Ultra-fast, lowest latency for quick evaluations"),
    ("google/gemma-2-27b-it", "Google high-efficiency instruction model"),
    ("google/gemma-2-9b-it", "Lightweight Gemma 2 instruction model"),
    ("microsoft/phi-3.5-moe-instruct", "Efficient mixture-of-experts model"),
    ("cohere/command-r-plus", "Cohere enterprise RAG and tool orchestration model"),
    ("writer/palmyra-med-70b", "Specialized high-parameter domain model"),
    ("nvidia/nemotron-4-340b-instruct", "Flagship ultra-large NVIDIA instruction model"),
    ("[Enter Custom Model ID]", "Type your own specific NIM or OpenAI model identifier"),
]

NVIDIA_FEATURED_MODELS = FALLBACK_NVIDIA_MODELS


def fetch_live_nvidia_models(api_key: Optional[str] = None, base_url: Optional[str] = None) -> List[Tuple[str, str]]:
    """Fetch live available model IDs from NVIDIA NIM API."""
    key = api_key or settings.nvidia_nim_api_key
    url = (base_url or settings.nvidia_nim_base_url or "https://integrate.api.nvidia.com/v1").rstrip("/") + "/models"

    if not key:
        return FALLBACK_NVIDIA_MODELS

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url, headers={"Authorization": f"Bearer {key}"})
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                models = []
                for item in data:
                    m_id = item.get("id")
                    if m_id:
                        models.append((m_id, "NVIDIA NIM Endpoint Model"))
                if models:
                    models.sort(key=lambda x: x[0])
                    models.append(("[Enter Custom Model ID]", "Type your own custom model identifier"))
                    return models
    except Exception:
        pass

    return FALLBACK_NVIDIA_MODELS


def choose_model_interactive(
    current_model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> str:
    """
    Renders an arrow-key navigable model selection menu.
    Dynamically attempts live model discovery from NVIDIA NIM.
    """
    model_catalog = fetch_live_nvidia_models(api_key=api_key, base_url=base_url)

    options = [m[0] for m in model_catalog]
    descriptions = [m[1] for m in model_catalog]

    # Find default index
    default_idx = 0
    if current_model:
        for idx, (m_id, _) in enumerate(model_catalog):
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
