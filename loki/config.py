"""
Configuration and settings management for Loki.
"""

from typing import Optional
import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()


class LokiConfig(BaseModel):
    # Default LLM configuration
    default_provider: str = Field(default_factory=lambda: os.getenv("LOKI_PROVIDER", "mock"))
    default_model: str = Field(default_factory=lambda: os.getenv("LOKI_MODEL", "mock-agent-v1"))
    temperature: float = Field(default_factory=lambda: float(os.getenv("LOKI_TEMPERATURE", "0.2")))
    max_steps: int = Field(default_factory=lambda: int(os.getenv("LOKI_MAX_STEPS", "10")))
    timeout_seconds: float = Field(default_factory=lambda: float(os.getenv("LOKI_TIMEOUT", "60.0")))

    # NVIDIA NIM configuration
    nvidia_nim_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("NVIDIA_NIM_API_KEY") or os.getenv("NVIDIA_API_KEY")
    )
    nvidia_nim_base_url: str = Field(
        default_factory=lambda: os.getenv("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    )
    nvidia_nim_model: str = Field(
        default_factory=lambda: os.getenv("NVIDIA_NIM_MODEL", "meta/llama-3.3-70b-instruct")
    )
    nvidia_nim_retry_attempts: int = Field(
        default_factory=lambda: int(os.getenv("NVIDIA_NIM_RETRY_ATTEMPTS", "3"))
    )

    # Provider API keys & endpoints
    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    openai_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    openai_base_url: str = Field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    )
    anthropic_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    anthropic_base_url: str = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
    )
    ollama_base_url: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    )

    # Tool sandbox configuration
    workspace_root: str = Field(default_factory=lambda: os.getcwd())
    enable_shell_execution: bool = Field(
        default_factory=lambda: os.getenv("LOKI_ENABLE_SHELL", "true").lower() == "true"
    )


# Global default configuration instance
settings = LokiConfig()
