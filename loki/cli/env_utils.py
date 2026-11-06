"""
Utility functions for updating and managing .env configuration.
"""

from pathlib import Path
import shutil


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


def reset_configuration() -> None:
    """Resets local .env configuration back to .env.example defaults."""
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        env_path.unlink()
    example_path = Path.cwd() / ".env.example"
    if example_path.exists():
        shutil.copy(example_path, env_path)
