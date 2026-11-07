"""
First-run security bootstrap for Loki.

Secrets are generated locally and stored outside the repository in a private,
per-user file. Users never need to copy signing keys or operator tokens by hand.
"""
from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path
from typing import Dict

from dotenv import dotenv_values

SECURITY_ENV_KEYS = ("LOKI_OPERATOR_TOKEN", "LOKI_AUTH_SIGNING_KEY")
_LOADED_FROM_FILE: Dict[str, str] = {}


def get_security_env_path() -> Path:
    """Return Loki's per-user private security file path."""
    configured = os.environ.get("LOKI_SECURITY_ENV_FILE")
    if configured and configured.strip():
        return Path(configured).expanduser()

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "Loki" / "security.env"
    return Path.home() / ".loki" / "security.env"


def _check_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.exists() and candidate.is_symlink():
            raise PermissionError(
                f"Refusing to use a symbolic link in the Loki security path: {candidate}"
            )


def load_security_environment() -> Path:
    """
    Load previously generated security secrets into the current process.
    Explicit process/.env variables take precedence over the per-user file.
    """
    path = get_security_env_path()
    _check_path(path)
    if path.exists():
        values = dotenv_values(path)
        for key in SECURITY_ENV_KEYS:
            value = values.get(key)
            if value and len(str(value).encode("utf-8")) >= 32 and not os.environ.get(key):
                os.environ[key] = str(value)
                _LOADED_FROM_FILE[key] = str(value)
    return path


def _write_private_file(path: Path, values: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _check_path(path)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)

    lines = [f"{key}={values[key]}\n" for key in SECURITY_ENV_KEYS if key in values]
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(str(temp_path), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def ensure_security_secrets() -> Dict[str, object]:
    """
    Ensure both required secrets exist, are strong, and are available in os.environ.

    Secrets explicitly supplied by the process environment are respected and are
    never copied into Loki's private file. Missing secrets are generated once.
    """
    path = load_security_environment()
    external_values: Dict[str, str] = {}
    stored: Dict[str, str] = {}
    if path.exists():
        values = dotenv_values(path)
        stored = {
            key: str(values[key])
            for key in SECURITY_ENV_KEYS
            if values.get(key)
        }

    created = []
    private_values: Dict[str, str] = {}
    for key in SECURITY_ENV_KEYS:
        current = os.environ.get(key, "").strip()
        loaded_from_file = bool(current) and _LOADED_FROM_FILE.get(key) == current
        external = current if current and not loaded_from_file else ""
        if external and len(external.encode("utf-8")) < 32:
            raise RuntimeError(
                f"{key} is configured but is shorter than 32 bytes. "
                "Provide a stronger secret or remove it to let Loki generate one."
            )

        if external:
            # Explicit process/.env values win, but are never copied into Loki's file.
            value = external
            if key in stored:
                private_values[key] = stored[key]
        else:
            value = stored.get(key, "")
            if value and len(value.encode("utf-8")) < 32:
                # A damaged/obsolete locally generated secret is safely rotated.
                value = ""
            if not value:
                value = secrets.token_urlsafe(48)
                created.append(key)
            private_values[key] = value

        os.environ[key] = value

    # Persist only locally generated or previously locally stored credentials.
    if private_values:
        _write_private_file(path, private_values)

    # config.py creates settings before CLI setup runs; refresh its cached token.
    try:
        from loki.config import settings
        settings.operator_token = os.environ["LOKI_OPERATOR_TOKEN"]
    except ImportError:
        pass

    return {"created": created, "path": path, "ready": True}
