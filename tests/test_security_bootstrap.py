from __future__ import annotations

import os
import pytest
from dotenv import dotenv_values

from loki.security_bootstrap import ensure_security_secrets, get_security_env_path, load_security_environment


def _clear_security_env(monkeypatch):
    monkeypatch.delenv("LOKI_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("LOKI_AUTH_SIGNING_KEY", raising=False)


def test_first_run_generates_private_independent_secrets(tmp_path, monkeypatch):
    from loki.config import settings
    monkeypatch.setattr(settings, "operator_token", settings.operator_token)
    secret_path = tmp_path / "profile" / "security.env"
    monkeypatch.setenv("LOKI_SECURITY_ENV_FILE", str(secret_path))
    _clear_security_env(monkeypatch)

    result = ensure_security_secrets()

    assert result["ready"] is True
    assert set(result["created"]) == {"LOKI_OPERATOR_TOKEN", "LOKI_AUTH_SIGNING_KEY"}
    assert os.environ["LOKI_OPERATOR_TOKEN"]
    assert os.environ["LOKI_AUTH_SIGNING_KEY"]
    assert os.environ["LOKI_OPERATOR_TOKEN"] != os.environ["LOKI_AUTH_SIGNING_KEY"]
    assert len(os.environ["LOKI_OPERATOR_TOKEN"].encode("utf-8")) >= 32
    assert len(os.environ["LOKI_AUTH_SIGNING_KEY"].encode("utf-8")) >= 32
    assert secret_path.is_file()
    assert not (tmp_path / ".env").exists()

    values = dotenv_values(secret_path)
    assert values["LOKI_OPERATOR_TOKEN"] == os.environ["LOKI_OPERATOR_TOKEN"]
    assert values["LOKI_AUTH_SIGNING_KEY"] == os.environ["LOKI_AUTH_SIGNING_KEY"]

    if os.name != "nt":
        assert secret_path.stat().st_mode & 0o777 == 0o600
        assert secret_path.parent.stat().st_mode & 0o777 == 0o700


def test_first_run_is_idempotent_and_reuses_saved_secrets(tmp_path, monkeypatch):
    from loki.config import settings
    monkeypatch.setattr(settings, "operator_token", settings.operator_token)
    secret_path = tmp_path / "security.env"
    monkeypatch.setenv("LOKI_SECURITY_ENV_FILE", str(secret_path))
    _clear_security_env(monkeypatch)

    ensure_security_secrets()
    operator_token = os.environ["LOKI_OPERATOR_TOKEN"]
    signing_key = os.environ["LOKI_AUTH_SIGNING_KEY"]

    monkeypatch.delenv("LOKI_OPERATOR_TOKEN")
    monkeypatch.delenv("LOKI_AUTH_SIGNING_KEY")
    loaded_path = load_security_environment()

    assert loaded_path == secret_path
    assert os.environ["LOKI_OPERATOR_TOKEN"] == operator_token
    assert os.environ["LOKI_AUTH_SIGNING_KEY"] == signing_key

    result = ensure_security_secrets()
    assert result["created"] == []
    assert os.environ["LOKI_OPERATOR_TOKEN"] == operator_token
    assert os.environ["LOKI_AUTH_SIGNING_KEY"] == signing_key


def test_external_secrets_are_respected_but_not_copied_to_local_file(tmp_path, monkeypatch):
    from loki.config import settings
    monkeypatch.setattr(settings, "operator_token", settings.operator_token)
    secret_path = tmp_path / "security.env"
    monkeypatch.setenv("LOKI_SECURITY_ENV_FILE", str(secret_path))
    operator_token = "externally-provisioned-operator-token-0123456789"
    signing_key = "externally-provisioned-signing-key-0123456789"
    monkeypatch.setenv("LOKI_OPERATOR_TOKEN", operator_token)
    monkeypatch.setenv("LOKI_AUTH_SIGNING_KEY", signing_key)

    result = ensure_security_secrets()

    assert result["created"] == []
    assert os.environ["LOKI_OPERATOR_TOKEN"] == operator_token
    assert os.environ["LOKI_AUTH_SIGNING_KEY"] == signing_key
    assert not secret_path.exists()


def test_weak_external_secret_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LOKI_SECURITY_ENV_FILE", str(tmp_path / "security.env"))
    monkeypatch.setenv("LOKI_OPERATOR_TOKEN", "short")
    monkeypatch.delenv("LOKI_AUTH_SIGNING_KEY", raising=False)

    with pytest.raises(RuntimeError, match="LOKI_OPERATOR_TOKEN"):
        ensure_security_secrets()


def test_security_file_symlink_is_rejected(tmp_path, monkeypatch):
    target = tmp_path / "target.env"
    target.write_text("LOKI_OPERATOR_TOKEN=" + "a" * 48 + "\n", encoding="utf-8")
    secret_path = tmp_path / "security.env"
    try:
        secret_path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not available for this test environment")

    monkeypatch.setenv("LOKI_SECURITY_ENV_FILE", str(secret_path))
    _clear_security_env(monkeypatch)
    with pytest.raises(PermissionError, match="symbolic link"):
        ensure_security_secrets()
