import pytest
from pathlib import Path
from loki.cli.env_utils import update_env_file, reset_configuration
from loki.cli.model_cmd import NVIDIA_FEATURED_MODELS


def test_featured_models_catalog():
    assert len(NVIDIA_FEATURED_MODELS) >= 5
    model_ids = [m[0] for m in NVIDIA_FEATURED_MODELS]
    assert "meta/llama-3.3-70b-instruct" in model_ids
    assert "nvidia/llama-3.1-nemotron-70b-instruct" in model_ids


def test_env_utils_lifecycle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Test update
    update_env_file({"TEST_KEY": "test_val", "LOKI_MODEL": "meta/llama-3.3-70b-instruct"})
    env_content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "TEST_KEY=test_val" in env_content
    assert "LOKI_MODEL=meta/llama-3.3-70b-instruct" in env_content

    # Test updating existing key
    update_env_file({"TEST_KEY": "updated_val"})
    env_content_updated = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "TEST_KEY=updated_val" in env_content_updated
    assert "TEST_KEY=test_val" not in env_content_updated

    # Test reset
    (tmp_path / ".env.example").write_text("DEFAULT_SETTING=123\n", encoding="utf-8")
    reset_configuration()
    reset_content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "DEFAULT_SETTING=123" in reset_content


def test_select_from_menu_non_tty(monkeypatch):
    import sys
    from loki.cli.menu import select_from_menu
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    idx = select_from_menu("Test Menu", ["Option A", "Option B", "Option C"], default_index=1)
    assert idx == 1
