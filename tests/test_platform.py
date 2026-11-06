import sys
import pytest
from loki.platform.detector import PlatformDetector, current_system
from loki.platform.adapters.factory import get_platform_adapter
from loki.platform.adapters.windows_adapter import WindowsPlatformAdapter
from loki.platform.adapters.linux_adapter import LinuxPlatformAdapter


def test_platform_detector():
    info = PlatformDetector.detect()
    assert info.os_name in ("windows", "linux", "darwin")
    assert len(info.architecture) > 0
    assert len(info.python_version) > 0


def test_platform_adapter_resolution():
    adapter = get_platform_adapter()
    assert adapter is not None
    assert adapter.name in ("windows_native", "linux_native", "docker_isolated")

    # On Windows, adapter should be windows_native
    if current_system.os_name == "windows":
        assert isinstance(adapter, WindowsPlatformAdapter)
    elif current_system.os_name == "linux":
        assert isinstance(adapter, LinuxPlatformAdapter)


def test_python_executable_lookup():
    adapter = get_platform_adapter()
    # Python should be discoverable by any platform adapter
    py_path = adapter.find_tool_binary("python")
    assert py_path is not None


def test_platform_install_instructions():
    adapter = get_platform_adapter()
    hint = adapter.get_install_instruction("nmap")
    assert len(hint) > 0
    if current_system.os_name == "windows":
        assert "winget" in hint or "apt" in hint
    else:
        assert "apt" in hint
