"""
Factory to resolve the active platform execution adapter.
"""

from typing import Optional
from loki.platform.adapters.base import BasePlatformAdapter
from loki.platform.adapters.windows_adapter import WindowsPlatformAdapter
from loki.platform.adapters.linux_adapter import LinuxPlatformAdapter
from loki.platform.adapters.docker_adapter import DockerPlatformAdapter
from loki.platform.detector import PlatformDetector


def get_platform_adapter(preferred_adapter: Optional[str] = None) -> BasePlatformAdapter:
    """
    Returns the appropriate execution adapter based on OS detection or user preference:
    - "windows" -> WindowsPlatformAdapter
    - "linux" -> LinuxPlatformAdapter
    - "docker" -> DockerPlatformAdapter
    - None -> Auto-detect host OS
    """
    pref = (preferred_adapter or "").lower().strip()

    if pref == "docker" and PlatformDetector.check_docker_available():
        return DockerPlatformAdapter()

    os_type = PlatformDetector.get_os_type()

    if os_type == "windows":
        return WindowsPlatformAdapter()
    elif os_type in ("linux", "darwin"):
        return LinuxPlatformAdapter()

    # Fallback to Linux adapter as generic POSIX
    return LinuxPlatformAdapter()
