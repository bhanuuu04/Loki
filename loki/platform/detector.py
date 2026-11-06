"""
Cross-platform environment and runtime capability detection.
"""

import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, Optional
from pydantic import BaseModel


class SystemInfo(BaseModel):
    os_name: str          # "windows", "linux", "darwin"
    os_release: str       # e.g., "10.0.22631", "6.1.0-kali7-amd64"
    architecture: str     # "x86_64", "AMD64", "aarch64", "arm64"
    python_version: str   # e.g., "3.11.5", "3.14.4"
    is_wsl: bool          # Running inside WSL
    wsl_available: bool   # Running on Windows with WSL available
    docker_available: bool
    is_kali: bool


class PlatformDetector:
    """Detects host operating system, architecture, and available execution runtimes."""

    @staticmethod
    def get_os_type() -> str:
        system = platform.system().lower()
        if system.startswith("win"):
            return "windows"
        elif system.startswith("linux"):
            return "linux"
        elif system.startswith("darwin"):
            return "darwin"
        return system

    @staticmethod
    def is_inside_wsl() -> bool:
        if platform.system().lower() != "linux":
            return False
        # Check /proc/version or WSL_DISTRO_NAME
        if "WSL_DISTRO_NAME" in os.environ:
            return True
        try:
            if os.path.exists("/proc/version"):
                with open("/proc/version", "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    return "microsoft" in content or "wsl" in content
        except Exception:
            pass
        return False

    @staticmethod
    def is_kali_linux() -> bool:
        if platform.system().lower() != "linux":
            return False
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    return "kali" in content
        except Exception:
            pass
        return False

    @staticmethod
    def check_wsl_available() -> bool:
        """Checks if host is Windows and wsl.exe exists."""
        if platform.system().lower() != "windows":
            return False
        return shutil.which("wsl.exe") is not None or shutil.which("wsl") is not None

    @staticmethod
    def check_docker_available() -> bool:
        return shutil.which("docker") is not None

    @classmethod
    def detect(cls) -> SystemInfo:
        os_type = cls.get_os_type()
        is_wsl = cls.is_inside_wsl()
        wsl_avail = cls.check_wsl_available() if os_type == "windows" else False
        docker_avail = cls.check_docker_available()
        is_kali = cls.is_kali_linux()

        return SystemInfo(
            os_name=os_type,
            os_release=platform.release(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            is_wsl=is_wsl,
            wsl_available=wsl_avail,
            docker_available=docker_avail,
            is_kali=is_kali,
        )


# Singleton system inspection
current_system = PlatformDetector.detect()
