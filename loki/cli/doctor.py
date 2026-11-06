"""
Loki Doctor: Automated Cross-Platform System Health Diagnostic.
"""

from typing import Dict, List, Optional
import os
import sys
import shutil
import platform
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

from loki.config import settings
from loki.platform.detector import PlatformDetector, current_system
from loki.platform.adapters.factory import get_platform_adapter
from loki.knowledge.tool_registry.catalog import SecurityToolCatalog

console = Console(force_terminal=True)


class DiagnosticItem:
    def __init__(self, category: str, name: str, status: str, details: str):
        self.category = category
        self.name = name
        self.status = status  # PASS, WARN, FAIL
        self.details = details


class LokiDoctor:
    """Runs end-to-end system diagnostics across OS, Python, dependencies, and providers."""

    @classmethod
    async def run_diagnostics(cls) -> List[DiagnosticItem]:
        items: List[DiagnosticItem] = []

        # 1. Environment & OS
        os_info = f"{current_system.os_name.capitalize()} ({current_system.os_release}) on {current_system.architecture}"
        items.append(DiagnosticItem("System", "Operating System", "PASS", os_info))

        # Python Version
        py_ver = sys.version.split()[0]
        py_status = "PASS" if sys.version_info >= (3, 10) else "FAIL"
        items.append(DiagnosticItem("System", "Python Version", py_status, f"{py_ver} (>= 3.10 required)"))

        # 2. Virtual Environment & Dependencies
        required_pkgs = ["pydantic", "httpx", "rich", "fastapi", "uvicorn", "dotenv"]
        missing_pkgs = []
        for pkg in required_pkgs:
            try:
                __import__(pkg)
            except ImportError:
                missing_pkgs.append(pkg)

        if not missing_pkgs:
            items.append(DiagnosticItem("Dependencies", "Python Packages", "PASS", "All core dependencies installed"))
        else:
            items.append(DiagnosticItem("Dependencies", "Python Packages", "FAIL", f"Missing: {', '.join(missing_pkgs)}"))

        # 3. Execution Adapters (Windows/WSL/Docker/Linux)
        adapter = get_platform_adapter()
        items.append(DiagnosticItem("Execution", "Active Platform Adapter", "PASS", f"{adapter.name}"))

        if current_system.os_name == "windows":
            if current_system.wsl_available:
                items.append(DiagnosticItem("Execution", "WSL2 Subsystem", "PASS", "WSL2 executable available on PATH"))
            else:
                items.append(DiagnosticItem("Execution", "WSL2 Subsystem", "WARN", "WSL2 not detected. Linux tools require native Windows binaries or Docker."))

        if current_system.docker_available:
            items.append(DiagnosticItem("Execution", "Docker Runtime", "PASS", "Docker executable discovered on PATH"))
        else:
            items.append(DiagnosticItem("Execution", "Docker Runtime", "WARN", "Docker not installed (optional for isolated execution)"))

        # 4. Storage & Filesystem Permissions
        storage_dirs = [Path.cwd() / "assessments", Path.cwd() / "reports", Path.cwd() / "logs"]
        storage_ok = True
        for d in storage_dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                test_file = d / ".health_check"
                test_file.write_text("ok", encoding="utf-8")
                test_file.unlink()
            except Exception:
                storage_ok = False
                break

        if storage_ok:
            items.append(DiagnosticItem("Storage", "Directory Permissions", "PASS", "Assessments, reports & logs directories writable"))
        else:
            items.append(DiagnosticItem("Storage", "Directory Permissions", "FAIL", "Permission error creating/writing to data directories"))

        # 5. Security Tool Catalog
        catalog = SecurityToolCatalog()
        tools = catalog.list_tools()
        installed_tools = [t for t in tools if t.is_installed]
        catalog_details = f"{len(installed_tools)} installed out of {len(tools)} documented security tools"
        cat_status = "PASS" if len(installed_tools) > 0 else "WARN"
        items.append(DiagnosticItem("Tools", "Security Tool Catalog", cat_status, catalog_details))

        # 6. LLM Provider & NVIDIA NIM Status
        active_provider = settings.default_provider
        items.append(DiagnosticItem("LLM", "Default Provider", "PASS", f"{active_provider} (Model: {settings.default_model})"))

        if settings.nvidia_nim_api_key:
            items.append(DiagnosticItem("LLM", "NVIDIA NIM Auth", "PASS", f"Key configured (Base: {settings.nvidia_nim_base_url})"))
        else:
            items.append(DiagnosticItem("LLM", "NVIDIA NIM Auth", "WARN", "NVIDIA_NIM_API_KEY not set (set in .env for NVIDIA NIM models)"))

        return items

    @classmethod
    def display_report(cls, items: List[DiagnosticItem]) -> bool:
        console.print("\n[bold cyan]─── LOKI SYSTEM DIAGNOSTIC (DOCTOR) ───[/bold cyan]\n")

        table = Table(box=box.ASCII_DOUBLE_HEAD)
        table.add_column("Category", style="dim", width=14)
        table.add_column("Component", width=24)
        table.add_column("Status", width=10)
        table.add_column("Details")

        has_fail = False
        for it in items:
            if it.status == "PASS":
                status_styled = "[bold green]PASS[/bold green]"
            elif it.status == "WARN":
                status_styled = "[bold yellow]WARN[/bold yellow]"
            else:
                status_styled = "[bold red]FAIL[/bold red]"
                has_fail = True

            table.add_row(it.category, it.name, status_styled, it.details)

        console.print(table)
        
        if has_fail:
            console.print("\n[bold red]Result: FAIL[/bold red] - Some critical components require attention.\n")
        else:
            console.print("\n[bold green]Result: PASS[/bold green] - Loki core environment is healthy and ready to operate.\n")

        return not has_fail
