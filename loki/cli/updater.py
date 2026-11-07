"""Safe self-update support for Loki's official Git checkout."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import re
import subprocess
import sys
import sysconfig
from typing import Callable, List, Optional
from urllib.parse import urlparse


OFFICIAL_GITHUB_HOST = "github.com"
OFFICIAL_REPOSITORY_PATH = "bhanuuu04/loki"
DEFAULT_BRANCH = "main"


@dataclass
class UpdateResult:
    """Outcome of a Loki update attempt."""

    success: bool
    state: str
    message: str
    current_commit: str = ""
    latest_commit: str = ""
    updated: bool = False
    dependencies_ok: Optional[bool] = None
    details: List[str] = field(default_factory=list)


class UpdateError(RuntimeError):
    """A safe update could not continue."""


def _active_environment_python() -> Optional[str]:
    """Return the Python executable in the shell's active venv/Conda environment."""
    prefix = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")
    if not prefix:
        return None

    environment_dir = Path(prefix).expanduser()
    if os.name == "nt":
        candidates = [environment_dir / "Scripts" / "python.exe"]
    else:
        candidates = [
            environment_dir / "bin" / "python",
            environment_dir / "bin" / "python3",
        ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def _is_externally_managed_system_python() -> bool:
    """Detect PEP 668 only for the base interpreter, never for a virtualenv."""
    if sys.prefix != sys.base_prefix:
        return False
    stdlib = sysconfig.get_path("stdlib")
    return bool(stdlib and (Path(stdlib) / "EXTERNALLY-MANAGED").is_file())


class LokiUpdater:
    """Fast-forward-only updater for an official Loki source checkout.

    The updater never stashes, resets, force-checks out, or overwrites local
    changes. It refuses dirty worktrees and diverged/non-main branches.
    """

    def __init__(
        self,
        repo_dir: Optional[Path] = None,
        command_runner: Callable = subprocess.run,
        python_executable: Optional[str] = None,
        branch: str = DEFAULT_BRANCH,
    ) -> None:
        self.repo_dir = Path(repo_dir or Path(__file__).resolve().parents[2]).resolve()
        self.command_runner = command_runner
        active_python = _active_environment_python()
        self.using_active_environment = bool(active_python)
        self.python_executable = (
            python_executable
            or active_python
            or sys.executable
        )
        self.externally_managed_python = (
            not python_executable
            and not active_python
            and _is_externally_managed_system_python()
        )
        self.branch = branch

    @staticmethod
    def is_official_remote(remote_url: str) -> bool:
        """Accept only canonical HTTPS/SSH URLs for the official GitHub repo."""
        value = (remote_url or "").strip()
        if not value:
            return False

        # Git's SCP-like SSH syntax is not understood by urlparse.
        scp_match = re.fullmatch(
            r"(?:git@)?github\.com:([^/]+/[^/]+?)(?:\.git)?/?",
            value,
            flags=re.IGNORECASE,
        )
        if scp_match:
            path = scp_match.group(1)
            return path.lower() == OFFICIAL_REPOSITORY_PATH

        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "ssh"}:
            return False
        if (parsed.hostname or "").lower() != OFFICIAL_GITHUB_HOST:
            return False
        if parsed.password or parsed.query or parsed.fragment:
            return False
        if scheme == "https" and parsed.username:
            return False
        if scheme == "ssh" and parsed.username not in (None, "git"):
            return False
        path = parsed.path.strip("/").removesuffix(".git")
        return path.lower() == OFFICIAL_REPOSITORY_PATH

    def _run(
        self,
        command: List[str],
        *,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess:
        try:
            return self.command_runner(
                command,
                cwd=str(self.repo_dir),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            executable = command[0] if command else "command"
            raise UpdateError(
                f"Required executable '{executable}' was not found. "
                "Install Git and ensure it is available on PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise UpdateError(
                f"Command timed out after {timeout} seconds: {' '.join(command[:4])}"
            ) from exc
        except OSError as exc:
            raise UpdateError(f"Could not execute update command: {exc}") from exc

    def _git(self, *args: str, timeout: int = 120) -> str:
        result = self._run(["git", *args], timeout=timeout)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "No details returned").strip()
            raise UpdateError(
                f"Git command failed ({' '.join(args)}): {detail[:1200]}"
            )
        return (result.stdout or "").strip()

    def run(
        self,
        *,
        check_only: bool = False,
        skip_dependencies: bool = False,
    ) -> UpdateResult:
        """Fetch official main, fast-forward if safe, refresh deps, and report."""
        details: List[str] = []
        current_commit = ""
        latest_commit = ""
        updated = False
        dependency_ok: Optional[bool] = None

        try:
            root = Path(self._git("rev-parse", "--show-toplevel")).resolve()
            if root != self.repo_dir:
                self.repo_dir = root

            remote_url = self._git("remote", "get-url", "origin")
            if not self.is_official_remote(remote_url):
                raise UpdateError(
                    "The 'origin' remote is not the official "
                    "https://github.com/bhanuuu04/Loki repository. "
                    "No files were changed."
                )

            current_branch = self._git("branch", "--show-current")
            if current_branch != self.branch:
                raise UpdateError(
                    f"You are on branch '{current_branch or 'detached HEAD'}', not "
                    f"'{self.branch}'. Switch to {self.branch} and rerun 'loki update'. "
                    "Loki will not switch branches or overwrite your work."
                )

            if not check_only:
                worktree_status = self._git(
                    "status", "--porcelain", "--untracked-files=normal"
                )
                if worktree_status:
                    preview = "\n".join(worktree_status.splitlines()[:12])
                    raise UpdateError(
                        "Your working tree has local changes. Loki left them untouched. "
                        "Commit or stash your changes, then rerun 'loki update'.\n"
                        f"{preview}"
                    )

            current_commit = self._git("rev-parse", "HEAD")
            self._git("fetch", "--prune", "origin", timeout=300)
            latest_commit = self._git(
                "rev-parse", "--verify", f"refs/remotes/origin/{self.branch}"
            )

            counts = self._git(
                "rev-list", "--left-right", "--count",
                f"HEAD...origin/{self.branch}",
            ).split()
            if len(counts) != 2:
                raise UpdateError("Git returned an unexpected ahead/behind count.")
            local_ahead, remote_ahead = (int(counts[0]), int(counts[1]))

            if check_only:
                if remote_ahead:
                    return UpdateResult(
                        success=True,
                        state="update_available",
                        message=f"{remote_ahead} upstream commit(s) are available.",
                        current_commit=current_commit,
                        latest_commit=latest_commit,
                        details=details,
                    )
                return UpdateResult(
                    success=True,
                    state="up_to_date",
                    message="This checkout already contains the latest official main commit.",
                    current_commit=current_commit,
                    latest_commit=latest_commit,
                    details=details,
                )

            if local_ahead and remote_ahead:
                raise UpdateError(
                    "Your local main branch and official main have diverged. "
                    "Loki will not rebase, reset, or merge automatically. Resolve "
                    "the branch history manually, then rerun the updater."
                )

            if remote_ahead:
                self._git("merge", "--ff-only", f"origin/{self.branch}", timeout=300)
                updated = True
                details.append(
                    f"Fast-forwarded {remote_ahead} commit(s) from official {self.branch}."
                )
            elif local_ahead:
                details.append(
                    "Local main contains unpushed commit(s) and already includes the latest official main."
                )
            else:
                details.append("Source checkout is already up to date.")

            current_commit = self._git("rev-parse", "HEAD")

            if not skip_dependencies:
                if self.externally_managed_python:
                    dependency_ok = False
                    details.append(
                        "Dependency refresh was not attempted: this is a PEP 668 "
                        "externally managed system Python. Activate Loki's virtual "
                        "environment and rerun 'loki update'. Example: "
                        "'source .venv/bin/activate && python -m pip install --upgrade -e .'."
                    )
                else:
                    if self.using_active_environment:
                        details.append(
                            f"Using active environment interpreter: {self.python_executable}"
                        )
                    pip_result = self._run(
                        [
                            self.python_executable,
                            "-m",
                            "pip",
                            "install",
                            "--upgrade",
                            "-e",
                            ".",
                        ],
                        timeout=600,
                    )
                    dependency_ok = pip_result.returncode == 0
                    if dependency_ok:
                        details.append("Editable install and declared dependencies refreshed.")
                    else:
                        detail = (
                            pip_result.stderr or pip_result.stdout or "No pip output returned"
                        ).strip()
                        details.append(
                            "Dependency refresh failed: " + detail[-1600:]
                        )
            else:
                details.append("Dependency refresh skipped by operator.")

            if dependency_ok is False:
                return UpdateResult(
                    success=False,
                    state="dependency_error",
                    message=(
                        "Source update completed, but dependency installation failed. "
                        "Review the pip error and run 'loki doctor'."
                    ),
                    current_commit=current_commit,
                    latest_commit=latest_commit,
                    updated=updated,
                    dependencies_ok=False,
                    details=details,
                )

            return UpdateResult(
                success=True,
                state="updated" if updated else "up_to_date",
                message=(
                    "Loki source and dependencies are updated."
                    if updated
                    else "Loki source is current; dependencies were checked and refreshed."
                ),
                current_commit=current_commit,
                latest_commit=latest_commit,
                updated=updated,
                dependencies_ok=dependency_ok,
                details=details,
            )

        except UpdateError as exc:
            return UpdateResult(
                success=False,
                state="blocked_or_failed",
                message=str(exc),
                current_commit=current_commit,
                latest_commit=latest_commit,
                updated=updated,
                dependencies_ok=dependency_ok,
                details=details,
            )
        except (ValueError, TypeError) as exc:
            return UpdateResult(
                success=False,
                state="error",
                message=f"Unexpected update metadata error: {exc}",
                current_commit=current_commit,
                latest_commit=latest_commit,
                updated=updated,
                dependencies_ok=dependency_ok,
                details=details,
            )
