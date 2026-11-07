from pathlib import Path

from loki.cli.updater import LokiUpdater


class FakeGitRunner:
    def __init__(
        self,
        repo: Path,
        *,
        branch="main",
        status="",
        ahead_behind="0 2",
        remote_url="https://github.com/bhanuuu04/Loki.git",
        pip_returncode=0,
    ):
        self.repo = repo
        self.branch = branch
        self.status = status
        self.ahead_behind = ahead_behind
        self.remote_url = remote_url
        self.pip_returncode = pip_returncode
        self.commands = []
        self.head_reads = 0

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[0] != "git":
            return_code = self.pip_returncode
            return type(
                "Result",
                (),
                {
                    "returncode": return_code,
                    "stdout": "Successfully installed loki-agent",
                    "stderr": "" if return_code == 0 else "pip dependency resolution failed",
                },
            )()

        args = command[1:]
        stdout = ""
        returncode = 0
        if args == ["rev-parse", "--show-toplevel"]:
            stdout = str(self.repo)
        elif args == ["remote", "get-url", "origin"]:
            stdout = self.remote_url
        elif args == ["branch", "--show-current"]:
            stdout = self.branch
        elif args == ["status", "--porcelain", "--untracked-files=normal"]:
            stdout = self.status
        elif args == ["rev-parse", "HEAD"]:
            self.head_reads += 1
            stdout = ("b" * 40) if self.ahead_behind == "0 0" else ("a" * 40 if self.head_reads == 1 else "b" * 40)
        elif args == ["fetch", "--prune", "origin"]:
            stdout = "Fetched origin"
        elif args == ["rev-parse", "--verify", "refs/remotes/origin/main"]:
            stdout = "b" * 40
        elif args == ["rev-list", "--left-right", "--count", "HEAD...origin/main"]:
            stdout = self.ahead_behind
        elif args == ["merge", "--ff-only", "origin/main"]:
            stdout = "Fast-forward"
        else:
            returncode = 1
            stderr = f"Unexpected test command: {command}"
            return type(
                "Result",
                (),
                {"returncode": returncode, "stdout": "", "stderr": stderr},
            )()

        return type(
            "Result",
            (),
            {"returncode": returncode, "stdout": stdout, "stderr": ""},
        )()


def test_accepts_only_official_github_repository_urls():
    assert LokiUpdater.is_official_remote(
        "https://github.com/bhanuuu04/Loki.git"
    )
    assert LokiUpdater.is_official_remote(
        "git@github.com:bhanuuu04/Loki.git"
    )
    assert LokiUpdater.is_official_remote(
        "ssh://git@github.com/bhanuuu04/Loki.git"
    )
    assert not LokiUpdater.is_official_remote(
        "https://github.com.evil.example/bhanuuu04/Loki.git"
    )
    assert not LokiUpdater.is_official_remote(
        "https://github.com/someone-else/Loki.git"
    )


def test_update_fast_forwards_and_refreshes_editable_install(tmp_path):
    runner = FakeGitRunner(tmp_path)
    updater = LokiUpdater(
        repo_dir=tmp_path,
        command_runner=runner,
        python_executable="python-test",
    )

    result = updater.run()

    assert result.success
    assert result.updated
    assert result.state == "updated"
    assert result.current_commit == "b" * 40
    assert result.dependencies_ok is True
    assert any(
        cmd[:4] == ["git", "merge", "--ff-only", "origin/main"]
        for cmd in runner.commands
    )
    assert any(
        cmd[:4] == ["python-test", "-m", "pip", "install"]
        and "--upgrade" in cmd
        and "-e" in cmd
        for cmd in runner.commands
    )
    assert not any("reset" in cmd or "--hard" in cmd for cmd in runner.commands)


def test_refuses_to_overwrite_dirty_worktree(tmp_path):
    runner = FakeGitRunner(tmp_path, status=" M README.md\n?? local-notes.txt")
    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)

    result = updater.run()

    assert not result.success
    assert "local changes" in result.message
    assert not any(cmd[1:3] == ["fetch", "--prune"] for cmd in runner.commands)
    assert not any("merge" in cmd for cmd in runner.commands)


def test_refuses_non_official_remote(tmp_path):
    runner = FakeGitRunner(
        tmp_path,
        remote_url="https://github.com/attacker/Loki.git",
    )
    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)

    result = updater.run()

    assert not result.success
    assert "not the official" in result.message
    assert not any("fetch" in cmd for cmd in runner.commands)


def test_refuses_to_switch_non_main_branch(tmp_path):
    runner = FakeGitRunner(tmp_path, branch="my-feature")
    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)

    result = updater.run()

    assert not result.success
    assert "not 'main'" in result.message
    assert not any("fetch" in cmd for cmd in runner.commands)


def test_refuses_diverged_history_without_reset_or_rebase(tmp_path):
    runner = FakeGitRunner(tmp_path, ahead_behind="2 3")
    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)

    result = updater.run(skip_dependencies=True)

    assert not result.success
    assert "diverged" in result.message
    assert not any("merge" in cmd or "rebase" in cmd or "reset" in cmd for cmd in runner.commands)


def test_check_only_reports_available_commits_without_installing(tmp_path):
    runner = FakeGitRunner(tmp_path, ahead_behind="0 4")
    updater = LokiUpdater(
        repo_dir=tmp_path,
        command_runner=runner,
        python_executable="python-test",
    )

    result = updater.run(check_only=True)

    assert result.success
    assert result.state == "update_available"
    assert "4 upstream commit(s)" in result.message
    assert not any("merge" in cmd for cmd in runner.commands)
    assert not any(cmd[0] == "python-test" for cmd in runner.commands)


def test_dependency_failure_is_reported_after_source_update(tmp_path):
    runner = FakeGitRunner(tmp_path, pip_returncode=1)
    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)

    result = updater.run()

    assert not result.success
    assert result.updated
    assert result.state == "dependency_error"
    assert result.dependencies_ok is False
    assert "dependency installation failed" in result.message



def test_up_to_date_checkout_still_refreshes_declared_dependencies(tmp_path):
    runner = FakeGitRunner(tmp_path, ahead_behind="0 0")
    updater = LokiUpdater(
        repo_dir=tmp_path,
        command_runner=runner,
        python_executable="python-test",
    )

    result = updater.run()

    assert result.success
    assert not result.updated
    assert result.state == "up_to_date"
    assert result.dependencies_ok is True
    assert any(cmd[0] == "python-test" for cmd in runner.commands)
    assert not any("merge" in cmd for cmd in runner.commands)


def test_local_commits_ahead_of_official_main_are_preserved(tmp_path):
    runner = FakeGitRunner(tmp_path, ahead_behind="2 0")
    updater = LokiUpdater(
        repo_dir=tmp_path,
        command_runner=runner,
        python_executable="python-test",
    )

    result = updater.run(skip_dependencies=True)

    assert result.success
    assert not result.updated
    assert any("unpushed commit(s)" in item for item in result.details)
    assert not any("merge" in cmd or "reset" in cmd for cmd in runner.commands)



def test_cli_entrypoint_accepts_loki_update_check(monkeypatch):
    import sys
    from loki.cli import main as cli_main
    from loki.cli import updater as updater_module
    from loki.cli.updater import UpdateResult

    calls = {}

    class StubUpdater:
        def run(self, *, check_only=False, skip_dependencies=False):
            calls["check_only"] = check_only
            calls["skip_dependencies"] = skip_dependencies
            return UpdateResult(
                success=True,
                state="update_available",
                message="2 upstream commit(s) are available.",
                current_commit="a" * 40,
                latest_commit="b" * 40,
            )

    monkeypatch.setattr(sys, "argv", ["loki", "update", "--check"])
    monkeypatch.setattr(updater_module, "LokiUpdater", StubUpdater)

    cli_main.cli_entrypoint()

    assert calls == {"check_only": True, "skip_dependencies": False}



def test_updater_prefers_active_virtualenv_python(tmp_path, monkeypatch):
    import os
    import sys

    venv = tmp_path / ".venv"
    if os.name == "nt":
        executable = venv / "Scripts" / "python.exe"
        system_python = "C:/Python/python.exe"
    else:
        executable = venv / "bin" / "python"
        system_python = "/usr/bin/python3"
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")
    (venv / "pyvenv.cfg").write_text("home = system-python", encoding="utf-8")

    monkeypatch.setenv("VIRTUAL_ENV", str(venv))
    monkeypatch.setattr(sys, "executable", system_python)

    updater = LokiUpdater(repo_dir=tmp_path)

    assert updater.python_executable == str(executable)
    assert updater.using_active_environment is True
    assert updater.externally_managed_python is False


def test_updater_uses_conda_environment_python_when_active(tmp_path, monkeypatch):
    import os

    venv = tmp_path / "conda-env"
    if os.name == "nt":
        executable = venv / "python.exe"
    else:
        executable = venv / "bin" / "python"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("", encoding="utf-8")
    (venv / "conda-meta").mkdir()

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.setenv("CONDA_PREFIX", str(venv))

    updater = LokiUpdater(repo_dir=tmp_path)

    assert updater.python_executable == str(executable)
    assert updater.using_active_environment is True


def test_pep668_system_python_fails_with_virtualenv_guidance_without_running_pip(
    tmp_path, monkeypatch
):
    import sys
    import sysconfig

    runner = FakeGitRunner(tmp_path, ahead_behind="0 0")
    stdlib = tmp_path / "python" / "lib"
    stdlib.mkdir(parents=True)
    (stdlib / "EXTERNALLY-MANAGED").write_text("managed by OS", encoding="utf-8")

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    monkeypatch.setattr(sys, "prefix", "/usr")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    monkeypatch.setattr(sysconfig, "get_path", lambda _name: str(stdlib))

    updater = LokiUpdater(repo_dir=tmp_path, command_runner=runner)
    result = updater.run()

    assert not result.success
    assert result.state == "dependency_error"
    assert result.dependencies_ok is False
    assert any("PEP 668" in item for item in result.details)
    assert any("source .venv/bin/activate" in item for item in result.details)
    assert not any(command[0] != "git" for command in runner.commands)


def test_cli_update_runs_doctor_with_the_selected_environment_python(
    tmp_path, monkeypatch
):
    import sys
    from types import SimpleNamespace

    from loki.cli import main as cli_main
    from loki.cli import updater as updater_module
    from loki.cli.updater import UpdateResult

    calls = {}

    class StubUpdater:
        repo_dir = tmp_path
        python_executable = str(tmp_path / ".venv" / "bin" / "python")

        def run(self, *, check_only=False, skip_dependencies=False):
            return UpdateResult(
                success=True,
                state="up_to_date",
                message="Loki source is current; dependencies were checked and refreshed.",
                current_commit="a" * 40,
                latest_commit="a" * 40,
                dependencies_ok=True,
            )

    def fake_subprocess_run(command, **kwargs):
        calls["command"] = command
        calls["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(sys, "argv", ["loki", "update"])
    monkeypatch.setattr(updater_module, "LokiUpdater", StubUpdater)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_subprocess_run)

    cli_main.cli_entrypoint()

    assert calls["command"] == [
        StubUpdater.python_executable,
        "-m",
        "loki.cli.main",
        "doctor",
    ]
    assert calls["cwd"] == str(tmp_path)
