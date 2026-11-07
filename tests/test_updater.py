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
            stdout = "a" * 40 if self.head_reads == 1 else "b" * 40
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
