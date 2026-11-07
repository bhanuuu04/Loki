import json

import pytest

from loki.knowledge.tool_registry.kali_catalog import (
    CACHE_SCHEMA_VERSION,
    KaliToolIndex,
    KaliToolRecord,
    parse_kali_tools_html,
)


def _catalogue_row(name, package, binary):
    return (
        f'<li><a href="https://www.kali.org/tools/{name}/">{name}</a>'
        f'<ul><li><a href="https://pkg.kali.org/pkg/{package}">{package}</a>'
        f'<ul><li>$ {binary}</li></ul></li></ul></li>'
    )


def test_parser_extracts_tool_packages_commands_and_docs():
    html = """
    <ul>
      <li><a href="https://www.kali.org/tools/aircrack-ng/">aircrack-ng</a>
        <ul>
          <li><a href="https://pkg.kali.org/pkg/aircrack-ng">aircrack-ng</a>
            <ul><li>$ aircrack-ng</li><li>$ airodump-ng</li></ul>
          </li>
        </ul>
      </li>
      <li><a href="https://www.kali.org/tools/ffuf/">ffuf $</a></li>
    </ul>
    """
    records = parse_kali_tools_html(html)
    by_name = {record.name: record for record in records}

    assert "aircrack-ng" in by_name
    assert by_name["aircrack-ng"].category == "wireless"
    assert "aircrack-ng" in by_name["aircrack-ng"].packages
    assert "airodump-ng" in by_name["aircrack-ng"].binaries
    assert by_name["aircrack-ng"].documentation_url == "https://www.kali.org/tools/aircrack-ng/"
    assert "ffuf" in by_name


def test_parser_handles_more_than_500_official_tool_entries():
    html = "<ul>" + "".join(
        _catalogue_row(f"tool-{i:03d}", f"package-{i:03d}", f"binary-{i:03d}")
        for i in range(501)
    ) + "</ul>"

    records = parse_kali_tools_html(html)

    assert len(records) == 501
    assert records[0].name == "tool-000"
    assert records[-1].name == "tool-500"
    assert records[250].binaries == ["binary-250"]


def _write_cache(path, records):
    payload = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "source_url": "https://www.kali.org/tools/all-tools/",
        "fetched_at": "2026-11-07T00:00:00+00:00",
        "tool_count": len(records),
        "tools": [record.model_dump() for record in records],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_index_searches_by_binary_package_and_category(tmp_path, monkeypatch):
    records = [
        KaliToolRecord(
            name="nmap",
            packages=["nmap"],
            binaries=["nmap"],
            category="information_gathering",
            summary="Network discovery and port scanning tool.",
        ),
        KaliToolRecord(
            name="aircrack-ng",
            packages=["aircrack-ng"],
            binaries=["aircrack-ng", "airodump-ng"],
            category="wireless",
            summary="Wireless network auditing toolkit.",
        ),
        KaliToolRecord(
            name="ffuf",
            packages=["ffuf"],
            binaries=["ffuf"],
            category="web_application",
            summary="Web content and endpoint fuzzing tool.",
        ),
    ]
    cache_path = tmp_path / "kali-tools.json"
    _write_cache(cache_path, records)
    index = KaliToolIndex(str(cache_path))

    monkeypatch.setattr(
        "loki.knowledge.tool_registry.kali_catalog.shutil.which",
        lambda binary: f"/usr/bin/{binary}" if binary == "nmap" else None,
    )

    nmap_results = index.search("port scanning", limit=5)
    assert nmap_results[0]["name"] == "nmap"
    assert nmap_results[0]["is_installed"] is True

    wireless_results = index.search("wifi", category="wireless", limit=5)
    assert wireless_results
    assert wireless_results[0]["name"] == "aircrack-ng"

    alias = index.get_tool("airodump-ng")
    assert alias is not None
    assert alias["name"] == "aircrack-ng"

    installed = index.search("", installed_only=True, limit=5)
    assert [item["name"] for item in installed] == ["nmap"]


def test_failed_partial_sync_does_not_overwrite_existing_cache(tmp_path, monkeypatch):
    records = [
        KaliToolRecord(
            name="nmap",
            packages=["nmap"],
            binaries=["nmap"],
            category="information_gathering",
            summary="Network mapper.",
        )
    ]
    cache_path = tmp_path / "kali-tools.json"
    _write_cache(cache_path, records)
    before = cache_path.read_text(encoding="utf-8")
    index = KaliToolIndex(str(cache_path))

    class FakeResponse:
        headers = {"Content-Type": "text/html"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b"<html><ul><li><a href='/tools/nmap/'>nmap</a></li></ul></html>"

    monkeypatch.setattr(
        "loki.knowledge.tool_registry.kali_catalog.urlopen",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(RuntimeError, match="only 1 tool entries"):
        index.sync_from_kali()

    assert cache_path.read_text(encoding="utf-8") == before
    assert len(index.records) == 1


def test_agent_registers_kali_discovery_functions():
    from loki.runtime.agent import LokiAgent

    agent = LokiAgent(provider="mock")

    assert agent.registry.get("discover_kali_tools") is not None
    assert agent.registry.get("get_kali_tool_details") is not None
    assert agent.registry.get("check_kali_tool_availability") is not None


@pytest.mark.asyncio
async def test_sandbox_availability_check_is_network_disabled_and_does_not_run_tool(monkeypatch):
    from loki.executor.isolation import ExecutionIsolationResult, IsolationBackend, IsolatedExecutionEngine
    from loki.tools import security_tools

    monkeypatch.setattr(
        security_tools.kali_tool_index,
        "get_tool",
        lambda name: {
            "name": "nmap",
            "binaries": ["nmap", "ncat"],
        },
    )
    monkeypatch.setattr(security_tools.settings, "shell_docker_image", "loki-kali-tools:latest")

    captured = {}

    async def fake_execute_shell(command, timeout_seconds, image, allow_network):
        captured.update(
            command=command,
            timeout_seconds=timeout_seconds,
            image=image,
            allow_network=allow_network,
        )
        return ExecutionIsolationResult(
            command=command,
            stdout="/usr/bin/nmap\\nnmap FOUND",
            stderr="",
            exit_code=0,
            backend=IsolationBackend.DOCKER,
        )

    monkeypatch.setattr(IsolatedExecutionEngine, "execute_shell", fake_execute_shell)

    output = await security_tools.check_kali_tool_availability.func("nmap")

    assert "AVAILABLE IN ISOLATED IMAGE" in output
    assert "command -v" in captured["command"]
    assert "nmap" in captured["command"]
    assert captured["image"] == "loki-kali-tools:latest"
    assert captured["allow_network"] is False
    assert captured["timeout_seconds"] == 5.0
