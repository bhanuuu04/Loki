import pytest
from loki.knowledge.tool_registry.catalog import SecurityToolCatalog
from loki.knowledge.tool_registry.models import SecurityToolEntry, ToolCategory
from loki.executor.output_parser import OutputParser


def test_tool_catalog_rigorous_status_tracking():
    catalog = SecurityToolCatalog()

    # Nmap is documented and has parser
    nmap = catalog.get_tool("nmap")
    assert nmap is not None
    assert nmap.documented_status is True
    assert nmap.output_parser_availability is True

    # HexStrike-inspired tools in catalog
    nuclei = catalog.get_tool("nuclei")
    assert nuclei is not None
    assert nuclei.documented_status is True
    assert nuclei.category == ToolCategory.VULNERABILITY_ANALYSIS

    # Verify is_implemented property: does NOT claim implemented if not installed
    uninstalled_tool = SecurityToolEntry(
        name="fantasy_scanner",
        category=ToolCategory.VULNERABILITY_ANALYSIS,
        description="Non-existent tool in catalog",
        binary_name="fantasy_scanner_xyz_999",
        installation_method="manual",
        documented_status=True,
        is_installed=False,
    )
    assert uninstalled_tool.documented_status is True
    assert uninstalled_tool.is_installed is False
    assert uninstalled_tool.is_implemented is False


def test_output_parsers_comprehensive():
    # 1. Nmap parser
    sample_nmap = """
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
    80/tcp   open  http    nginx 1.18.0
    443/tcp  closed https
    """
    nmap_parsed = OutputParser.parse_nmap_text(sample_nmap)
    assert nmap_parsed["total_open"] == 2
    assert nmap_parsed["open_ports"][0]["port"] == 22
    assert nmap_parsed["open_ports"][0]["service"] == "ssh"
    assert "OpenSSH" in nmap_parsed["open_ports"][0]["version"]

    # 2. HTTP Security headers parser
    sample_headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41",
        "Strict-Transport-Security": "max-age=31536000",
    }
    header_parsed = OutputParser.parse_security_headers(sample_headers)
    assert header_parsed["server_banner"] == "Apache/2.4.41"
    assert "strict-transport-security" in header_parsed["present_headers"]
    assert "content-security-policy" in header_parsed["missing_headers"]
    assert header_parsed["present_count"] >= 1

    # 3. FFUF JSON parser
    sample_ffuf = '{"results": [{"url": "http://target/admin", "status": 200, "length": 1500, "words": 120}]}'
    ffuf_parsed = OutputParser.parse_ffuf_json(sample_ffuf)
    assert len(ffuf_parsed) == 1
    assert ffuf_parsed[0]["status"] == 200
    assert "/admin" in ffuf_parsed[0]["url"]

    # 4. Nuclei JSONL parser
    sample_nuclei = '{"template-id": "cve-2021-44228", "info": {"name": "Log4j RCE", "severity": "critical", "description": "Log4j vulnerability"}, "matched-at": "http://target:8080"}\n'
    nuclei_parsed = OutputParser.parse_nuclei_json(sample_nuclei)
    assert len(nuclei_parsed) == 1
    assert nuclei_parsed[0]["template_id"] == "cve-2021-44228"
    assert nuclei_parsed[0]["severity"] == "critical"
