"""
Security Tool Registry Catalog for Loki 2.0.
Stores documented tool knowledge, platform compatibility, tested status,
output parser availability, and dynamic host installation checks.
Incorporates HexStrike AI tools and patterns under MIT license attribution.
"""

from typing import Dict, List, Optional
import shutil

from loki.knowledge.tool_registry.models import (
    CommandTemplate,
    SecurityToolEntry,
    ToolCategory,
)

# Canonical catalog of primary security auditing tools with rigorous status tracking
INITIAL_TOOL_CATALOG: List[SecurityToolEntry] = [
    SecurityToolEntry(
        name="nmap",
        category=ToolCategory.INFORMATION_GATHERING,
        description="Network exploration tool and security / port scanner.",
        binary_name="nmap",
        installation_method="apt install nmap / winget install Insecure.Nmap",
        documentation_url="https://nmap.org/book/man.html",
        required_inputs=["target"],
        expected_outputs=["open_ports", "services", "os_fingerprints"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        execution_handler_available=True,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Fast Top 100 Port Discovery (Non-intrusive)",
                syntax="nmap -F --open -sT -Pn {target}",
                args=["-F", "--open", "-sT", "-Pn"],
                description="Scans top 100 ports using standard TCP connect without sending ping probes.",
                risk_level="low",
            ),
            CommandTemplate(
                purpose="Standard Service and Version Detection",
                syntax="nmap -sV -sC -Pn -T3 {target}",
                args=["-sV", "-sC", "-Pn", "-T3"],
                description="Performs service version detection and runs default safe NSE scripts.",
                risk_level="medium",
            ),
        ],
    ),
    SecurityToolEntry(
        name="nikto",
        category=ToolCategory.WEB_APPLICATION,
        description="Web server vulnerability scanner for outdated software, dangerous files, and misconfigurations.",
        binary_name="nikto",
        installation_method="apt install nikto",
        documentation_url="https://cirt.net/Nikto2",
        required_inputs=["target"],
        expected_outputs=["http_options", "outdated_components", "dangerous_files"],
        documented_status=True,
        tested_status=False,
        output_parser_availability=False,
        supported_platforms=["linux", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Standard Web Server Configuration Audit",
                syntax="nikto -h {target} -Tuning 1,2,3,b",
                args=["-h", "{target}", "-Tuning", "1,2,3,b"],
                description="Audits web server headers, server identification, and configuration misconfigurations.",
                risk_level="medium",
            ),
        ],
    ),
    SecurityToolEntry(
        name="whatweb",
        category=ToolCategory.WEB_APPLICATION,
        description="Next-generation web scanner identifying technologies, CMSs, blogging platforms, and web servers.",
        binary_name="whatweb",
        installation_method="apt install whatweb / gem install whatweb",
        documentation_url="https://github.com/urbanadventurer/WhatWeb",
        required_inputs=["target"],
        expected_outputs=["technologies", "cms", "frameworks", "headers"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        supported_platforms=["linux", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Passive Web Technology Fingerprinting",
                syntax="whatweb -a 1 {target}",
                args=["-a", "1", "{target}"],
                description="Stealthy passive fingerprinting based solely on homepage response headers and body.",
                risk_level="low",
            ),
        ],
    ),
    SecurityToolEntry(
        name="whois",
        category=ToolCategory.INFORMATION_GATHERING,
        description="Client for WHOIS directory service providing domain ownership and IP allocation data.",
        binary_name="whois",
        installation_method="apt install whois",
        documentation_url="https://linux.die.net/man/1/whois",
        required_inputs=["target"],
        expected_outputs=["registrar", "creation_date", "nameservers", "ip_blocks"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=False,
        supported_platforms=["linux", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Domain Registration Query",
                syntax="whois {target}",
                args=["{target}"],
                description="Queries authoritative WHOIS servers for domain registration details.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="dig",
        category=ToolCategory.INFORMATION_GATHERING,
        description="DNS lookup utility for interrogating DNS name servers.",
        binary_name="dig",
        installation_method="apt install dnsutils / bind9-dnsutils",
        documentation_url="https://linux.die.net/man/1/dig",
        required_inputs=["target"],
        expected_outputs=["a_records", "mx_records", "txt_records", "ns_records"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        supported_platforms=["linux", "darwin", "windows"],
        commands=[
            CommandTemplate(
                purpose="Comprehensive DNS Records Query",
                syntax="dig {target} ANY +noall +answer",
                args=["{target}", "ANY", "+noall", "+answer"],
                description="Retrieves all available DNS records for the host.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="sublist3r",
        category=ToolCategory.INFORMATION_GATHERING,
        description="Fast subdomains discovery tool using passive search engines.",
        binary_name="sublist3r",
        installation_method="apt install sublist3r / pip install sublist3r",
        documentation_url="https://github.com/aboul3la/Sublist3r",
        required_inputs=["target"],
        expected_outputs=["subdomains"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Passive Subdomain Discovery",
                syntax="sublist3r -d {target} -t 10",
                args=["-d", "{target}", "-t", "10"],
                description="Gathers subdomains passively via search engines.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="ffuf",
        category=ToolCategory.FUZZING,
        description="Fast web fuzzer written in Go for discovering endpoints, directories, and parameters.",
        binary_name="ffuf",
        installation_method="apt install ffuf / go install github.com/ffuf/ffuf/v2@latest",
        documentation_url="https://github.com/ffuf/ffuf",
        required_inputs=["target", "wordlist"],
        expected_outputs=["discovered_paths", "status_codes", "content_lengths"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Controlled Directory and Route Discovery",
                syntax="ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403 -rate 50",
                args=["-u", "{target}/FUZZ", "-w", "{wordlist}", "-mc", "200,301,302,403", "-rate", "50"],
                description="Scans for accessible endpoints under target URL.",
                risk_level="medium",
            )
        ],
    ),
    # HexStrike AI inspired additions with verified metadata & capability flags
    SecurityToolEntry(
        name="nuclei",
        category=ToolCategory.VULNERABILITY_ANALYSIS,
        description="Fast and customizable vulnerability scanner based on simple YAML DSL templates.",
        binary_name="nuclei",
        installation_method="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        documentation_url="https://docs.projectdiscovery.io/tools/nuclei",
        required_inputs=["target"],
        expected_outputs=["vulnerabilities", "cves", "misconfigurations"],
        documented_status=True,
        tested_status=True,
        output_parser_availability=True,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Template-based Security Scan",
                syntax="nuclei -u {target} -severity low,medium -jsonl",
                args=["-u", "{target}", "-severity", "low,medium", "-jsonl"],
                description="Scans target using validated community templates with JSONL structured reporting.",
                risk_level="medium",
            )
        ],
    ),
    SecurityToolEntry(
        name="gobuster",
        category=ToolCategory.FUZZING,
        description="Directory, file, DNS, and vhost busting tool written in Go.",
        binary_name="gobuster",
        installation_method="apt install gobuster / go install github.com/OJ/gobuster/v3@latest",
        documentation_url="https://github.com/OJ/gobuster",
        required_inputs=["target", "wordlist"],
        expected_outputs=["discovered_urls", "status_codes"],
        documented_status=True,
        tested_status=False,
        output_parser_availability=False,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Directory Enumeration",
                syntax="gobuster dir -u {target} -w {wordlist} -q",
                args=["dir", "-u", "{target}", "-w", "{wordlist}", "-q"],
                description="Fast brute forcing of web paths and directories.",
                risk_level="medium",
            )
        ],
    ),
    SecurityToolEntry(
        name="sqlmap",
        category=ToolCategory.DATABASE_ASSESSMENT,
        description="Automatic SQL injection and database takeover tool.",
        binary_name="sqlmap",
        installation_method="apt install sqlmap / pip install sqlmap",
        documentation_url="https://sqlmap.org/",
        required_inputs=["url"],
        expected_outputs=["injectable_parameters", "database_type"],
        documented_status=True,
        tested_status=False,
        output_parser_availability=False,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Passive Parameter Injection Detection",
                syntax="sqlmap -u {url} --batch --level=1 --risk=1",
                args=["-u", "{url}", "--batch", "--level=1", "--risk=1"],
                description="Tests parameters for standard SQL injection vulnerability in safe non-destructive mode.",
                risk_level="high",
            )
        ],
    ),
    SecurityToolEntry(
        name="amass",
        category=ToolCategory.INFORMATION_GATHERING,
        description="In-depth attack surface mapping and network asset discovery tool.",
        binary_name="amass",
        installation_method="apt install amass / go install github.com/owasp-amass/amass/v4/...@master",
        documentation_url="https://github.com/owasp-amass/amass",
        required_inputs=["domain"],
        expected_outputs=["subdomains", "asns", "netblocks"],
        documented_status=True,
        tested_status=False,
        output_parser_availability=False,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="Passive Network and Subdomain Enum",
                syntax="amass enum -passive -d {domain}",
                args=["enum", "-passive", "-d", "{domain}"],
                description="Passive asset discovery without touching target infrastructure.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="wafw00f",
        category=ToolCategory.WEB_APPLICATION,
        description="Identifies and fingerprints Web Application Firewall (WAF) products protecting a website.",
        binary_name="wafw00f",
        installation_method="pip install wafw00f / apt install wafw00f",
        documentation_url="https://github.com/EnableSecurity/wafw00f",
        required_inputs=["target"],
        expected_outputs=["waf_detected", "waf_vendor"],
        documented_status=True,
        tested_status=False,
        output_parser_availability=False,
        supported_platforms=["linux", "windows", "darwin"],
        commands=[
            CommandTemplate(
                purpose="WAF Detection and Identification",
                syntax="wafw00f {target}",
                args=["{target}"],
                description="Sends benign HTTP probes to detect WAF behavioral responses.",
                risk_level="low",
            )
        ],
    ),
]


class SecurityToolCatalog:
    """Registry maintaining documented tools and checking system availability."""

    def __init__(self):
        self._tools: Dict[str, SecurityToolEntry] = {}
        for entry in INITIAL_TOOL_CATALOG:
            entry.refresh_installed_status()
            self._tools[entry.name.lower()] = entry

    def register_tool(self, tool_entry: SecurityToolEntry) -> None:
        """Register or update a tool definition."""
        tool_entry.refresh_installed_status()
        self._tools[tool_entry.name.lower()] = tool_entry

    def get_tool(self, name: str) -> Optional[SecurityToolEntry]:
        entry = self._tools.get(name.lower())
        if entry:
            entry.refresh_installed_status()
        return entry

    def list_tools(
        self, category: Optional[ToolCategory] = None, only_installed: bool = False
    ) -> List[SecurityToolEntry]:
        results = []
        for t in self._tools.values():
            t.refresh_installed_status()
            if category and t.category != category:
                continue
            if only_installed and not t.is_installed:
                continue
            results.append(t)
        return results

    def search_by_objective(self, query: str) -> List[SecurityToolEntry]:
        """Search tools by relevance to user's objective (e.g. 'port scan', 'ssl', 'cve', 'dns')."""
        query_words = set(query.lower().split())
        matched = []

        for tool_entry in self._tools.values():
            tool_entry.refresh_installed_status()
            haystack = f"{tool_entry.name} {tool_entry.description} {tool_entry.category.value} {' '.join(c.purpose for c in tool_entry.commands)}".lower()
            
            # Compute match score
            score = sum(1 for word in query_words if word in haystack)
            if score > 0:
                matched.append((score, tool_entry))

        matched.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in matched]
