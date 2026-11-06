"""
Security Tool Registry Catalog.
Stores documented tool knowledge and checks host installation status.
"""

from typing import Dict, List, Optional
import shutil

from loki.knowledge.tool_registry.models import (
    CommandTemplate,
    SecurityToolEntry,
    ToolCategory,
)

# Canonical catalog of primary security auditing tools
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
            CommandTemplate(
                purpose="Specific Port Verification",
                syntax="nmap -p {ports} -sV {target}",
                args=["-p", "{ports}", "-sV"],
                description="Inspects specified ports for running services and version banners.",
                risk_level="low",
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
        commands=[
            CommandTemplate(
                purpose="Standard Web Server Configuration Audit",
                syntax="nikto -h {target} -Tuning 1,2,3,b",
                args=["-h", "{target}", "-Tuning", "1,2,3,b"],
                description="Audits web server headers, server identification, and configuration misconfigurations.",
                risk_level="medium",
            ),
            CommandTemplate(
                purpose="SSL/TLS Web Audit",
                syntax="nikto -h {target} -ssl",
                args=["-h", "{target}", "-ssl"],
                description="Scans an HTTPS target checking SSL cipher and certificate configuration.",
                risk_level="medium",
            ),
        ],
    ),
    SecurityToolEntry(
        name="whatweb",
        category=ToolCategory.WEB_APPLICATION,
        description="Next-generation web scanner identifying technologies, CMSs, blogging platforms, JavaScript libraries, and web servers.",
        binary_name="whatweb",
        installation_method="apt install whatweb / gem install whatweb",
        documentation_url="https://github.com/urbanadventurer/WhatWeb",
        required_inputs=["target"],
        expected_outputs=["technologies", "cms", "frameworks", "headers"],
        commands=[
            CommandTemplate(
                purpose="Passive Web Technology Fingerprinting",
                syntax="whatweb -a 1 {target}",
                args=["-a", "1", "{target}"],
                description="Stealthy passive fingerprinting based solely on the homepage response headers and body.",
                risk_level="low",
            ),
            CommandTemplate(
                purpose="Detailed Technology Identification",
                syntax="whatweb -a 3 --color=never {target}",
                args=["-a", "3", "--color=never", "{target}"],
                description="Active technology inspection examining plugins, headers, and specific endpoint fingerprints.",
                risk_level="medium",
            ),
        ],
    ),
    SecurityToolEntry(
        name="whois",
        category=ToolCategory.INFORMATION_GATHERING,
        description="Client for the WHOIS directory service providing domain ownership and IP allocation data.",
        binary_name="whois",
        installation_method="apt install whois",
        documentation_url="https://linux.die.net/man/1/whois",
        required_inputs=["target"],
        expected_outputs=["registrar", "creation_date", "nameservers", "ip_blocks"],
        commands=[
            CommandTemplate(
                purpose="Domain Registration Query",
                syntax="whois {target}",
                args=["{target}"],
                description="Queries authoritative WHOIS servers for domain registration and nameserver details.",
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
        commands=[
            CommandTemplate(
                purpose="Comprehensive DNS Records Query",
                syntax="dig {target} ANY +noall +answer",
                args=["{target}", "ANY", "+noall", "+answer"],
                description="Retrieves all available DNS records (A, MX, TXT, NS, CNAME) for the host.",
                risk_level="low",
            ),
            CommandTemplate(
                purpose="Mail Exchange Records Verification",
                syntax="dig {target} MX +short",
                args=["{target}", "MX", "+short"],
                description="Fetches mail servers handling incoming email for target domain.",
                risk_level="low",
            ),
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
        commands=[
            CommandTemplate(
                purpose="Passive Subdomain Discovery",
                syntax="sublist3r -d {target} -t 10",
                args=["-d", "{target}", "-t", "10"],
                description="Gathers subdomains passively via search engines and Netcraft without sending packets to target.",
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
        commands=[
            CommandTemplate(
                purpose="Controlled Directory and Route Discovery",
                syntax="ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403 -rate 50",
                args=["-u", "{target}/FUZZ", "-w", "{wordlist}", "-mc", "200,301,302,403", "-rate", "50"],
                description="Scans for accessible endpoints under target URL with controlled rate limiting (50 req/s).",
                risk_level="medium",
            )
        ],
    ),
    SecurityToolEntry(
        name="trivy",
        category=ToolCategory.CONTAINER_CLOUD,
        description="Comprehensive vulnerability and misconfiguration scanner for containers, filesystems, and Git repos.",
        binary_name="trivy",
        installation_method="apt install trivy / brew install trivy",
        documentation_url="https://aquasecurity.github.io/trivy/",
        required_inputs=["target"],
        expected_outputs=["cves", "misconfigurations", "vulnerable_libraries"],
        commands=[
            CommandTemplate(
                purpose="Filesystem and Dependency Vulnerability Scan",
                syntax="trivy fs --severity HIGH,CRITICAL {target}",
                args=["fs", "--severity", "HIGH,CRITICAL", "{target}"],
                description="Scans project directory for vulnerable dependencies with known High and Critical CVEs.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="semgrep",
        category=ToolCategory.VULNERABILITY_ANALYSIS,
        description="Fast, open-source static analysis engine for finding bugs and enforcing code security standards.",
        binary_name="semgrep",
        installation_method="pip install semgrep",
        documentation_url="https://semgrep.dev/docs/",
        required_inputs=["target"],
        expected_outputs=["code_vulnerabilities", "cwe_matches"],
        commands=[
            CommandTemplate(
                purpose="Static Code Security Audit (OWASP Top 10 rules)",
                syntax="semgrep scan --config=auto {target}",
                args=["scan", "--config=auto", "{target}"],
                description="Scans source code directory for insecure functions, hardcoded secrets, and injection vulnerabilities.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="sslscan",
        category=ToolCategory.CRYPTOGRAPHY,
        description="Fast SSL/TLS cipher suite and certificate scanner.",
        binary_name="sslscan",
        installation_method="apt install sslscan",
        documentation_url="https://github.com/rbsec/sslscan",
        required_inputs=["target"],
        expected_outputs=["supported_ciphers", "tls_versions", "certificate_validity"],
        commands=[
            CommandTemplate(
                purpose="SSL/TLS Cipher Suite and Protocol Security Audit",
                syntax="sslscan --no-failed {target}",
                args=["--no-failed", "{target}"],
                description="Tests target for weak TLS 1.0/1.1 protocols, insecure cipher suites, and certificate flaws.",
                risk_level="low",
            )
        ],
    ),
    SecurityToolEntry(
        name="testssl",
        category=ToolCategory.CRYPTOGRAPHY,
        description="Command line tool which checks a server's service on any port for the support of TLS/SSL ciphers.",
        binary_name="testssl.sh",
        installation_method="apt install testssl.sh",
        documentation_url="https://testssl.sh/",
        required_inputs=["target"],
        expected_outputs=["vulnerabilities", "cipher_rankings", "certificate_details"],
        commands=[
            CommandTemplate(
                purpose="Comprehensive SSL/TLS Vulnerability Check (Heartbleed, POODLE, Robot)",
                syntax="testssl.sh --fast {target}",
                args=["--fast", "{target}"],
                description="Audits SSL/TLS implementations for known protocol vulnerabilities.",
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
