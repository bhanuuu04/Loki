"""
Kali Linux tool catalogue index.

The upstream Kali "All Tools" page is the source of truth. Loki syncs this
catalogue on operator request, caches it locally, and performs discovery
without adding hundreds of individual LLM function schemas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from pydantic import BaseModel
import json
import os
import re
import shutil
import subprocess


KALI_TOOLS_URL = "https://www.kali.org/tools/all-tools/"
CACHE_SCHEMA_VERSION = 1
MAX_HTML_BYTES = 12 * 1024 * 1024
MIN_SYNC_ENTRIES = 100

CATEGORY_HINTS = {
    "wireless": ("aircrack", "wifi", "wireless", "bluetooth", "rfid", "sdr", "wifite", "kismet"),
    "web_application": ("web", "http", "burp", "zap", "nikto", "wpscan", "sqlmap", "xss", "cms", "dirbuster"),
    "information_gathering": ("recon", "dns", "whois", "amass", "asset", "subdomain", "osint", "nmap", "arp-scan"),
    "vulnerability_analysis": ("vuln", "exploit", "metasploit", "openvas", "nessus", "cve", "searchsploit"),
    "passwords": ("password", "hash", "john", "hashcat", "hydra", "crack", "rainbow", "medusa"),
    "forensics": ("forensic", "autopsy", "volatility", "binwalk", "foremost", "sleuth", "memory"),
    "reverse_engineering": ("reverse", "ghidra", "radare", "rizin", "gdb", "apktool", "jadx", "disasm"),
    "fuzzing": ("fuzz", "afl", "boofuzz", "ffuf", "wfuzz", "radamsa"),
    "sniffing_spoofing": ("sniff", "spoof", "wireshark", "tcpdump", "ettercap", "mitm", "dsniff"),
    "database": ("database", "mysql", "postgres", "sql", "mongo", "redis"),
    "cloud_container": ("cloud", "aws", "azure", "kube", "docker", "container", "terraform"),
    "reporting": ("report", "dradis", "faraday", "cherrytree", "eyewitness"),
}

QUERY_SYNONYMS = {
    "port": {"ports", "portscan", "scanner", "nmap", "masscan", "rustscan"},
    "scan": {"scanning", "scanner", "enumeration", "discovery"},
    "subdomain": {"subdomains", "domain", "dns", "amass", "assetfinder", "subfinder"},
    "web": {"http", "website", "webapp", "web_application", "burp", "zap", "nikto"},
    "directory": {"content", "path", "endpoint", "fuzz", "ffuf", "gobuster", "dirsearch"},
    "password": {"credential", "credentials", "hash", "cracking", "john", "hashcat", "hydra"},
    "wireless": {"wifi", "wi-fi", "802.11", "aircrack", "bluetooth", "rfid"},
    "forensics": {"disk", "memory", "image", "recovery", "evidence", "autopsy", "volatility"},
    "reverse": {"binary", "disassembly", "decompiler", "ghidra", "radare2", "rizin"},
    "packet": {"traffic", "capture", "sniff", "pcap", "wireshark", "tcpdump"},
}

CATEGORY_ALIASES = {
    "recon": "information_gathering",
    "osint": "information_gathering",
    "web": "web_application",
    "webapp": "web_application",
    "vuln": "vulnerability_analysis",
    "password": "passwords",
    "credential": "passwords",
    "wireless": "wireless",
    "forensic": "forensics",
    "reverse": "reverse_engineering",
    "fuzz": "fuzzing",
    "packet": "sniffing_spoofing",
    "sniffing": "sniffing_spoofing",
    "cloud": "cloud_container",
    "container": "cloud_container",
    "db": "database",
}


class KaliToolRecord(BaseModel):
    """A source-level tool entry from Kali's official catalogue."""

    name: str
    packages: List[str]
    binaries: List[str]
    category: str
    summary: str
    documentation_url: str = ""
    source_url: str = KALI_TOOLS_URL


class _ListNode:
    def __init__(self) -> None:
        self.anchors: List[Dict[str, str]] = []
        self.text: List[str] = []
        self.children: List["_ListNode"] = []


class _KaliHTMLParser(HTMLParser):
    """Extract nested source/package/command list items from Kali's catalogue."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.roots: List[_ListNode] = []
        self.stack: List[_ListNode] = []
        self.anchor: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        values = dict(attrs)
        if tag.lower() == "li":
            node = _ListNode()
            if self.stack:
                self.stack[-1].children.append(node)
            else:
                self.roots.append(node)
            self.stack.append(node)
        elif tag.lower() == "a":
            self.anchor = {"href": values.get("href") or "", "text": []}

    def handle_data(self, data: str) -> None:
        if self.anchor is not None:
            self.anchor["text"].append(data)
        elif self.stack:
            self.stack[-1].text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self.anchor is not None:
            label = " ".join(" ".join(self.anchor["text"]).split())
            if self.stack and label:
                self.stack[-1].anchors.append(
                    {"label": label, "href": str(self.anchor["href"])}
                )
            self.anchor = None
        elif tag.lower() == "li" and self.stack:
            self.stack.pop()


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9.+_-]+", "-", value.strip().lower()).strip("-")


def _node_name(node: _ListNode) -> str:
    for anchor in node.anchors:
        label = anchor["label"].strip()
        if label and not label.startswith("$"):
            return label.rstrip("$").strip()
    text = " ".join(" ".join(node.text).split())
    return text.rstrip("$").strip()


def _walk_nodes(node: _ListNode) -> Iterable[_ListNode]:
    for child in node.children:
        yield child
        yield from _walk_nodes(child)


def _classify(name: str, packages: List[str], binaries: List[str]) -> str:
    haystack = " ".join([name, *packages, *binaries]).lower().replace("-", " ")
    for category, hints in CATEGORY_HINTS.items():
        if any(hint in haystack for hint in hints):
            return category
    return "security_utilities"


def _summary(name: str, category: str, packages: List[str]) -> str:
    readable = name.replace("-", " ").replace("_", " ").strip().capitalize()
    category_names = {
        "wireless": "wireless and radio assessment",
        "web_application": "web application assessment",
        "information_gathering": "reconnaissance and information gathering",
        "vulnerability_analysis": "vulnerability analysis and validation",
        "passwords": "password and hash auditing",
        "forensics": "digital forensics and evidence analysis",
        "reverse_engineering": "reverse engineering and binary analysis",
        "fuzzing": "fuzzing and input testing",
        "sniffing_spoofing": "network traffic analysis",
        "database": "database assessment",
        "cloud_container": "cloud and container security",
        "reporting": "assessment reporting",
        "security_utilities": "security research and administration",
    }
    package_note = f" Related package(s): {', '.join(packages[:4])}." if packages else ""
    return (
        f"{readable} is listed in Kali's official tool catalogue for "
        f"{category_names.get(category, 'security work')}."
        f"{package_note} Check the linked upstream documentation for current usage and options."
    )


def parse_kali_tools_html(html: str) -> List[KaliToolRecord]:
    """
    Parse Kali's nested source -> package -> command catalogue.

    The parser intentionally records tool-level entries, not every Linux library
    or helper executable as a separate security tool.
    """
    parser = _KaliHTMLParser()
    parser.feed(html)

    records: Dict[str, KaliToolRecord] = {}
    for root in parser.roots:
        name = _node_name(root)
        normalized = _slug(name)
        if (
            not normalized
            or len(normalized) > 100
            or normalized in {"all-kali-tools", "categories", "top-100", "kali-tools"}
            or normalized.startswith("kali-tools-top")
            or not re.search(r"[a-z0-9]", normalized)
        ):
            continue

        packages: List[str] = []
        for child in root.children:
            package = _node_name(child)
            if package and not package.startswith("$"):
                package_name = _slug(package)
                if package_name and package_name not in packages:
                    packages.append(package_name)

        binaries: List[str] = []
        for node in [root, *_walk_nodes(root)]:
            for anchor in node.anchors:
                label = anchor["label"].strip()
                if label.startswith("$"):
                    binary = label.lstrip("$").strip()
                    if binary and re.fullmatch(r"[A-Za-z0-9._+:-]{1,100}", binary):
                        binaries.append(binary)
            raw_text = " ".join(node.text)
            for match in re.findall(r"\$\s*([A-Za-z0-9._+:-]{1,100})", raw_text):
                binaries.append(match)

        # Some source entries expose a single command with the same name.
        if not binaries:
            binaries = [name]

        unique_binaries = list(dict.fromkeys(binaries))
        documentation_url = ""
        for anchor in root.anchors:
            href = anchor.get("href", "")
            if "/tools/" in href and "all-tools" not in href:
                documentation_url = urljoin(KALI_TOOLS_URL, href)
                break

        category = _classify(name, packages, unique_binaries)
        records[normalized] = KaliToolRecord(
            name=name,
            packages=packages,
            binaries=unique_binaries,
            category=category,
            summary=_summary(name, category, packages),
            documentation_url=documentation_url,
        )

    return sorted(records.values(), key=lambda item: item.name.lower())


class KaliToolIndex:
    """Cached searchable index of Kali's official source-level tool catalogue."""

    def __init__(self, cache_path: Optional[str] = None) -> None:
        configured_path = cache_path or os.getenv("LOKI_KALI_TOOLS_INDEX")
        self.cache_path = (
            Path(configured_path).expanduser()
            if configured_path
            else Path.home() / ".loki" / "kali-tools-index.json"
        )
        self.records: List[KaliToolRecord] = []
        self.metadata: Dict[str, Any] = {}
        self.load_cache()

    def load_cache(self) -> int:
        """Load a previously synced catalogue. Missing or invalid caches are ignored."""
        if not self.cache_path.exists():
            return 0
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if payload.get("schema_version") != CACHE_SCHEMA_VERSION:
                return 0
            records = [
                KaliToolRecord.model_validate(item)
                for item in payload.get("tools", [])
            ]
            self.records = records
            self.metadata = {
                "source_url": payload.get("source_url", KALI_TOOLS_URL),
                "fetched_at": payload.get("fetched_at", ""),
                "tool_count": len(records),
            }
            return len(records)
        except (OSError, ValueError, TypeError, KeyError):
            return 0

    def sync_from_kali(self, timeout_seconds: float = 25.0) -> Dict[str, Any]:
        """
        Download and parse the official index, then atomically replace the cache.

        A failed/partial fetch never overwrites a valid existing cache.
        """
        request = Request(
            KALI_TOOLS_URL,
            headers={
                "User-Agent": "Loki-Security-Research-Agent/1.0 (+https://github.com/bhanuuu04/Loki)",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                content_type = response.headers.get("Content-Type", "")
                if "html" not in content_type.lower():
                    raise RuntimeError(f"Unexpected Kali catalogue content type: {content_type}")
                html_bytes = response.read(MAX_HTML_BYTES + 1)
        except (URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Could not download Kali's official tools index: {type(exc).__name__}: {exc}") from exc

        if len(html_bytes) > MAX_HTML_BYTES:
            raise RuntimeError("Kali tools index exceeded the 12 MiB safety limit.")

        html = html_bytes.decode("utf-8", errors="replace")
        records = parse_kali_tools_html(html)
        if len(records) < MIN_SYNC_ENTRIES:
            raise RuntimeError(
                f"Catalogue parser found only {len(records)} tool entries; "
                "the response may be incomplete or the upstream page format may have changed. "
                "The existing cache was left unchanged."
            )

        fetched_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "source_url": KALI_TOOLS_URL,
            "fetched_at": fetched_at,
            "tool_count": len(records),
            "tools": [record.model_dump() for record in records],
        }

        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.cache_path)

        self.records = records
        self.metadata = {
            "source_url": KALI_TOOLS_URL,
            "fetched_at": fetched_at,
            "tool_count": len(records),
        }
        return dict(self.metadata)

    @staticmethod
    def _installed_path(record: KaliToolRecord) -> Optional[str]:
        for binary in record.binaries or [record.name]:
            path = shutil.which(binary)
            if path:
                return path
        return None

    @staticmethod
    def _query_terms(query: str) -> set[str]:
        terms = set(re.findall(r"[a-z0-9.+_-]+", query.lower()))
        expanded = set(terms)
        for term in terms:
            expanded.update(QUERY_SYNONYMS.get(term, set()))
            # Make aliases searchable in both directions: "wifi" should find
            # entries described as "wireless", just as "wireless" finds "wifi".
            for canonical, aliases in QUERY_SYNONYMS.items():
                if term in aliases:
                    expanded.add(canonical)
        return expanded

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        installed_only: bool = False,
        limit: int = 8,
    ) -> List[Dict[str, Any]]:
        """Rank tools by exact names, aliases, package names, category, and intent terms."""
        query = (query or "").strip()
        if not self.records:
            self.load_cache()
        if not self.records:
            return []

        terms = self._query_terms(query)
        normalized_category = CATEGORY_ALIASES.get(
            (category or "").strip().lower(),
            (category or "").strip().lower(),
        )
        scored: List[tuple[float, KaliToolRecord, Optional[str]]] = []

        for record in self.records:
            if normalized_category and record.category != normalized_category:
                continue

            installed_path = self._installed_path(record)
            if installed_only and not installed_path:
                continue

            searchable = " ".join(
                [record.name, *record.packages, *record.binaries, record.category, record.summary]
            ).lower()
            score = 0.0

            if query and record.name.lower() == query.lower():
                score += 100.0
            if query and any(binary.lower() == query.lower() for binary in record.binaries):
                score += 90.0
            if query and any(package.lower() == query.lower() for package in record.packages):
                score += 80.0

            for term in terms:
                if term and term in searchable:
                    score += 5.0 if term in record.name.lower() else 2.0

            if query and score == 0:
                similarity = SequenceMatcher(None, query.lower(), record.name.lower()).ratio()
                if similarity >= 0.55:
                    score = similarity * 4.0

            if not query:
                score = 1.0

            if score > 0:
                scored.append((score, record, installed_path))

        scored.sort(key=lambda item: (-item[0], item[1].name.lower()))
        max_results = min(max(int(limit), 1), 20)
        return [
            {
                **record.model_dump(),
                "is_installed": installed_path is not None,
                "installed_path": installed_path,
                "install_hint": (
                    f"sudo apt install {record.packages[0]}"
                    if record.packages
                    else f"Find the package for {record.name} in Kali's repository."
                ),
            }
            for _, record, installed_path in scored[:max_results]
        ]

    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """Look up a tool by source name, package name, or executable alias."""
        if not self.records:
            self.load_cache()
        requested = _slug(name)
        for record in self.records:
            if requested == _slug(record.name):
                match = record
            elif requested in {_slug(x) for x in record.packages + record.binaries}:
                match = record
            else:
                continue

            installed_path = self._installed_path(match)
            description = self._local_package_description(match.packages)
            result = match.model_dump()
            if description:
                result["local_package_description"] = description
            result["is_installed"] = installed_path is not None
            result["installed_path"] = installed_path
            result["install_hint"] = (
                f"sudo apt install {match.packages[0]}"
                if match.packages
                else f"Find the package for {match.name} in Kali's repository."
            )
            return result
        return None

    @staticmethod
    def _local_package_description(packages: List[str]) -> str:
        """Read a short local APT package description without installing or updating anything."""
        if not packages or not shutil.which("apt-cache"):
            return ""
        try:
            result = subprocess.run(
                ["apt-cache", "show", packages[0]],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("Description:"):
                    return line.partition(":")[2].strip()[:500]
        except (OSError, subprocess.TimeoutExpired):
            pass
        return ""
