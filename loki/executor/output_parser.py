"""
Parsers for extracting structured security intelligence from tool outputs for Loki 2.0.
Supports Nmap, HTTP security headers, WhatWeb, FFUF, and Nuclei JSON.
"""

from typing import Any, Dict, List, Optional
import json
import re


class OutputParser:
    """Parses tool outputs into structured models."""

    @staticmethod
    def parse_nmap_text(output: str) -> Dict[str, Any]:
        """Extract open ports, services, and versions from standard nmap text output."""
        ports = []
        for line in output.splitlines():
            line_s = line.strip()
            # Match lines like "80/tcp open http Apache httpd 2.4.41"
            match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)?\s*(.*)?$", line_s)
            if match:
                port_num, proto, state, service, version = match.groups()
                ports.append({
                    "port": int(port_num),
                    "protocol": proto,
                    "state": state,
                    "service": service or "unknown",
                    "version": (version or "").strip(),
                })
        return {"open_ports": ports, "total_open": len([p for p in ports if p["state"] == "open"])}

    @staticmethod
    def parse_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP response headers for defensive security posture."""
        normalized = {k.lower(): v for k, v in headers.items()}

        checks = {
            "strict-transport-security": normalized.get("strict-transport-security"),
            "content-security-policy": normalized.get("content-security-policy"),
            "x-content-type-options": normalized.get("x-content-type-options"),
            "x-frame-options": normalized.get("x-frame-options"),
            "referrer-policy": normalized.get("referrer-policy"),
            "permissions-policy": normalized.get("permissions-policy"),
        }

        missing = [h for h, val in checks.items() if not val]
        present = [h for h, val in checks.items() if val]

        # Check server disclosure
        server_banner = normalized.get("server") or normalized.get("x-powered-by")

        return {
            "present_headers": checks,
            "missing_headers": missing,
            "present_count": len(present),
            "missing_count": len(missing),
            "server_banner": server_banner,
        }

    @staticmethod
    def parse_whatweb_json(output: str) -> List[Dict[str, Any]]:
        """Parses WhatWeb JSON output for discovered web technologies."""
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            return [data]
        except Exception:
            # Fallback text parsing for plugin matches
            technologies = []
            for match in re.finditer(r"\[([^\]]+)\]", output):
                technologies.append({"name": match.group(1)})
            return technologies

    @staticmethod
    def parse_ffuf_json(output: str) -> List[Dict[str, Any]]:
        """Parses Ffuf JSON output into structured endpoints and response codes."""
        try:
            data = json.loads(output)
            results = data.get("results", [])
            endpoints = []
            for item in results:
                endpoints.append({
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words"),
                })
            return endpoints
        except Exception:
            return []

    @staticmethod
    def parse_nuclei_json(output: str) -> List[Dict[str, Any]]:
        """Parses Nuclei JSONL stream output into structured vulnerability records."""
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                findings.append({
                    "template_id": item.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity", "info"),
                    "matched_at": item.get("matched-at"),
                    "type": item.get("type"),
                    "description": info.get("description", ""),
                })
            except Exception:
                continue
        return findings
