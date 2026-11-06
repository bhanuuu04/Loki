"""
Parsers for extracting structured security intelligence from tool outputs.
"""

from typing import Any, Dict, List, Optional
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
