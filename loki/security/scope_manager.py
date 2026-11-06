"""
Scope management and target boundary enforcement for Loki.
"""

from typing import List, Optional, Set
import ipaddress
import urllib.parse
from pydantic import BaseModel, Field


class ScopeTarget(BaseModel):
    """Represents an authorized target asset."""
    identifier: str  # domain, hostname, IP, or CIDR
    description: Optional[str] = ""
    is_cidr: bool = False
    is_ip: bool = False
    port_range: Optional[str] = None  # e.g., "80,443,8000-8080"


class ScopeConfig(BaseModel):
    """
    Declared assessment authorization and scope boundaries.
    Enforces that the agent can ONLY interact with explicitly authorized assets.
    """
    assessment_name: str
    organization: Optional[str] = ""
    targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allow_subdomains: bool = True
    allowed_ports: Optional[List[int]] = None
    rate_limit_requests_per_second: float = 10.0


class ScopeManager:
    """Validates and enforces target scope boundaries."""

    def __init__(self, config: Optional[ScopeConfig] = None):
        self.config = config or ScopeConfig(assessment_name="Default Assessment")
        self._parsed_targets: Set[str] = set()
        self._parsed_exclusions: Set[str] = set()
        self._ip_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._init_rules()

    def set_config(self, config: ScopeConfig) -> None:
        self.config = config
        self._init_rules()

    def _init_rules(self) -> None:
        self._parsed_targets.clear()
        self._parsed_exclusions.clear()
        self._ip_networks.clear()
        self._excluded_networks.clear()

        for t in self.config.targets:
            cleaned = self._clean_target(t)
            try:
                if "/" in cleaned:
                    net = ipaddress.ip_network(cleaned, strict=False)
                    self._ip_networks.append(net)
                else:
                    ip = ipaddress.ip_address(cleaned)
                    self._ip_networks.append(ipaddress.ip_network(f"{ip}/32"))
            except ValueError:
                self._parsed_targets.add(cleaned.lower())

        for ex in self.config.excluded_targets:
            cleaned = self._clean_target(ex)
            try:
                if "/" in cleaned:
                    net = ipaddress.ip_network(cleaned, strict=False)
                    self._excluded_networks.append(net)
                else:
                    ip = ipaddress.ip_address(cleaned)
                    self._excluded_networks.append(ipaddress.ip_network(f"{ip}/32"))
            except ValueError:
                self._parsed_exclusions.add(cleaned.lower())

    @staticmethod
    def _clean_target(target: str) -> str:
        """Strips protocol and ports to get host/domain/IP."""
        target = target.strip()
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or target
            return host.lower()
        if ":" in target and not target.count(":") > 1:  # Not IPv6
            return target.split(":")[0].lower()
        return target.lower()

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """
        Check if a given target host, URL, or IP is within the authorized scope.
        Returns: (is_allowed: bool, reason: str)
        """
        host = self._clean_target(target)

        # 1. Check exclusions first
        if host in self._parsed_exclusions:
            return False, f"Target '{host}' is explicitly excluded in assessment scope."

        try:
            ip_obj = ipaddress.ip_address(host)
            for ex_net in self._excluded_networks:
                if ip_obj in ex_net:
                    return False, f"Target IP '{host}' falls within excluded network '{ex_net}'."

            # Check included IP networks
            for net in self._ip_networks:
                if ip_obj in net:
                    return True, f"Target IP '{host}' is authorized under network '{net}'."
        except ValueError:
            # Target is a hostname/domain
            pass

        # 2. Check exact hostname match
        if host in self._parsed_targets:
            return True, f"Target host '{host}' is explicitly authorized."

        # 3. Check subdomain matching if enabled
        if self.config.allow_subdomains:
            for authorized in self._parsed_targets:
                if host.endswith(f".{authorized}"):
                    return True, f"Target '{host}' is an authorized subdomain of '{authorized}'."

        return False, f"Target '{host}' is NOT in authorized scope. Permitted targets: {self.config.targets}"
