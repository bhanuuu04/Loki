"""
Scope management and target boundary enforcement for Loki 2.0.
Provides explicit scope initialization, scope versioning, exclusion precedence,
strict domain/IP normalization, IPv4/IPv6/CIDR handling, DNS resolution checks,
and DNS rebinding / redirect destination protections.
"""

from typing import List, Optional, Set, Tuple, Union
import ipaddress
import re
import socket
import time
import urllib.parse
import uuid
from pydantic import BaseModel, Field


class ScopeVersionRecord(BaseModel):
    """Audit record for a versioned scope change."""
    version: int
    timestamp: float = Field(default_factory=time.time)
    author: str = "system"
    action: str
    targets: List[str]
    excluded_targets: List[str]
    reason: Optional[str] = None


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
    scope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    organization: Optional[str] = ""
    targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allow_subdomains: bool = True
    allowed_ports: Optional[List[int]] = None
    allow_private_ips: bool = False
    allow_loopback: bool = False
    dns_check_enabled: bool = True
    rate_limit_requests_per_second: float = 10.0


# Cloud metadata and hazardous link-local / internal IP ranges
METADATA_IPS = [
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 Link-local / AWS / GCP / Azure metadata
    ipaddress.ip_network("fe80::/10"),        # IPv6 Link-local
    ipaddress.ip_network("fd00::/8"),         # IPv6 Unique Local Address
]

LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


class ScopeManager:
    """
    Validates and enforces target scope boundaries with strict verification,
    DNS rebinding protection, exclusion precedence, and versioned audit history.
    """

    def __init__(self, config: Optional[ScopeConfig] = None, authorization_key: Optional[str] = None):
        self._auth_key = authorization_key or str(uuid.uuid4())
        self.config = config or ScopeConfig(assessment_name="Default Assessment")
        self._parsed_targets: Set[str] = set()
        self._parsed_exclusions: Set[str] = set()
        self._ip_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._excluded_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._version_history: List[ScopeVersionRecord] = []
        self._dns_cache: dict[str, List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = {}

        self._init_rules()
        self._record_history("Initial scope configuration")

    @classmethod
    def create_explicit_scope(
        cls,
        assessment_name: str,
        targets: List[str],
        excluded_targets: Optional[List[str]] = None,
        allow_subdomains: bool = True,
        allowed_ports: Optional[List[int]] = None,
        allow_private_ips: bool = False,
        allow_loopback: bool = False,
        dns_check_enabled: bool = True,
        author: str = "admin",
    ) -> "ScopeManager":
        """Explicit scope initialization factory with mandatory parameters."""
        config = ScopeConfig(
            assessment_name=assessment_name,
            targets=targets,
            excluded_targets=excluded_targets or [],
            allow_subdomains=allow_subdomains,
            allowed_ports=allowed_ports,
            allow_private_ips=allow_private_ips,
            allow_loopback=allow_loopback,
            dns_check_enabled=dns_check_enabled,
        )
        instance = cls(config=config)
        if instance._version_history:
            instance._version_history[-1].author = author
            instance._version_history[-1].action = f"Explicit scope initialized by {author}"
        return instance

    def set_config(self, config: ScopeConfig, author: str = "system", reason: Optional[str] = None) -> None:
        """Update scope configuration with version increment and audit logging."""
        config.version = self.config.version + 1
        self.config = config
        self._init_rules()
        self._dns_cache.clear()
        self._record_history(f"Scope updated to version {config.version}", author=author, reason=reason)

    def update_targets(
        self,
        add_targets: Optional[List[str]] = None,
        remove_targets: Optional[List[str]] = None,
        add_exclusions: Optional[List[str]] = None,
        remove_exclusions: Optional[List[str]] = None,
        author: str = "operator",
        reason: Optional[str] = None,
    ) -> None:
        """Explicit versioned target mutation."""
        targets = set(self.config.targets)
        exclusions = set(self.config.excluded_targets)

        if add_targets:
            targets.update(add_targets)
        if remove_targets:
            targets.difference_update(remove_targets)
        if add_exclusions:
            exclusions.update(add_exclusions)
        if remove_exclusions:
            exclusions.difference_update(remove_exclusions)

        self.config.targets = sorted(list(targets))
        self.config.excluded_targets = sorted(list(exclusions))
        self.config.version += 1
        self._init_rules()
        self._dns_cache.clear()
        self._record_history(f"Targets modified (v{self.config.version})", author=author, reason=reason)

    def get_version_history(self) -> List[ScopeVersionRecord]:
        """Return the immutable audit history of scope changes."""
        return list(self._version_history)

    def _record_history(self, action: str, author: str = "system", reason: Optional[str] = None) -> None:
        record = ScopeVersionRecord(
            version=self.config.version,
            author=author,
            action=action,
            targets=list(self.config.targets),
            excluded_targets=list(self.config.excluded_targets),
            reason=reason,
        )
        self._version_history.append(record)

    def _init_rules(self) -> None:
        self._parsed_targets.clear()
        self._parsed_exclusions.clear()
        self._ip_networks.clear()
        self._excluded_networks.clear()

        # Check if loopback or private ranges are explicitly configured in targets
        for t in self.config.targets:
            cleaned = self.normalize_target(t)
            if not cleaned:
                continue

            ip_net = self._parse_ip_or_network(cleaned)
            if ip_net:
                self._ip_networks.append(ip_net)
                if any(ip_net.overlaps(loop_net) for loop_net in LOOPBACK_NETWORKS):
                    self.config.allow_loopback = True
                if any(ip_net.overlaps(priv_net) for priv_net in PRIVATE_NETWORKS):
                    self.config.allow_private_ips = True
            else:
                self._parsed_targets.add(cleaned)
                if cleaned in ("localhost", "127.0.0.1", "::1"):
                    self.config.allow_loopback = True

        for ex in self.config.excluded_targets:
            cleaned = self.normalize_target(ex)
            if not cleaned:
                continue

            ip_net = self._parse_ip_or_network(cleaned)
            if ip_net:
                self._excluded_networks.append(ip_net)
            else:
                self._parsed_exclusions.add(cleaned)

    @staticmethod
    def _parse_ip_or_network(target: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Parses an IPv4/IPv6 address or CIDR network, including IPv4-mapped IPv6."""
        try:
            if "/" in target:
                return ipaddress.ip_network(target, strict=False)
            ip = ipaddress.ip_address(target)
            # Unmap IPv4-in-IPv6 if present (e.g. ::ffff:192.0.2.1)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if isinstance(ip, ipaddress.IPv4Address):
                return ipaddress.IPv4Network(f"{ip}/32")
            return ipaddress.IPv6Network(f"{ip}/128")
        except ValueError:
            return None

    @staticmethod
    def normalize_target(target: str) -> str:
        """
        Strict domain/IP normalization.
        - Strips scheme, credentials, port, path, parameters, trailing dots.
        - Normalizes Unicode/IDNA domains to ASCII.
        - Lowercases and validates characters.
        """
        if not target or not isinstance(target, str):
            return ""

        raw = target.strip()
        # Remove surrounding quotes or angle brackets if present
        raw = raw.strip("\"'<>")

        # Strip URL scheme if present
        if "://" in raw:
            try:
                parsed = urllib.parse.urlparse(raw)
                raw = parsed.netloc or parsed.path
            except Exception:
                raw = raw.split("://", 1)[1]

        # Strip userinfo (user:pass@host)
        if "@" in raw:
            raw = raw.split("@", 1)[1]

        # Check if it is a CIDR before stripping slashes
        is_cidr = False
        try:
            if "/" in raw and "://" not in target:
                ipaddress.ip_network(raw.strip(), strict=False)
                is_cidr = True
        except ValueError:
            pass

        if not is_cidr:
            # Strip path or query or fragment if still present
            raw = re.split(r"[/?#]", raw)[0].strip()

        # Handle port stripping:
        # If target has brackets (IPv6 with port like [::1]:8080)
        if raw.startswith("[") and "]" in raw:
            ipv6_part = raw[1:raw.index("]")]
            port_part = raw[raw.index("]"):].lstrip("]:")
            raw = ipv6_part
        elif ":" in raw and not raw.count(":") > 1 and not is_cidr:
            # Single colon indicates hostname:port or ipv4:port
            raw = raw.split(":", 1)[0]

        # Strip trailing dot
        raw = raw.rstrip(".").lower()

        # Handle IDNA / Punycode conversion for international domain names
        try:
            raw = raw.encode("idna").decode("ascii")
        except Exception:
            pass

        return raw

    def is_in_scope(self, target: str, check_dns: Optional[bool] = None) -> Tuple[bool, str]:
        """
        Check if a given target host, URL, or IP is within the authorized scope.
        Strictly enforces EXCLUSION PRECEDENCE, IPv4/IPv6/CIDR validation,
        DNS rebinding protection, and out-of-scope resolved addresses.

        Returns: (is_allowed: bool, reason: str)
        """
        if not target or not str(target).strip():
            return False, "Target is empty or null."

        host = self.normalize_target(target)
        if not host:
            return False, f"Could not parse a valid host from '{target}'."

        # Reject dangerous shell injection or control characters in target name
        if re.search(r"[\s\x00-\x1f`\$\&\|;\<\>]", host):
            return False, f"Target '{host}' contains illegal or dangerous characters."

        # Parse target if it is an IP address
        target_ip_net = self._parse_ip_or_network(host)
        target_ip = target_ip_net.network_address if target_ip_net else None

        # -------------------------------------------------------------
        # STEP 1: EXCLUSION PRECEDENCE (Strictly overrides all inclusions)
        # -------------------------------------------------------------
        # 1a. Direct hostname exclusion match
        if host in self._parsed_exclusions:
            return False, f"Target '{host}' is explicitly excluded in assessment scope."

        # 1b. Domain/Subdomain exclusion match
        for ex in self._parsed_exclusions:
            if host.endswith(f".{ex}"):
                return False, f"Target '{host}' is a subdomain of explicitly excluded domain '{ex}'."

        # 1c. IP in excluded network
        if target_ip:
            for ex_net in self._excluded_networks:
                if target_ip in ex_net:
                    return False, f"Target IP '{target_ip}' falls within explicitly excluded network '{ex_net}'."

        # -------------------------------------------------------------
        # STEP 2: INCLUSION MATCHING
        # -------------------------------------------------------------
        # 2a. IP network inclusion
        if target_ip:
            for net in self._ip_networks:
                if target_ip in net:
                    return True, f"Target IP '{target_ip}' is authorized under network '{net}'."

        # 2b. Exact hostname inclusion
        if host in self._parsed_targets:
            return True, f"Target host '{host}' is explicitly authorized."

        # 2c. Subdomain inclusion
        if self.config.allow_subdomains:
            for authorized in self._parsed_targets:
                if host.endswith(f".{authorized}"):
                    return True, f"Target '{host}' is an authorized subdomain of '{authorized}'."

        # -------------------------------------------------------------
        # STEP 3: METADATA & FORBIDDEN IP PROTECTION (SSRF / Rebinding)
        # -------------------------------------------------------------
        if target_ip:
            # Link-local / cloud metadata is never allowed unless explicitly authorized
            for meta_net in METADATA_IPS:
                if target_ip in meta_net:
                    return False, f"Target IP '{target_ip}' is in forbidden cloud-metadata/link-local range '{meta_net}'."

            # Loopback protection
            if not self.config.allow_loopback:
                for loop_net in LOOPBACK_NETWORKS:
                    if target_ip in loop_net:
                        return False, f"Target IP '{target_ip}' is loopback, which is disabled in this scope."

            # Private network protection
            if not self.config.allow_private_ips:
                for priv_net in PRIVATE_NETWORKS:
                    if target_ip in priv_net:
                        return False, f"Target IP '{target_ip}' is private RFC-1918/RFC-4193, which is disabled in this scope."

        # -------------------------------------------------------------
        # STEP 4: DNS RESOLUTION & REBINDING VERIFICATION
        # -------------------------------------------------------------
        should_check_dns = self.config.dns_check_enabled if check_dns is None else check_dns
        if should_check_dns and not target_ip:
            resolved_ips = self._resolve_host(host)
            if resolved_ips:
                for res_ip in resolved_ips:
                    # Check exclusions against resolved IP
                    for ex_net in self._excluded_networks:
                        if res_ip in ex_net:
                            return False, f"Target '{host}' resolved to excluded IP '{res_ip}' in network '{ex_net}'."

                    # Check metadata/SSRF on resolved IP
                    for meta_net in METADATA_IPS:
                        if res_ip in meta_net:
                            return False, f"Target '{host}' resolved to forbidden cloud-metadata IP '{res_ip}'."

                    # Check loopback on resolved IP
                    if not self.config.allow_loopback:
                        for loop_net in LOOPBACK_NETWORKS:
                            if res_ip in loop_net:
                                return False, f"Target '{host}' resolved to forbidden loopback IP '{res_ip}' (DNS rebinding protection)."

                    # Check private IP on resolved IP
                    if not self.config.allow_private_ips:
                        for priv_net in PRIVATE_NETWORKS:
                            if res_ip in priv_net:
                                return False, f"Target '{host}' resolved to unpermitted private network IP '{res_ip}'."

        return False, f"Target '{host}' is NOT in authorized scope. Permitted targets: {self.config.targets}"

    def _resolve_host(self, host: str) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """Resolves hostname to IP addresses with local caching."""
        if host in self._dns_cache:
            return self._dns_cache[host]

        ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
        try:
            addr_info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)
                if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                    ip_obj = ip_obj.ipv4_mapped
                if ip_obj not in ips:
                    ips.append(ip_obj)
        except Exception:
            pass

        self._dns_cache[host] = ips
        return ips

    def validate_redirect(self, original_url: str, redirect_url: str) -> Tuple[bool, str]:
        """
        Validates that an HTTP redirect stays strictly within authorized assessment scope.
        Prevents open-redirect attacks from leading the agent into attacking out-of-scope targets.
        """
        if not redirect_url:
            return False, "Redirect destination is empty."

        # If redirect is relative, resolve it relative to original URL
        if not urllib.parse.urlparse(redirect_url).netloc:
            full_dest = urllib.parse.urljoin(original_url, redirect_url)
        else:
            full_dest = redirect_url

        dest_host = self.normalize_target(full_dest)
        in_scope, reason = self.is_in_scope(dest_host)
        if not in_scope:
            return False, f"Redirect to '{dest_host}' is blocked: {reason}"

        return True, f"Redirect to '{dest_host}' is authorized."
