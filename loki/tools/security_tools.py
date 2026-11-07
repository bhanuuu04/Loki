"""
Agent Tools for Cybersecurity Research and Auditing.
Binds together ScopeManager, PolicyEngine, ToolRegistry, and AssessmentStore
under a single shared AssessmentSecurityContext.
"""

from typing import Any, Dict, List, Optional, Union
import httpx
import socket
import asyncio
import re
import hmac

from loki.tools.base import tool, ToolCapability
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode
from loki.security.gateway import ExecutionGateway
from loki.security.context import AssessmentSecurityContext
from loki.knowledge.cwe_database import lookup_cwe
from loki.knowledge.owasp_knowledge import lookup_owasp
from loki.knowledge.tool_registry.catalog import SecurityToolCatalog
from loki.executor.process_manager import SecureProcessExecutor
from loki.executor.output_parser import OutputParser
from loki.assessment.store import AssessmentStore
from loki.assessment.models import (
    DiscoveredAsset,
    SecurityFinding,
    SeverityLevel,
    ConfidenceLevel,
)
from loki.config import settings


# Dynamic proxies ensuring calls always reflect the shared AssessmentSecurityContext
class _ScopeManagerProxy:
    def __getattr__(self, item: str) -> Any:
        return getattr(AssessmentSecurityContext.get_default().scope_manager, item)


class _PolicyEngineProxy:
    def __getattr__(self, item: str) -> Any:
        return getattr(AssessmentSecurityContext.get_default().policy_engine, item)


class _AssessmentStoreProxy:
    def __getattr__(self, item: str) -> Any:
        return getattr(AssessmentSecurityContext.get_default().assessment_store, item)


scope_mgr = _ScopeManagerProxy()
policy_engine = _PolicyEngineProxy()
assessment_store = _AssessmentStoreProxy()
tool_catalog = SecurityToolCatalog()
process_executor = SecureProcessExecutor()


def authorize_target(target: str, authorization_token: Optional[str] = None) -> str:
    """
    Verify if a target domain or IP is within the authorized assessment scope.
    Autonomous self-authorization by LLM reasoning is blocked to enforce scope correctness.
    """
    ctx = AssessmentSecurityContext.get_default()
    if not ctx.active_assessment_id:
        return "Authorization Denied: No active assessment is bound to this session."
    cleaned = ctx.scope_manager.normalize_target(target)
    if not cleaned:
        return "Error: Target identifier cannot be empty or invalid."

    in_scope, reason = ctx.scope_manager.is_in_scope(cleaned)
    if in_scope:
        return f"Target '{cleaned}' is verified and within authorized assessment scope ({reason})."

    # 1. Check cryptographically signed operator ticket
    if authorization_token and "." in authorization_token:
        from loki.security.authorization import OperatorAuthorizationManager
        is_valid, auth_reason, ticket = OperatorAuthorizationManager.verify_ticket(
            token_str=authorization_token,
            assessment_id=ctx.active_assessment_id,
            target=cleaned,
        )
        if is_valid and ticket:
            ctx.scope_manager.update_targets(
                add_targets=[cleaned],
                author=f"ticket:{ticket.issued_by}",
                reason=f"Signed operator ticket {ticket.ticket_id} verified for {cleaned}",
            )
            return f"Target '{cleaned}' has been authorized via signed operator ticket under scope version {ctx.scope_manager.config.version}."

    # 2. Check static operator master token if configured
    expected_token = settings.operator_token
    if (expected_token and len(expected_token.encode("utf-8")) >= 32
            and authorization_token
            and hmac.compare_digest(authorization_token.strip(), expected_token)):
        ctx.scope_manager.update_targets(
            add_targets=[cleaned],
            author="verified_operator",
            reason=f"Explicit operator authorization verified for {cleaned}",
        )
        return f"Target '{cleaned}' has been explicitly authorized under scope version {ctx.scope_manager.config.version}."

    return (
        f"Authorization Denied: Target '{cleaned}' is not authorized. "
        "Autonomous self-authorization by the model is disabled. "
        "An authenticated operator must update the active assessment scope."
    )


def configure_scope(
    targets: Union[List[str], str],
    assessment_name: Optional[str] = None,
    excluded_targets: Optional[Union[List[str], str]] = None,
    execution_mode: str = "safe",
    operator_token: Optional[str] = None,
    operator_name: str = "operator",
    reason: Optional[str] = None,
) -> str:
    """
    Trusted operator API for scope setup; deliberately not exposed as an LLM tool.
    The caller must supply the independently provisioned LOKI_OPERATOR_TOKEN.
    """
    expected_token = settings.operator_token
    if not expected_token or len(expected_token.encode("utf-8")) < 32:
        return "Scope configuration denied: configure a high-entropy LOKI_OPERATOR_TOKEN (at least 32 bytes) first."
    if not operator_token or not hmac.compare_digest(operator_token, expected_token):
        return "Scope configuration denied: valid operator authentication is required."

    ctx = AssessmentSecurityContext.get_default()

    if isinstance(targets, str):
        if "," in targets:
            target_list = [t.strip() for t in targets.split(",") if t.strip()]
        else:
            target_list = [targets.strip()]
    elif isinstance(targets, (list, tuple)):
        target_list = [str(t).strip() for t in targets if str(t).strip()]
    else:
        target_list = [str(targets).strip()]

    cleaned_targets = []
    for t in target_list:
        c = ctx.scope_manager.normalize_target(t)
        if c:
            cleaned_targets.append(c)

    if not cleaned_targets:
        return "Scope configuration denied: at least one valid target is required."

    clean_excluded = []
    if excluded_targets:
        if isinstance(excluded_targets, str):
            clean_excluded = [ctx.scope_manager.normalize_target(e.strip()) for e in excluded_targets.split(",") if e.strip()]
        elif isinstance(excluded_targets, (list, tuple)):
            clean_excluded = [ctx.scope_manager.normalize_target(str(e)) for e in excluded_targets if str(e).strip()]

    clean_excluded = [target for target in clean_excluded if target]
    name = assessment_name or f"Assessment-{cleaned_targets[0]}"

    mode = ExecutionMode.SAFE
    if execution_mode:
        try:
            mode = ExecutionMode.parse(execution_mode)
        except ValueError:
            return "Scope configuration denied: execution_mode must be safe, audit, or nomercy."

    config = ScopeConfig(
        assessment_name=name,
        targets=cleaned_targets,
        excluded_targets=clean_excluded,
        allow_subdomains=True,
    )
    ctx.configure_scope(
        config=config,
        mode=mode,
        author="authenticated_operator",
        reason=reason or f"Configured scope for {name}",
        operator_confirmed=True,
    )

    # Initialize assessment session in store
    clean_sess_id = re.sub(r"[^a-zA-Z0-9_]", "_", name.lower())
    session_id = f"audit_{clean_sess_id}"
    session = ctx.assessment_store.create_assessment(
        session_id=session_id,
        name=name,
        scope=config,
    )
    session.execution_mode = mode
    ctx.assessment_store.save_assessment(session)
    ctx.active_assessment_id = session_id

    return f"Scope successfully configured for '{name}'. Authorized Targets: {cleaned_targets}. Excluded: {clean_excluded}. Mode: {mode.value.upper()}."


@tool(
    name="check_scope_authorization",
    description="Verify if a target host, IP, or URL is within the authorized assessment scope.",
    capabilities=[ToolCapability.UTILITY],
)
def check_scope(target: str) -> str:
    """Check if target is authorized under scope."""
    allowed, reason = scope_mgr.is_in_scope(target)
    return f"Target: {target} | In Scope: {allowed} | Details: {reason}"


@tool(
    name="search_security_tool_catalog",
    description="Search the Kali security tool registry by objective (e.g. 'port scan', 'ssl', 'cve', 'web').",
    capabilities=[ToolCapability.UTILITY],
)
def search_tools(query: str) -> str:
    """Find relevant security tools from the registry."""
    matches = tool_catalog.search_by_objective(query)
    if not matches:
        return f"No documented tools matched query: '{query}'."

    results = []
    for t in matches[:5]:
        status = "[INSTALLED]" if t.is_installed else "[NOT INSTALLED ON PATH]"
        cmd_purposes = "; ".join(c.purpose for c in t.commands)
        results.append(f"• {t.name} {status} ({t.category.value}): {t.description}\n  Commands: {cmd_purposes}\n  Install: {t.installation_method}")

    return "\n\n".join(results)


@tool(
    name="lookup_cwe_knowledge",
    description="Lookup official CWE definition, impact, and remediation steps (e.g., 'CWE-89' or 'CWE-79').",
    capabilities=[ToolCapability.UTILITY],
)
def get_cwe(cwe_id: str) -> str:
    """Retrieve CWE details and remediation."""
    cwe = lookup_cwe(cwe_id)
    if not cwe:
        return f"CWE '{cwe_id}' not found in local database."
    return (
        f"[{cwe.cwe_id}] {cwe.name}\n\n"
        f"Description:\n{cwe.description}\n\n"
        f"Common Impact:\n{cwe.common_impact}\n\n"
        f"Remediation Guidance:\n{cwe.remediation}\n\n"
        f"References: {', '.join(cwe.references)}"
    )


@tool(
    name="lookup_owasp_guidelines",
    description="Retrieve OWASP Top 10 category description and prevention steps (e.g., 'A01', 'A03', 'Injection').",
    capabilities=[ToolCapability.UTILITY],
)
def get_owasp(category: str) -> str:
    """Retrieve OWASP Top 10 category."""
    cat = lookup_owasp(category)
    if not cat:
        return f"OWASP category '{category}' not found."
    steps = "\n".join(f" - {step}" for step in cat.prevention_steps)
    return (
        f"[{cat.category_id}] {cat.name}\n"
        f"Description: {cat.description}\n"
        f"Associated CWEs: {', '.join(cat.top_cwes)}\n\n"
        f"Prevention Guidelines:\n{steps}"
    )


@tool(
    name="audit_http_security_headers",
    description="Audit HTTP security headers on an authorized web endpoint.",
    capabilities=[ToolCapability.NETWORK, ToolCapability.TARGET_INTERACTION],
)
async def audit_headers(url: str) -> str:
    """Audit HTTP response security headers."""
    is_allowed, reason = scope_mgr.is_in_scope(url)
    if not is_allowed:
        return f"Authorization Error: {reason}"

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
            headers = dict(resp.headers)
            analysis = OutputParser.parse_security_headers(headers)

            lines = [
                f"HTTP Audit for {url} (Status: {resp.status_code})",
                f"Present Security Headers ({analysis['present_count']}):",
            ]
            for h, val in analysis["present_headers"].items():
                if val:
                    lines.append(f"  + {h}: {val}")

            lines.append(f"\nMissing Recommended Security Headers ({analysis['missing_count']}):")
            for h in analysis["missing_headers"]:
                lines.append(f"  - {h}")

            if analysis["server_banner"]:
                lines.append(f"\nIdentified Server Banner: {analysis['server_banner']}")

            return "\n".join(lines)
    except Exception as e:
        return f"Header audit error: {type(e).__name__}: {str(e)}"


@tool(
    name="record_security_finding",
    description="Record a validated vulnerability or configuration weakness into the assessment report.",
    capabilities=[ToolCapability.UTILITY],
)
def record_finding(
    session_id: str,
    finding_id: str,
    title: str,
    description: str,
    affected_asset: str,
    severity: str,
    remediation: str,
    cwe_id: Optional[str] = None,
    cvss_score: float = 0.0,
    evidence: str = "",
) -> str:
    """Record finding into assessment store."""
    try:
        sev = SeverityLevel(severity.lower())
    except ValueError:
        sev = SeverityLevel.MEDIUM

    finding = SecurityFinding(
        finding_id=finding_id,
        title=title,
        description=description,
        affected_asset=affected_asset,
        category="Vulnerability Assessment",
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        severity=sev,
        confidence=ConfidenceLevel.CONFIRMED,
        evidence=evidence,
        remediation=remediation,
    )
    assessment_store.add_finding(session_id, finding)
    return f"Finding '{finding_id}: {title}' recorded in session '{session_id}'."


@tool(
    name="generate_assessment_report",
    description="Export assessment report in Markdown, HTML, and JSON formats.",
    capabilities=[ToolCapability.UTILITY],
)
def generate_report(session_id: str) -> str:
    """Export security report."""
    from loki.reporting.generator import ReportGenerator

    session = assessment_store.load_assessment(session_id)
    if not session:
        return f"Session '{session_id}' not found in store."

    generator = ReportGenerator(session)
    exported = generator.export_all()
    return (
        f"Assessment report generated successfully!\n"
        f"• Markdown: {exported['markdown']}\n"
        f"• HTML: {exported['html']}\n"
        f"• JSON: {exported['json']}\n"
        f"Total Findings: {len(session.findings)}"
    )


@tool(
    name="enumerate_subdomains",
    description="Passively enumerate subdomains for an authorized target domain using Certificate Transparency and DNS reconnaissance.",
    capabilities=[ToolCapability.NETWORK, ToolCapability.TARGET_INTERACTION],
)
async def enumerate_subdomains(domain: str) -> str:
    """Enumerate subdomains passively via Certificate Transparency and verify DNS."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if ":" in domain:
        domain = domain.split(":")[0]

    is_allowed, reason = scope_mgr.is_in_scope(domain)
    if not is_allowed:
        return f"Scope Authorization Error: {reason}"

    discovered_subs = set()

    # 1. Query Certificate Transparency (crt.sh)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            discovered_subs.add(sub)
    except Exception:
        pass

    # 2. Add common standard prefixes as baseline
    common_prefixes = ["www", "mail", "api", "dev", "staging", "blog", "vpn", "admin", "app", "portal", "ns1", "ns2"]
    for p in common_prefixes:
        discovered_subs.add(f"{p}.{domain}")

    # 3. Resolve active subdomains
    active_results = []
    async def _resolve(fqdn: str):
        try:
            loop = asyncio.get_running_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            return (fqdn, ip)
        except Exception:
            return None

    tasks = [_resolve(sub) for sub in sorted(discovered_subs)]
    resolved = await asyncio.gather(*tasks, return_exceptions=True)

    for res in resolved:
        if isinstance(res, tuple) and res is not None:
            active_results.append(res)

    if not active_results:
        return f"No active subdomains resolved for target '{domain}'."

    active_results.sort(key=lambda x: x[0])
    lines = [f"Discovered {len(active_results)} active subdomains for '{domain}':\n"]
    for fqdn, ip in active_results:
        lines.append(f"  • {fqdn} ({ip})")

    return "\n".join(lines)


@tool(
    name="dns_lookup",
    description="Query DNS record resolution (A records, hostname to IP) for a target domain or host.",
    capabilities=[ToolCapability.NETWORK, ToolCapability.TARGET_INTERACTION],
)
async def dns_lookup(domain: str) -> str:
    """Resolve IP address for target domain."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    is_allowed, reason = scope_mgr.is_in_scope(domain)
    if not is_allowed:
        return f"Scope Authorization Error: {reason}"

    try:
        loop = asyncio.get_running_loop()
        ip_list = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
        hostname, aliases, ips = ip_list
        res = [f"DNS Resolution for {domain}:", f"Primary Hostname: {hostname}"]
        if aliases:
            res.append(f"Aliases: {', '.join(aliases)}")
        res.append(f"IP Addresses: {', '.join(ips)}")
        return "\n".join(res)
    except Exception as e:
        return f"DNS resolution failed for '{domain}': {str(e)}"


ALL_SECURITY_TOOLS = [
    # Scope mutation and ticket use are trusted operator APIs, never LLM-callable tools.
    check_scope,
    enumerate_subdomains,
    dns_lookup,
    search_tools,
    get_cwe,
    get_owasp,
    audit_headers,
    record_finding,
    generate_report,
]
