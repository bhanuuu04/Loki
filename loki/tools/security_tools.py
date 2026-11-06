"""
Agent Tools for Cybersecurity Research and Auditing.
Binds together ScopeManager, PolicyEngine, ToolRegistry, and AssessmentStore.
"""

from typing import Any, Dict, List, Optional
import httpx

from loki.tools.base import tool
from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode
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

# Global shared context singletons
scope_mgr = ScopeManager()
policy_engine = PolicyEngine(scope_manager=scope_mgr)
tool_catalog = SecurityToolCatalog()
process_executor = SecureProcessExecutor()
assessment_store = AssessmentStore()


@tool(name="configure_assessment_scope", description="Initialize or update authorized assessment scope and targets.")
def configure_scope(
    assessment_name: str,
    targets: List[str],
    excluded_targets: Optional[List[str]] = None,
    execution_mode: str = "safe",
) -> str:
    """Set the assessment scope and boundaries."""
    mode = ExecutionMode(execution_mode.lower()) if execution_mode.lower() in ("safe", "aggressive", "advanced_audit") else ExecutionMode.SAFE
    config = ScopeConfig(
        assessment_name=assessment_name,
        targets=targets,
        excluded_targets=excluded_targets or [],
    )
    scope_mgr.set_config(config)
    policy_engine.set_mode(mode)
    
    # Initialize assessment session
    session_id = f"audit_{assessment_name.lower().replace(' ', '_')}"
    session = assessment_store.create_assessment(
        session_id=session_id,
        name=assessment_name,
        scope=config,
    )
    session.execution_mode = mode
    assessment_store.save_assessment(session)

    return f"Scope successfully configured for '{assessment_name}'. Targets: {targets}. Excluded: {excluded_targets or []}. Mode: {mode.value.upper()}. Session ID: {session_id}."


@tool(name="check_scope_authorization", description="Verify if a target host, IP, or URL is within the authorized assessment scope.")
def check_scope(target: str) -> str:
    """Check if target is authorized under scope."""
    allowed, reason = scope_mgr.is_in_scope(target)
    return f"Target: {target} | In Scope: {allowed} | Details: {reason}"


@tool(name="search_security_tool_catalog", description="Search the Kali security tool registry by objective (e.g. 'port scan', 'ssl', 'cve', 'web').")
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


@tool(name="lookup_cwe_knowledge", description="Lookup official CWE definition, impact, and remediation steps (e.g., 'CWE-89' or 'CWE-79').")
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


@tool(name="lookup_owasp_guidelines", description="Retrieve OWASP Top 10 category description and prevention steps (e.g., 'A01', 'A03', 'Injection').")
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


@tool(name="audit_http_security_headers", description="Audit HTTP security headers on an authorized web endpoint.")
async def audit_headers(url: str) -> str:
    """Audit HTTP response security headers."""
    # Scope check
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


@tool(name="record_security_finding", description="Record a validated vulnerability or configuration weakness into the assessment report.")
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


@tool(name="generate_assessment_report", description="Export assessment report in Markdown, HTML, and JSON formats.")
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


ALL_SECURITY_TOOLS = [
    configure_scope,
    check_scope,
    search_tools,
    get_cwe,
    get_owasp,
    audit_headers,
    record_finding,
    generate_report,
]
