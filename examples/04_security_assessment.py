"""
Example 04: Cybersecurity Assessment & Reporting Workflow.
Demonstrates Scope Enforcement, Tool Discovery, CWE/OWASP Knowledge, and Report Generation.
"""

import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
from loki.security import ScopeManager, ScopeConfig, PolicyEngine, ExecutionMode
from loki.knowledge import SecurityToolCatalog, lookup_cwe, lookup_owasp
from loki.assessment import AssessmentStore, SecurityFinding, SeverityLevel, ConfidenceLevel
from loki.reporting import ReportGenerator


def main():
    print("=== Loki Cybersecurity Assessment Harness ===\n")

    # 1. Initialize Scope & Policy
    scope_config = ScopeConfig(
        assessment_name="Q4 Production Infrastructure Audit",
        organization="Acme Security Labs",
        targets=["app.acme-corp.test", "192.168.1.0/24"],
        excluded_targets=["production-db.acme-corp.test", "192.168.1.50"],
    )
    scope = ScopeManager(scope_config)
    policy = PolicyEngine(scope_manager=scope, mode=ExecutionMode.SAFE)

    # 2. Scope Validation
    print("--- 1. Scope Boundary Checks ---")
    test_targets = [
        "app.acme-corp.test",
        "api.app.acme-corp.test",
        "production-db.acme-corp.test",
        "192.168.1.15",
        "192.168.1.50",
        "unauthorized-target.com",
    ]
    for target in test_targets:
        allowed, reason = scope.is_in_scope(target)
        status = "[ALLOWED]" if allowed else "[BLOCKED]"
        print(f"{status} {target}: {reason}")

    # 3. Security Tool Knowledge Base Search
    print("\n--- 2. Kali Security Tool Registry Search ---")
    catalog = SecurityToolCatalog()
    matches = catalog.search_by_objective("port scan")
    print(f"Found {len(matches)} matching tools for 'port scan':")
    for t in matches[:2]:
        installed_str = "Installed" if t.is_installed else "Not Installed on PATH"
        print(f" • {t.name} ({installed_str}) - {t.description}")
        for cmd in t.commands[:1]:
            print(f"   Syntax: {cmd.syntax} (Risk: {cmd.risk_level})")

    # 4. CWE & OWASP Knowledge Retrieval
    print("\n--- 3. Security Knowledge Engine Lookup ---")
    cwe_info = lookup_cwe("CWE-89")
    print(f"CWE-89 ({cwe_info.name}):")
    print(f"  Remediation: {cwe_info.remediation[:110]}...")

    owasp_info = lookup_owasp("A01")
    print(f"\nOWASP Top 10 ({owasp_info.category_id} - {owasp_info.name}):")
    print(f"  Top Prevention: {owasp_info.prevention_steps[0]}")

    # 5. Assessment Session & Findings Management
    print("\n--- 4. Assessment Findings & Evidence Recording ---")
    store = AssessmentStore()
    session = store.create_assessment("audit_demo_01", "Demo Security Audit", scope_config)

    finding = SecurityFinding(
        finding_id="VULN-001",
        title="Missing HTTP Strict-Transport-Security (HSTS) Header",
        description="The web server does not send the HSTS header, allowing potential SSL-stripping attacks on insecure networks.",
        affected_asset="app.acme-corp.test",
        affected_endpoint="/login",
        category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-16",
        cvss_score=4.3,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.CONFIRMED,
        evidence="HTTP/1.1 200 OK\nServer: nginx/1.18.0\n[Strict-Transport-Security is missing]",
        remediation="Configure the web server to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    )
    store.add_finding("audit_demo_01", finding)
    print(f"Added Finding '{finding.finding_id}: {finding.title}' to assessment.")

    # 6. Report Generation
    print("\n--- 5. Generating Security Assessment Reports ---")
    updated_session = store.load_assessment("audit_demo_01")
    generator = ReportGenerator(updated_session)
    exported = generator.export_all()

    print(f"[+] Markdown Report: {exported['markdown']}")
    print(f"[+] HTML Report:     {exported['html']}")
    print(f"[+] JSON Data:        {exported['json']}")


if __name__ == "__main__":
    main()
