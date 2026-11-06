"""
OWASP Top 10 (2021/Latest) Knowledge Base.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class OWASPCategory(BaseModel):
    category_id: str
    name: str
    description: str
    top_cwes: List[str]
    prevention_steps: List[str]


OWASP_TOP_10: Dict[str, OWASPCategory] = {
    "A01:2021": OWASPCategory(
        category_id="A01:2021",
        name="Broken Access Control",
        description="Failures leading to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside the user's limits.",
        top_cwes=["CWE-862", "CWE-22", "CWE-284"],
        prevention_steps=[
            "Enforce access controls on the server side for every endpoint.",
            "Deny access by default.",
            "Disable web server directory listing.",
            "Log access control failures and rate-limit sensitive endpoints."
        ]
    ),
    "A02:2021": OWASPCategory(
        category_id="A02:2021",
        name="Cryptographic Failures",
        description="Exposure of sensitive data due to inadequate cryptographic protection in transit or at rest.",
        top_cwes=["CWE-327", "CWE-310", "CWE-312"],
        prevention_steps=[
            "Classify data processed, stored, or transmitted by an application.",
            "Enforce encryption in transit with TLS 1.3 and HSTS.",
            "Store passwords using salted adaptive hashing (Argon2, bcrypt).",
            "Do not use legacy cryptographic protocols (MD5, SHA1, DES)."
        ]
    ),
    "A03:2021": OWASPCategory(
        category_id="A03:2021",
        name="Injection",
        description="Hostile data sent to an interpreter as part of a command or query (SQL, NoSQL, OS command, LDAP).",
        top_cwes=["CWE-89", "CWE-78", "CWE-79"],
        prevention_steps=[
            "Use parameterized queries (prepared statements).",
            "Use positive or 'whitelist' server-side input validation.",
            "Context-aware escape special characters for output interpreters."
        ]
    ),
    "A04:2021": OWASPCategory(
        category_id="A04:2021",
        name="Insecure Design",
        description="Flaws related to architecture and design deficiencies, missing threat modeling, or lacking security controls.",
        top_cwes=["CWE-209", "CWE-256", "CWE-501"],
        prevention_steps=[
            "Establish a secure development lifecycle (SDL) with threat modeling.",
            "Integrate security design patterns into early architectural reviews.",
            "Limit resource consumption per user/tenant."
        ]
    ),
    "A05:2021": OWASPCategory(
        category_id="A05:2021",
        name="Security Misconfiguration",
        description="Missing security hardening across application stacks, improperly configured cloud permissions, default accounts, or verbose error messages.",
        top_cwes=["CWE-16", "CWE-209", "CWE-611"],
        prevention_steps=[
            "Automate repeatable hardening processes.",
            "Remove unnecessary features, components, documentation, and samples.",
            "Implement strong Content-Security-Policy (CSP) and security headers.",
            "Send security directives such as HSTS, X-Content-Type-Options: nosniff."
        ]
    ),
    "A06:2021": OWASPCategory(
        category_id="A06:2021",
        name="Vulnerable and Outdated Components",
        description="Running software or libraries with known CVEs or unpatched dependencies.",
        top_cwes=["CWE-1104", "CWE-1035"],
        prevention_steps=[
            "Maintain an up-to-date Software Bill of Materials (SBOM).",
            "Continuously scan dependencies using tools like Trivy, OSV, or npm audit.",
            "Only obtain components from official, verified sources over secure links."
        ]
    ),
    "A07:2021": OWASPCategory(
        category_id="A07:2021",
        name="Identification and Authentication Failures",
        description="Authentication and session management flaws enabling brute-force attacks, credential stuffing, or session hijacking.",
        top_cwes=["CWE-287", "CWE-384", "CWE-613"],
        prevention_steps=[
            "Implement multi-factor authentication where possible.",
            "Do not ship or deploy with default credentials.",
            "Implement rate-limiting and account lockout mechanisms against brute force.",
            "Use secure, server-side session management."
        ]
    ),
    "A08:2021": OWASPCategory(
        category_id="A08:2021",
        name="Software and Data Integrity Failures",
        description="Code and infrastructure that does not protect against integrity violations (e.g., untrusted CI/CD pipelines, insecure deserialization).",
        top_cwes=["CWE-502", "CWE-829"],
        prevention_steps=[
            "Use digital signatures to verify software or data from untrusted sources.",
            "Avoid insecure deserialization of user-controlled objects.",
            "Ensure CI/CD build pipelines have segregated access controls and code signing."
        ]
    ),
    "A09:2021": OWASPCategory(
        category_id="A09:2021",
        name="Security Logging and Monitoring Failures",
        description="Insufficient logging, detection, monitoring, and active response to breach attempts.",
        top_cwes=["CWE-778", "CWE-117"],
        prevention_steps=[
            "Ensure all login, access control, and server-side input validation failures are logged.",
            "Ensure log data is formatted to prevent log injection.",
            "Establish real-time monitoring and alerting for suspicious events."
        ]
    ),
    "A10:2021": OWASPCategory(
        category_id="A10:2021",
        name="Server-Side Request Forgery (SSRF)",
        description="Web applications fetching remote resources without validating user-supplied destination URLs.",
        top_cwes=["CWE-918"],
        prevention_steps=[
            "Segment remote resource access in separate networks.",
            "Enforce strict destination IP/scheme/port allowlists.",
            "Disable HTTP redirections and do not forward raw responses to the client."
        ]
    )
}


def lookup_owasp(category_id: str) -> Optional[OWASPCategory]:
    """Lookup OWASP category (e.g., 'A01', 'A01:2021', 'A03')."""
    clean_id = category_id.upper().strip()
    for cat_key, cat in OWASP_TOP_10.items():
        if clean_id in cat_key or clean_id == cat_key.split(":")[0]:
            return cat
    return None
