"""
CWE (Common Weakness Enumeration) knowledge base.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class CWEDefinition(BaseModel):
    cwe_id: str
    name: str
    description: str
    common_impact: str
    remediation: str
    references: List[str] = []


CWE_DATABASE: Dict[str, CWEDefinition] = {
    "CWE-89": CWEDefinition(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description="The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        common_impact="Unauthorized data disclosure, data modification, or administrative bypass.",
        remediation="Use parameterized queries (prepared statements) or stored procedures. Never concatenate raw user input into SQL queries. Implement input validation and ORM parameter binding.",
        references=["https://cwe.mitre.org/data/definitions/89.html", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
    ),
    "CWE-79": CWEDefinition(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        common_impact="Execution of malicious scripts in the victim's browser, session hijacking, defacement.",
        remediation="Context-aware output encoding (HTML, JavaScript, CSS), use Content Security Policy (CSP), and adopt modern frameworks with built-in auto-escaping (React, Angular).",
        references=["https://cwe.mitre.org/data/definitions/79.html"]
    ),
    "CWE-918": CWEDefinition(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but does not sufficiently ensure that the request is being sent to the expected destination.",
        common_impact="Access to internal services, cloud metadata APIs (e.g. 169.254.169.254), and intranet port scanning.",
        remediation="Enforce strict allowlists for destination schemes, hosts, and ports. Block private IP ranges (RFC 1918) and link-local addresses at the network and application layer.",
        references=["https://cwe.mitre.org/data/definitions/918.html"]
    ),
    "CWE-22": CWEDefinition(
        cwe_id="CWE-22",
        name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description="The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements such as '..' sequences.",
        common_impact="Arbitrary file reading, disclosure of sensitive system files, configuration leakage.",
        remediation="Validate paths using canonicalization (e.g., path.resolve()), verify the target path begins with the intended root directory, or use indirect IDs/lookups instead of direct file paths.",
        references=["https://cwe.mitre.org/data/definitions/22.html"]
    ),
    "CWE-78": CWEDefinition(
        cwe_id="CWE-78",
        name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description="The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
        common_impact="Execution of arbitrary operating system commands with application privileges.",
        remediation="Avoid invoking shell commands directly. Use native language APIs or pass arguments as separate arrays without invoking a shell interpreter.",
        references=["https://cwe.mitre.org/data/definitions/78.html"]
    ),
    "CWE-352": CWEDefinition(
        cwe_id="CWE-352",
        name="Cross-Site Request Forgery (CSRF)",
        description="The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        common_impact="Unintended user actions performed on authenticated sessions.",
        remediation="Implement anti-CSRF tokens (synchronizer token pattern) and set SameSite=Lax or SameSite=Strict cookies on session identifiers.",
        references=["https://cwe.mitre.org/data/definitions/352.html"]
    ),
    "CWE-287": CWEDefinition(
        cwe_id="CWE-287",
        name="Improper Authentication",
        description="When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        common_impact="Unauthorized access, credential stuffing vulnerability, account takeover.",
        remediation="Implement multi-factor authentication (MFA), secure password storage (Argon2id, bcrypt), and rate-limit authentication endpoints.",
        references=["https://cwe.mitre.org/data/definitions/287.html"]
    ),
    "CWE-862": CWEDefinition(
        cwe_id="CWE-862",
        name="Missing Authorization (Broken Object Level Authorization / IDOR)",
        description="The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        common_impact="Privilege escalation, unauthorized data tampering, tenant data leakage.",
        remediation="Implement server-side object-level access controls for every request. Validate that the requesting user possesses authorization to access the specific record ID.",
        references=["https://cwe.mitre.org/data/definitions/862.html"]
    ),
}


def lookup_cwe(cwe_id: str) -> Optional[CWEDefinition]:
    """Retrieve CWE details by ID (e.g., 'CWE-89' or '89')."""
    clean_id = cwe_id.upper().strip()
    if not clean_id.startswith("CWE-"):
        clean_id = f"CWE-{clean_id}"
    return CWE_DATABASE.get(clean_id)
