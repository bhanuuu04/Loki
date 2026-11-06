"""
Security Assessment Report Generator.
Produces professional Markdown, HTML, and JSON reports with executive summaries,
vulnerability breakdowns, evidence, and actionable remediation steps.
"""

from typing import Dict, List, Optional
import time
from pathlib import Path

from loki.assessment.models import AssessmentSession, SecurityFinding, SeverityLevel


class ReportGenerator:
    """Compiles assessment session data into comprehensive security reports."""

    def __init__(self, session: AssessmentSession):
        self.session = session

    def _calculate_metrics(self) -> Dict[str, int]:
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.INFORMATIONAL.value: 0,
        }
        for f in self.session.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_markdown(self) -> str:
        metrics = self._calculate_metrics()
        total_findings = len(self.session.findings)
        date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.session.updated_at))

        md = []
        md.append(f"# Security Assessment Report: {self.session.assessment_name}\n")
        md.append(f"**Generated:** {date_str}  ")
        md.append(f"**Session ID:** `{self.session.session_id}`  ")
        md.append(f"**Execution Mode:** `{self.session.execution_mode.value.upper()}`  \n")
        md.append("---\n")

        # Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(
            f"This security assessment evaluated the authorized target assets under scope for "
            f"**{self.session.scope.organization or self.session.assessment_name}**. "
            f"During the assessment, **{total_findings} finding(s)** were identified across "
            f"**{len(self.session.assets)} discovered asset(s)**.\n"
        )

        md.append("### Severity Distribution\n")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| **CRITICAL** | {metrics['critical']} |")
        md.append(f"| **HIGH** | {metrics['high']} |")
        md.append(f"| **MEDIUM** | {metrics['medium']} |")
        md.append(f"| **LOW** | {metrics['low']} |")
        md.append(f"| **INFORMATIONAL** | {metrics['informational']} |\n")

        # Scope & Attack Surface
        md.append("## 2. Scope & Attack Surface Overview\n")
        md.append(f"- **Authorized Targets:** {', '.join(self.session.scope.targets) or 'None'}")
        md.append(f"- **Excluded Targets:** {', '.join(self.session.scope.excluded_targets) or 'None'}\n")

        if self.session.assets:
            md.append("### Discovered Assets & Services\n")
            md.append("| Asset | IP Address | Open Ports | Identified Technologies |")
            md.append("| :--- | :--- | :--- | :--- |")
            for asset in self.session.assets.values():
                ports_str = ", ".join(str(p) for p in asset.open_ports) or "None detected"
                tech_str = ", ".join(asset.technologies) or "N/A"
                md.append(f"| `{asset.identifier}` | {asset.ip_address or 'N/A'} | {ports_str} | {tech_str} |")
            md.append("")

        # Detailed Findings
        md.append("## 3. Detailed Security Findings\n")
        if not self.session.findings:
            md.append("*No vulnerabilities or security weaknesses were identified in this session.*\n")
        else:
            for idx, finding in enumerate(self.session.findings, 1):
                md.append(f"### {idx}. [{finding.severity.value.upper()}] {finding.title}\n")
                md.append(f"- **Finding ID:** `{finding.finding_id}`")
                md.append(f"- **Affected Asset:** `{finding.affected_asset}`")
                if finding.affected_endpoint:
                    md.append(f"- **Affected Endpoint:** `{finding.affected_endpoint}`")
                if finding.cwe_id:
                    md.append(f"- **CWE:** {finding.cwe_id}")
                if finding.cve_id:
                    md.append(f"- **CVE:** {finding.cve_id}")
                md.append(f"- **CVSS v3.1 Score:** {finding.cvss_score:.1f}")
                md.append(f"- **Confidence:** {finding.confidence.value.title()}\n")

                md.append("#### Description")
                md.append(f"{finding.description}\n")

                if finding.evidence:
                    md.append("#### Evidence / Technical Observation")
                    md.append(f"```text\n{finding.evidence.strip()}\n```\n")

                md.append("#### Remediation & Recommendations")
                md.append(f"{finding.remediation}\n")

                if finding.references:
                    md.append("#### References")
                    for ref in finding.references:
                        md.append(f"- {ref}")
                    md.append("")
                md.append("---\n")

        # Remediation Roadmap
        md.append("## 4. Remediation Roadmap & Best Practices\n")
        md.append("1. **Address Critical and High Severity Weaknesses Immediately:** Patch outdated software and resolve access-control or injection flaws.")
        md.append("2. **Implement Defense in Depth:** Enforce strict Content Security Policy, HSTS, and parameter validation across all incoming requests.")
        md.append("3. **Continuous Auditing:** Regularly execute automated scans and configuration audits in CI/CD build pipelines.\n")

        return "\n".join(md)

    def to_html(self) -> str:
        metrics = self._calculate_metrics()
        date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.session.updated_at))

        findings_html = []
        for f in self.session.findings:
            badge_color = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "informational": "#6b7280",
            }.get(f.severity.value, "#6b7280")

            findings_html.append(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <h3 style="margin:0;color:#fff;">{f.title}</h3>
                    <span style="background:{badge_color};color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;">
                        {f.severity.value.upper()} (CVSS {f.cvss_score:.1f})
                    </span>
                </div>
                <p style="color:#8b949e;font-size:13px;margin:5px 0;"><b>Asset:</b> {f.affected_asset} {f'| <b>Endpoint:</b> {f.affected_endpoint}' if f.affected_endpoint else ''} | <b>CWE:</b> {f.cwe_id or 'N/A'}</p>
                <p style="color:#c9d1d9;font-size:14px;line-height:1.5;">{f.description}</p>
                {f'<pre style="background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:6px;color:#58a6ff;font-size:12px;overflow-x:auto;">{f.evidence}</pre>' if f.evidence else ''}
                <div style="background:#0d1117;border-left:3px solid #238636;padding:10px 15px;margin-top:10px;">
                    <h4 style="margin:0 0 5px 0;color:#3fb950;font-size:13px;">Remediation:</h4>
                    <p style="margin:0;color:#c9d1d9;font-size:13px;">{f.remediation}</p>
                </div>
            </div>
            """)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Assessment Report — {self.session.assessment_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:40px; }}
        .container {{ max-width: 900px; margin:0 auto; }}
        h1, h2, h3 {{ color:#fff; }}
        .metric-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:15px; text-align:center; }}
        .grid {{ display:grid; grid-template-columns: repeat(5, 1fr); gap:12px; margin:20px 0; }}
        table {{ width:100%; border-collapse:collapse; margin:20px 0; }}
        th, td {{ border:1px solid #30363d; padding:10px; text-align:left; }}
        th {{ background:#161b22; color:#8b949e; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        <p style="color:#8b949e;"><b>Project:</b> {self.session.assessment_name} | <b>Date:</b> {date_str} | <b>Mode:</b> {self.session.execution_mode.value.upper()}</p>
        
        <div class="grid">
            <div class="metric-card"><div style="color:#ef4444;font-size:24px;font-weight:bold;">{metrics['critical']}</div><div style="font-size:11px;color:#8b949e;">CRITICAL</div></div>
            <div class="metric-card"><div style="color:#f97316;font-size:24px;font-weight:bold;">{metrics['high']}</div><div style="font-size:11px;color:#8b949e;">HIGH</div></div>
            <div class="metric-card"><div style="color:#eab308;font-size:24px;font-weight:bold;">{metrics['medium']}</div><div style="font-size:11px;color:#8b949e;">MEDIUM</div></div>
            <div class="metric-card"><div style="color:#3b82f6;font-size:24px;font-weight:bold;">{metrics['low']}</div><div style="font-size:11px;color:#8b949e;">LOW</div></div>
            <div class="metric-card"><div style="color:#8b949e;font-size:24px;font-weight:bold;">{metrics['informational']}</div><div style="font-size:11px;color:#8b949e;">INFO</div></div>
        </div>

        <h2>Findings &amp; Remediation</h2>
        {''.join(findings_html) if findings_html else '<p>No security findings recorded.</p>'}
    </div>
</body>
</html>"""
        return html

    def export_all(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """Export report in Markdown, HTML, and JSON formats."""
        out_path = Path(output_dir) if output_dir else Path.cwd() / "reports"
        out_path.mkdir(parents=True, exist_ok=True)

        prefix = f"report_{self.session.session_id}"
        md_file = out_path / f"{prefix}.md"
        html_file = out_path / f"{prefix}.html"
        json_file = out_path / f"{prefix}.json"

        md_content = self.to_markdown()
        html_content = self.to_html()
        json_content = self.session.model_dump_json(indent=2)

        md_file.write_text(md_content, encoding="utf-8")
        html_file.write_text(html_content, encoding="utf-8")
        json_file.write_text(json_content, encoding="utf-8")

        return {
            "markdown": str(md_file),
            "html": str(html_file),
            "json": str(json_file),
        }
