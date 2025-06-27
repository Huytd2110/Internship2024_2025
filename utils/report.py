import json
from fpdf import FPDF
from datetime import datetime
import unicodedata
import platform
import sys
import os
import subprocess
from collections import defaultdict

def generate_full_report(scan_results, target_name="Unknown"):
    total = len(scan_results)
    success_count = sum(1 for r in scan_results if r.get("success"))
    severities = [r.get("severity", "Low") for r in scan_results if r.get("success")]
    if "Critical" in severities:
        risk_level = "Critical"
    elif "High" in severities:
        risk_level = "High"
    elif "Medium" in severities:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    report = {
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "target": target_name,
        "vulnerabilities": scan_results,
        "summary": {
            "total_vulnerabilities": total,
            "successful_exploits": success_count,
            "risk_level": risk_level
        }
    }
    return report

def get_env_info(custom_info=None):
    os_info = f"{platform.system()} {platform.release()}"
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_info = line.strip().split("=")[1].strip("\"")
    pyver = sys.version.split()[0]
    scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        sqlmap_ver = subprocess.check_output(['sqlmap', '--version'], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        sqlmap_ver = "N/A"
    info = {
        "Server OS": os_info,
        "Python Version": pyver,
        "Scan Date": scan_date,
        "SQLmap Version": sqlmap_ver,
    }
    if custom_info:
        info.update(custom_info)
    return info

CUSTOM_ENV = {
    "Target App": "DVWA (Damn Vulnerable Web Application)",
    "Version": "1.10 *Development*",
    "Security Level": "low",
    "Web Server": "Apache 2.4",
    "Database": "MySQL 8",
    "Language": "PHP 8.1",
    "Tools Used": "Python requests, BeautifulSoup4, SQLmap, Burp Suite (manual verify)",
}

def normalize_pdf_text(s):
    if not isinstance(s, str):
        return str(s)
    s = s.replace("–", "-").replace("—", "-").replace("“", "\"").replace("”", "\"")
    s = unicodedata.normalize('NFKD', s).encode('latin-1', 'ignore').decode('latin-1')
    return s

METHODOLOGY = [
    "Automated Python script loads payloads from file, sends HTTP requests, extracts evidence with BeautifulSoup4.",
    "Auto-classifies results, exports as PDF/Markdown/JSON.",
    "SQLmap integration for advanced SQLi detection.",
    "Ready for CI/CD: can run in GitHub Actions/Jenkins."
]

DETAILED_RECOMMENDATIONS = [
    "Use prepared statements (parameterized queries) for all database access.",
    "Enable a Web Application Firewall (e.g., ModSecurity + CRS) in production.",
    "Build a code review checklist for input validation and output encoding.",
    "Patch DVWA and all dependencies regularly.",
    "Integrate automated security testing (e.g., SonarQube, OWASP ZAP) into CI/CD.",
    "Regularly update payload signatures and review recent CVE advisories."
]

REFERENCES = [
    "OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection",
    "PayloadAllTheThings SQLi: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
    "DVWA GitHub: https://github.com/digininja/DVWA",
    "SQLmap: http://sqlmap.org/",
    "OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/"
]

SEVERITY_COLOR = {
    "Critical": (255, 80, 80),    # Light Red
    "High":     (255, 165, 70),   # Orange
    "Medium":   (140, 220, 255),  # Light Blue
    "Low":      (220, 220, 220)   # Light Gray
}

def draw_dashed_line(pdf):
    x = pdf.get_x(); y = pdf.get_y()
    pdf.set_draw_color(120,120,120)
    for i_dash in range(0, 190, 8):
        pdf.line(10+i_dash, y, 15+i_dash, y)
    pdf.ln(3)
    pdf.set_draw_color(0,0,0)

def save_report_json(report, filename="output/full_report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

def save_report_markdown(report, filename="output/full_report.md"):
    ENVIRONMENT_INFO = get_env_info(CUSTOM_ENV)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Automated Web Pentest Report\n\n")
        f.write(f"**Scan Date:** {report['scan_date']}  \n")
        f.write(f"**Target:** {report['target']}\n\n")

        # Test Environment
        f.write("## Test Environment\n\n")
        for k, v in ENVIRONMENT_INFO.items():
            f.write(f"- **{k}:** {v}\n")
        f.write("\n---\n")

        # Methodology
        f.write("## Methodology & Tools\n\n")
        for step in METHODOLOGY:
            f.write(f"- {step}\n")
        f.write("\n---\n")

        summary = report["summary"]
        f.write("## Executive Summary\n")
        f.write(f"- Total vulnerabilities tested: {summary['total_vulnerabilities']}  \n")
        f.write(f"- Successful exploits: {summary['successful_exploits']}  \n")
        f.write(f"- Risk Level: **{summary['risk_level']}**\n\n")
        f.write("\n---\n")

        # Group by vulnerability type (module)
        module_groups = defaultdict(list)
        for v in report["vulnerabilities"]:
            module_type = v.get("type", "Other")
            module_groups[module_type].append(v)

        for module_type, vulns in module_groups.items():
            f.write(f"\n## {module_type} Test Cases\n\n")
            f.write("| # | Payload | Status | Severity |\n")
            f.write("|---|---------|--------|----------|\n")
            for i, v in enumerate(vulns):
                f.write(
                    f"| {i+1} | `{v.get('payload','N/A')}` | {v.get('status','')} | "
                    f"{v.get('severity','')} |\n"
                )
            f.write("\n---\n")

            f.write(f"### {module_type} Evidence Details\n\n")
            for i, v in enumerate(vulns):
                severity = v.get("severity", "Low")
                f.write(f"**Severity:** `{severity}`\n")
                f.write(f"#### Payload: `{v.get('payload','N/A')}`\n")
                evidence = v.get('evidence', [])
                if isinstance(evidence, list):
                    evidence_block = "\n\n".join(evidence)
                elif isinstance(evidence, str):
                    evidence_block = evidence
                else:
                    evidence_block = str(evidence)
                f.write(f"```\n{evidence_block}\n```\n\n")
            f.write("---\n")

        f.write("## Recommendations\n")
        for r in DETAILED_RECOMMENDATIONS:
            f.write(f"- {r}\n")
        f.write("\n---\n")

        f.write("## References\n")
        for ref in REFERENCES:
            f.write(f"- {ref}\n")
        f.write("\n---\n")

def save_report_pdf(report, filename="output/full_report.pdf"):
    ENVIRONMENT_INFO = get_env_info(CUSTOM_ENV)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, normalize_pdf_text("Automated Web Pentest Report"), 0, 1, 'C')
    pdf.ln(5)

    # Test Environment
    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 10, "Test Environment", 0, 1)
    pdf.set_font("Arial", size=10)
    for k, v in ENVIRONMENT_INFO.items():
        pdf.cell(0, 8, f"{k}: {normalize_pdf_text(v)}", 0, 1)
    draw_dashed_line(pdf)

    # Methodology & Tools
    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 10, "Methodology & Tools", 0, 1)
    pdf.set_font("Arial", size=10)
    for step in METHODOLOGY:
        pdf.multi_cell(0, 7, f"- {normalize_pdf_text(step)}")
    draw_dashed_line(pdf)

    summary = report["summary"]
    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 10, "Executive Summary", 0, 1)
    pdf.set_font("Arial", size=11)
    pdf.cell(0, 8, f"Total vulnerabilities tested: {summary['total_vulnerabilities']}", 0, 1)
    pdf.cell(0, 8, f"Successful exploits: {summary['successful_exploits']}", 0, 1)
    pdf.cell(0, 8, f"Risk Level: {summary['risk_level']}", 0, 1)
    draw_dashed_line(pdf)

    # Group by vulnerability type (module)
    module_groups = defaultdict(list)
    for v in report["vulnerabilities"]:
        module_type = v.get("type", "Other")
        module_groups[module_type].append(v)

    for module_type, vulns in module_groups.items():
        pdf.set_font("Arial", 'B', 13)
        pdf.cell(0, 10, f"{module_type} Test Cases", 0, 1)
        pdf.set_font("Arial", size=9)
        pdf.cell(8, 8, "#", 1)
        pdf.cell(80, 8, "Payload", 1)
        pdf.cell(22, 8, "Status", 1)
        pdf.cell(22, 8, "Severity", 1)
        pdf.ln()
        for i, v in enumerate(vulns):
            pdf.set_text_color(0,0,0)
            pdf.cell(8, 8, str(i+1), 1)
            pdf.cell(80, 8, normalize_pdf_text(v.get("payload","")), 1)
            pdf.cell(22, 8, normalize_pdf_text(v.get("status","")), 1)
            pdf.cell(22, 8, normalize_pdf_text(v.get("severity","")), 1)
            pdf.ln()
        pdf.set_text_color(0,0,0)
        draw_dashed_line(pdf)

        # Evidence details for this module
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, f"{module_type} Evidence Details", 0, 1)
        pdf.set_font("Arial", size=10)
        for i, v in enumerate(vulns):
            severity = v.get("severity", "Low")
            color = SEVERITY_COLOR.get(severity, (220,220,220))
            pdf.set_fill_color(*color)
            pdf.set_text_color(30,30,30)
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(0, 8, f"  Severity: {severity}", 0, 1, 'L', True)
            pdf.set_text_color(0,0,0)
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(0, 8, normalize_pdf_text(f"[{i+1}] Payload: {v.get('payload','N/A')}"), 0, 1)
            pdf.set_font("Arial", size=10)
            evidence = v.get('evidence', [])
            if isinstance(evidence, list):
                evidence_block = "\n\n".join(evidence)
            elif isinstance(evidence, str):
                evidence_block = evidence
            else:
                evidence_block = str(evidence)
            pdf.multi_cell(0, 6, normalize_pdf_text(evidence_block))
            draw_dashed_line(pdf)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Recommendations", 0, 1)
    pdf.set_font("Arial", size=11)
    for r in DETAILED_RECOMMENDATIONS:
        pdf.multi_cell(0, 8, f"- {normalize_pdf_text(r)}")
    draw_dashed_line(pdf)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "References", 0, 1)
    pdf.set_font("Arial", size=10)
    for ref in REFERENCES:
        pdf.multi_cell(0, 7, normalize_pdf_text(ref))
    draw_dashed_line(pdf)

    pdf.output(filename)
