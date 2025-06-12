import json
from fpdf import FPDF
from datetime import datetime
import unicodedata
import re

def normalize_pdf_text(s):
    if not isinstance(s, str):
        return str(s)
    s = s.replace("–", "-").replace("—", "-").replace("“", "\"").replace("”", "\"")
    s = unicodedata.normalize('NFKD', s).encode('latin-1', 'ignore').decode('latin-1')
    return s

def parse_users_from_evidence(evidence):
    users = []
    if isinstance(evidence, list):
        for user_block in evidence:
            username = password = ""
            m1 = re.search(r"First name:\s*(.+)", user_block, re.IGNORECASE)
            if m1: username = m1.group(1).strip()
            m2 = re.search(r"Surname:\s*(.+)", user_block, re.IGNORECASE)
            if m2: password = m2.group(1).strip()
            if username or password:
                users.append({"username": username, "password": password})
    return users

def classify_severity(evidence):
    txt = "\n".join(evidence) if isinstance(evidence, list) else str(evidence)
    if "admin" in txt.lower():
        return "Critical"
    elif "password" in txt.lower() or "hash" in txt.lower():
        return "High"
    elif "user" in txt.lower():
        return "Medium"
    else:
        return "Low"

def generate_full_report(scan_results, target_name="Unknown"):
    for r in scan_results:
        if not r.get("severity"):
            r["severity"] = classify_severity(r.get("evidence", ""))
    total = len(scan_results)
    success_count = sum(1 for r in scan_results if r.get("success"))
    severities = [r["severity"] for r in scan_results if r.get("success")]
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
        },
        "recommendations": list(set(r.get("remediation") for r in scan_results if r.get("remediation")))
    }
    return report

def save_report_json(report, filename="output/full_report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

def save_report_markdown(report, filename="output/full_report.md"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Automated Web Pentest Report\n\n")
        f.write(f"**Scan Date:** {report['scan_date']}  \n")
        f.write(f"**Target:** {report['target']}\n\n")

        summary = report["summary"]
        f.write("## Executive Summary\n")
        f.write(f"- Total vulnerabilities tested: {summary['total_vulnerabilities']}  \n")
        f.write(f"- Successful exploits: {summary['successful_exploits']}  \n")
        f.write(f"- Risk Level: **{summary['risk_level']}**\n\n")

        f.write("## Test Cases Table\n\n")
        f.write("| # | Payload | Status | Severity |\n")
        f.write("|---|---------|--------|----------|\n")
        for i, v in enumerate(report["vulnerabilities"]):
            f.write(
                f"| {i+1} | `{v.get('payload','N/A')}` | {v.get('status','')} | "
                f"{v.get('severity','')} |\n"
            )
        f.write("\n")

        f.write("## Evidence Details\n\n")
        for i, v in enumerate(report["vulnerabilities"]):
            f.write(f"### [{i+1}] Payload: `{v.get('payload','N/A')}`\n")
            evidence = v.get('evidence', [])
            if isinstance(evidence, list):
                evidence_block = "\n\n".join(evidence)
            elif isinstance(evidence, str):
                evidence_block = evidence
            else:
                evidence_block = str(evidence)
            f.write(f"```\n{evidence_block}\n```\n\n")

        all_users = []
        for v in report["vulnerabilities"]:
            if "union select" in v.get("payload", "").lower():
                ev = v.get('evidence', [])
                users = parse_users_from_evidence(ev)
                all_users.extend(users)
        if all_users:
            f.write("## Extracted Users\n\n")
            f.write("| # | Username | Password/Hash |\n")
            f.write("|---|----------|---------------|\n")
            for i, user in enumerate(all_users):
                f.write(f"| {i+1} | {user['username']} | {user['password']} |\n")
            f.write("\n")

        f.write("## Recommendations\n")
        for r in report["recommendations"]:
            f.write(f"- {r}  \n")

def save_report_pdf(report, filename="output/full_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, normalize_pdf_text("Automated Web Pentest Report"), 0, 1, 'C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, normalize_pdf_text(f"Scan Date: {report['scan_date']}"), 0, 1)
    pdf.cell(0, 10, normalize_pdf_text(f"Target: {report['target']}"), 0, 1)
    pdf.ln(8)

    summary = report["summary"]
    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 10, normalize_pdf_text("Executive Summary"), 0, 1)
    pdf.set_font("Arial", size=11)
    pdf.cell(0, 8, normalize_pdf_text(f"Total vulnerabilities tested: {summary['total_vulnerabilities']}"), 0, 1)
    pdf.cell(0, 8, normalize_pdf_text(f"Successful exploits: {summary['successful_exploits']}"), 0, 1)
    pdf.cell(0, 8, normalize_pdf_text(f"Risk Level: {summary['risk_level']}"), 0, 1)
    pdf.ln(3)

    # Test Cases Table
    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 10, normalize_pdf_text("Test Cases Table"), 0, 1)
    pdf.set_font("Arial", size=9)
    pdf.cell(8, 8, "#", 1)
    pdf.cell(100, 8, "Payload", 1)
    pdf.cell(22, 8, "Status", 1)
    pdf.cell(22, 8, "Severity", 1)
    pdf.ln()
    for i, v in enumerate(report["vulnerabilities"]):
        pdf.cell(8, 8, str(i+1), 1)
        pdf.cell(100, 8, normalize_pdf_text(v.get("payload","")), 1)
        pdf.cell(22, 8, normalize_pdf_text(v.get("status","")), 1)
        pdf.cell(22, 8, normalize_pdf_text(v.get("severity","")), 1)
        pdf.ln()
    pdf.ln(3)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, normalize_pdf_text("Evidence Details"), 0, 1)
    pdf.set_font("Arial", size=10)
    for i, v in enumerate(report["vulnerabilities"]):
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
        pdf.ln(1)

    all_users = []
    for v in report["vulnerabilities"]:
        if "union select" in v.get("payload", "").lower():
            ev = v.get('evidence', [])
            users = parse_users_from_evidence(ev)
            all_users.extend(users)
    if all_users:
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, normalize_pdf_text("Extracted Users"), 0, 1)
        pdf.set_font("Arial", size=10)
        pdf.cell(10, 8, "#", 1)
        pdf.cell(40, 8, "Username", 1)
        pdf.cell(60, 8, "Password/Hash", 1)
        pdf.ln()
        for i, user in enumerate(all_users):
            pdf.cell(10, 8, str(i+1), 1)
            pdf.cell(40, 8, normalize_pdf_text(user['username']), 1)
            pdf.cell(60, 8, normalize_pdf_text(user['password']), 1)
            pdf.ln()
        pdf.ln(2)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, normalize_pdf_text("Recommendations"), 0, 1)
    pdf.set_font("Arial", size=11)
    for r in report["recommendations"]:
        pdf.multi_cell(0, 8, normalize_pdf_text(f"- {r}"))

    pdf.output(filename)
