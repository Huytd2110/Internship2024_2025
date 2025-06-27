import os
import json
from utils import report
from modules.sqli import sqli_scan
from modules.xss import xss_scan
from modules.idor import idor_scan

def run_and_report_scan(module_func, target, target_name="Unknown"):
    print(f"\n--- Running: {target_name} ---")
    results = module_func(target)
    return results

if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)

    # Load target configurations
    with open("config/targets.json") as f:
        config = json.load(f)

    all_results = []

    # 1. Run SQL Injection module
    if "sqli_dvwa" in config:
        all_results.extend(run_and_report_scan(
            sqli_scan, config["sqli_dvwa"], target_name="DVWA_SQLi"
        ))

    # 2. Run XSS Reflected module
    if "xss_dvwa_reflected" in config:
        all_results.extend(run_and_report_scan(
            xss_scan, config["xss_dvwa_reflected"], target_name="DVWA_XSS_Reflected"
        ))

    # 3. Run XSS Stored module
    if "xss_dvwa_stored" in config:
        all_results.extend(run_and_report_scan(
            xss_scan, config["xss_dvwa_stored"], target_name="DVWA_XSS_Stored"
        ))

    # 4. Run IDOR Juice Shop module
    if "idor_juiceshop" in config:
        all_results.extend(run_and_report_scan(
            idor_scan, config["idor_juiceshop"], target_name="JuiceShop_IDOR"
        ))

    # Only generate the consolidated report
    if all_results:
        full_report = report.generate_full_report(all_results, target_name="Full Automated Web Pentest")
        report.save_report_json(full_report, "output/full_report.json")
        report.save_report_markdown(full_report, "output/full_report.md")
        report.save_report_pdf(full_report, "output/full_report.pdf")
        print("\n=> Consolidated report has been saved to the output/ directory (full_report.pdf, .md, .json).")
    else:
        print("No scan results to report!")
