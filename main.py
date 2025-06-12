from utils import report
import os
import time
import json
from modules.sqli import sqli_scan

os.makedirs("output", exist_ok=True)

def run_and_report(engine_name, target, target_name="Unknown"):
    print(f"\n--- Running engine: {engine_name} ---")
    start = time.time()
    results = sqli_scan(target, engine=engine_name)
    elapsed = time.time() - start
    print(f"{engine_name} engine time: {elapsed:.2f}s")

    # Tổng hợp báo cáo
    full_report = report.generate_full_report(results, target_name=target_name)

    # Xuất báo cáo
    base_fname = f"output/sqli_{engine_name}"
    report.save_report_json(full_report, base_fname + ".json")
    report.save_report_markdown(full_report, base_fname + ".md")
    report.save_report_pdf(full_report, base_fname + ".pdf")

    return results, elapsed

if __name__ == "__main__":
    with open("config/targets.json") as f:
        config = json.load(f)
    target = config["sqli_dvwa"]

    results_script, time_script = run_and_report("script", target, target_name="DVWA")

