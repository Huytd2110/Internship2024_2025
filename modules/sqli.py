import requests
from bs4 import BeautifulSoup

def classify_severity(evidence):
    txt = "\n".join(evidence) if isinstance(evidence, list) else str(evidence)
    if "admin" in txt.lower():
        return "Critical"
    elif "password" in txt.lower() or "hash" in txt.lower():
        return "High"
    elif "user" in txt.lower() or "surname:" in txt.lower():
        return "Medium"
    else:
        return "Low"

def load_payloads(target_config):
    if "payloads" in target_config:
        return target_config["payloads"]
    elif "payloads_file" in target_config:
        with open(target_config["payloads_file"], "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        raise Exception("No payloads specified in config!")

def extract_evidence(response_text):
    soup = BeautifulSoup(response_text, "html.parser")
    vuln_div = soup.find("div", class_="vulnerable_code_area")
    if vuln_div:
        pre_tags = vuln_div.find_all("pre")
        if pre_tags:
            return [pre.get_text(separator="\n").strip() for pre in pre_tags]
    pre_tags = soup.find_all("pre")
    if pre_tags:
        return [pre.get_text(separator="\n").strip() for pre in pre_tags]
    if vuln_div:
        return [vuln_div.get_text(separator="\n").strip()]
    return [soup.get_text(separator="\n").strip()]

def is_sqli_success(evd):
    if isinstance(evd, list) and len(evd) > 1:
        return True
    evd_text = "\n".join(evd) if isinstance(evd, list) else str(evd)
    keywords = ["admin", "gordon", "union select", "password", "Surname:"]
    return any(kw.lower() in evd_text.lower() for kw in keywords)

def sqli_scan(target_config, engine="script"):
    level = target_config.get("level", "N/A")
    results = []
    url = target_config["url"]
    method = target_config["method"].lower()
    param = target_config["param"]
    payloads = load_payloads(target_config)
    cookies = target_config.get("cookies", None)
    headers = target_config.get("headers", None)

    for idx, payload in enumerate(payloads):
        params = {param: payload, "Submit": "Submit"}
        test_case_name = f"SQLi Test #{idx+1}: {payload}"
        try:
            if method == "get":
                resp = requests.get(url, params=params, cookies=cookies, headers=headers, timeout=10)
            else:
                resp = requests.post(url, data=params, cookies=cookies, headers=headers, timeout=10)
            evd = extract_evidence(resp.text)
            is_success = is_sqli_success(evd)
            sev = classify_severity(evd) if is_success else "Low"
            status = "Success" if is_success else "Fail"
            results.append({
                "type": "SQL Injection",
                "test_case_name": test_case_name,
                "module": "native",
                "payload": payload,
                "success": is_success,
                "status": status,
                "level": level,
                "severity": sev,
                "remediation": "Use parameterized queries (prepared statements) for all database access. Always validate and sanitize user input.",
                "evidence": evd,
                "request_sample": f"{method.upper()} {url}?{param}={payload}&Submit=Submit",
                "status_code": resp.status_code,
                "response_sample": resp.text[:500]
            })
        except Exception as e:
            results.append({
                "type": "SQL Injection",
                "test_case_name": test_case_name,
                "module": "native",
                "payload": payload,
                "success": False,
                "status": "Error",
                "level": level,
                "severity": "Low",
                "remediation": "Use parameterized queries (prepared statements) for all database access. Always validate and sanitize user input.",
                "evidence": [f"Exception: {e}"],
                "request_sample": f"{method.upper()} {url}?{param}={payload}&Submit=Submit",
                "status_code": None,
                "response_sample": ""
            })
    return results
