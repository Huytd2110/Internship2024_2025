import requests
from bs4 import BeautifulSoup

def classify_severity(evidence):
    txt = "\n".join(evidence) if isinstance(evidence, list) else str(evidence)
    txt = txt.lower()
    if "alert(" in txt or "<script>" in txt:
        return "High"
    elif "img" in txt or "onerror" in txt:
        return "Medium"
    elif "payload reflected" in txt:
        return "Low"
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

def extract_evidence(response_text, payload):
    soup = BeautifulSoup(response_text, "html.parser")
    evidence_blocks = []
    if payload in response_text:
        evidence_blocks.append(f"Payload reflected: {payload}")
    if "<script" in response_text.lower():
        evidence_blocks.append("Detected <script> tag in response.")
    if "alert(" in response_text.lower():
        evidence_blocks.append("Detected alert() in response.")
    if "onerror" in response_text.lower():
        evidence_blocks.append("Detected image/event XSS payload.")
    blocks = soup.find_all(string=lambda t: payload in t)
    for b in blocks:
        evidence_blocks.append(b.strip())
    if not evidence_blocks:
        evidence_blocks.append(soup.get_text(separator="\n").strip())
    return evidence_blocks

def is_xss_success(evidence):
    if isinstance(evidence, list) and len(evidence) > 0:
        for e in evidence:
            e = e.lower()
            if "alert(" in e or "<script" in e or "payload reflected" in e or "onerror" in e:
                return True
    return False

def xss_scan(target_config, engine="script"):
    level = target_config.get("level", "N/A")
    results = []
    url = target_config["url"]
    method = target_config["method"].lower()
    param = target_config.get("param")
    extra_params = target_config.get("extra_params", {})
    payloads = load_payloads(target_config)
    cookies = target_config.get("cookies", None)
    headers = target_config.get("headers", None)
    params_multi = target_config.get("params_multi", None)  

    for idx, payload in enumerate(payloads):
        if params_multi:
            for field in params_multi:
                params = {fld: (payload if fld == field else "autotest") for fld in params_multi}
                params["Submit"] = "Sign Guestbook"
                params.update(extra_params)
                test_case_name = f"XSS Test #{idx+1} [{field}]: {payload}"
                try:
                    if method == "get":
                        resp = requests.get(url, params=params, cookies=cookies, headers=headers, timeout=10)
                    else:
                        resp = requests.post(url, data=params, cookies=cookies, headers=headers, timeout=10)
                    evd = extract_evidence(resp.text, payload)
                    is_success = is_xss_success(evd)
                    sev = classify_severity(evd) if is_success else "Low"
                    status = "Success" if is_success else "Fail"
                    results.append({
                        "type": "XSS",
                        "test_case_name": test_case_name,
                        "module": "native",
                        "payload": payload,
                        "success": is_success,
                        "status": status,
                        "level": level,
                        "severity": sev,
                        "remediation": "Sanitize and encode user input/output. Use Content Security Policy (CSP). Apply input validation.",
                        "evidence": evd,
                        "request_sample": f"{method.upper()} {url} {params}",
                        "status_code": resp.status_code,
                        "response_sample": resp.text[:500]
                    })
                except Exception as e:
                    results.append({
                        "type": "XSS",
                        "test_case_name": test_case_name,
                        "module": "native",
                        "payload": payload,
                        "success": False,
                        "status": "Error",
                        "level": level,
                        "severity": "Low",
                        "remediation": "Sanitize and encode user input/output. Use Content Security Policy (CSP). Apply input validation.",
                        "evidence": [f"Exception: {e}"],
                        "request_sample": f"{method.upper()} {url} {params}",
                        "status_code": None,
                        "response_sample": ""
                    })
        else:
            params = {param: payload, "Submit": "Sign Guestbook"}
            params.update(extra_params)
            test_case_name = f"XSS Test #{idx+1}: {payload}"
            try:
                if method == "get":
                    resp = requests.get(url, params=params, cookies=cookies, headers=headers, timeout=10)
                else:
                    resp = requests.post(url, data=params, cookies=cookies, headers=headers, timeout=10)
                evd = extract_evidence(resp.text, payload)
                is_success = is_xss_success(evd)
                sev = classify_severity(evd) if is_success else "Low"
                status = "Success" if is_success else "Fail"
                results.append({
                    "type": "XSS",
                    "test_case_name": test_case_name,
                    "module": "native",
                    "payload": payload,
                    "success": is_success,
                    "status": status,
                    "level": level,
                    "severity": sev,
                    "remediation": "Sanitize and encode user input/output. Use Content Security Policy (CSP). Apply input validation.",
                    "evidence": evd,
                    "request_sample": f"{method.upper()} {url} {params}",
                    "status_code": resp.status_code,
                    "response_sample": resp.text[:500]
                })
            except Exception as e:
                results.append({
                    "type": "XSS",
                    "test_case_name": test_case_name,
                    "module": "native",
                    "payload": payload,
                    "success": False,
                    "status": "Error",
                    "level": level,
                    "severity": "Low",
                    "remediation": "Sanitize and encode user input/output. Use Content Security Policy (CSP). Apply input validation.",
                    "evidence": [f"Exception: {e}"],
                    "request_sample": f"{method.upper()} {url} {params}",
                    "status_code": None,
                    "response_sample": ""
                })
    return results
