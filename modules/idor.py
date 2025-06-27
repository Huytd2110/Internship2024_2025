import requests

def idor_scan(target_config):
    base_url = target_config["base_url"]
    method = target_config.get("method", "GET").upper()
    ids = target_config.get("ids", [])
    headers = target_config.get("headers", None)
    cookies = target_config.get("cookies", None)
    indicator = target_config.get("success_indicator", "")
    results = []

    for id_value in ids:
        url = f"{base_url}{id_value}"
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, cookies=cookies, timeout=10)
            else:
                resp = requests.post(url, headers=headers, cookies=cookies, timeout=10)
            evidence = [f"Status: {resp.status_code}", f"Response: {resp.text[:300]}"]
            # Thành công khi trả về 200 và có indicator (products) trong response
            success = (resp.status_code == 200 and indicator.lower() in resp.text.lower())
            sev = "High" if success else "Low"
            status = "Success" if success else "Fail"
            results.append({
                "type": "IDOR",
                "test_case_name": f"IDOR basket_id={id_value}",
                "module": "native",
                "payload": str(id_value),
                "success": success,
                "status": status,
                "severity": sev,
                "remediation": "Implement strict access control to verify resource ownership before granting access.",
                "evidence": evidence,
                "request_sample": f"{method} {url}",
                "status_code": resp.status_code,
                "response_sample": resp.text[:500]
            })
        except Exception as e:
            results.append({
                "type": "IDOR",
                "test_case_name": f"IDOR basket_id={id_value}",
                "module": "native",
                "payload": str(id_value),
                "success": False,
                "status": "Error",
                "severity": "Low",
                "remediation": "Implement strict access control to verify resource ownership before granting access.",
                "evidence": [f"Exception: {e}"],
                "request_sample": f"{method} {url}",
                "status_code": None,
                "response_sample": ""
            })
    return results
