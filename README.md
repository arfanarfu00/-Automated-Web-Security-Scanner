# 🛡️ Automated Web Security Scanner

> **Website Security Header & CORS Configuration Auditor**  
> A beginner-friendly cybersecurity dashboard built with Python, Streamlit, and Pandas.

---

## ⚠️ Responsible Use

Only scan websites **you own** or have **explicit permission** to test.  
This tool performs a passive read of HTTP response headers only. It does not exploit vulnerabilities, bypass authentication, crawl links, or store credentials.  
Results are educational heuristics — **not** certified security assessments.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard Sections](#dashboard-sections)
- [Security Checks](#security-checks)
- [Security Score Formula](#security-score-formula)
- [Download Reports](#download-reports)
- [Safe Test Targets](#safe-test-targets)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [License](#license)

---

## Overview

The **Automated Web Security Scanner** audits any website's HTTP response headers and Cross-Origin Resource Sharing (CORS) configuration in a single passive GET request. Results are displayed on a modern dark-themed dashboard with metric cards, bar charts, filterable findings tables, a threats section, and matched remediation advice — all exportable as JSON or CSV.

---

## Features

| Feature | Details |
|---|---|
| 🔍 **Security Header Audit** | Checks 6 critical HTTP response headers |
| 🌐 **CORS Analysis** | Inspects 4 CORS headers for misconfigurations |
| ⚠️ **Threats Detected** | Categorised threat table with risk levels and evidence limitations |
| 🛠️ **Recommended Solutions** | Matched fix per threat with example configs and verification steps |
| 📊 **Visual Charts** | Bar charts for findings by severity and header status |
| 🎯 **Security Score** | Documented 0–100 heuristic score with descriptive rating |
| 🔽 **Filter Findings** | Dropdown filters by severity and category (no re-scan needed) |
| 📥 **Download Reports** | JSON and CSV export, generated entirely in memory |
| 💾 **Session State** | Results persist while switching sections or adjusting filters |
| 🚫 **No Exploitation** | Passive analysis only — no injections, no crawling, no auth bypass |

---

## Tech Stack

| Technology | Purpose |
|---|---|
| **Python 3.x** | Application language |
| **Streamlit** | Web dashboard and UI |
| **Pandas** | DataFrames for tables and charts |
| **Requests** | Sending the HTTP GET request |
| **json** (stdlib) | JSON report generation |
| **csv + io** (stdlib) | CSV report generation |
| **time + datetime** (stdlib) | Response timing and timestamps |

> No API keys, databases, machine learning, or external services required.

---

## Installation

### 1. Prerequisites

- Python **3.8 or later**
- pip package manager (included with Python)

### 2. Clone or download the project

```bash
git clone https://github.com/your-username/automated-web-security-scanner.git
cd automated-web-security-scanner
```

Or simply place `app.py` in any folder on your machine.

### 3. Install dependencies

```bash
pip install streamlit pandas requests
```

---

## Usage

```bash
streamlit run app.py
```

Streamlit will open the dashboard automatically, or print a local URL such as:

```
Local URL:  http://localhost:8501
```

Open it in any modern browser.

### Step-by-step

1. Enter a website URL in the text box (e.g. `https://example.com`).
2. Click **🔍 Scan Website**.
3. Review the metric cards, security score, and charts.
4. Scroll through the Security Header Audit and CORS Analysis.
5. Check the **⚠️ Threats Detected** table.
6. Read the **🛠️ Recommended Solutions** for each detected threat.
7. Use the **severity** and **category** dropdowns to filter findings.
8. Click **⬇️ Download JSON Report** or **⬇️ Download CSV Report**.

---

## Dashboard Sections

### Scan Summary
HTTP status code, target URL, and response time in milliseconds.

### Overview (Metric Cards)
Four top-level counters: Headers Checked · Missing Headers · CORS Warnings · Total Findings.

### Security Score
A heuristic score from 0 to 100 with a colour-coded progress bar and a descriptive rating (Good / Fair / Poor / Critical). The scoring formula is displayed inline.

### Visual Analysis
- **Findings by Severity** — bar chart grouped by High / Medium / Low / Informational.
- **Header Status** — bar chart showing Present / Missing / Needs Review counts.

### Security Header Audit
Per-header cards showing the observed value, status badge, risk level, explanation, and remediation advice.

### CORS Configuration Analysis
Raw CORS header values table followed by per-finding cards for any flagged configurations.

### Security Findings
Filterable table with dropdowns for Severity and Category. Includes an expandable detailed view. No re-scan is triggered when filters change.

### ⚠️ Threats Detected
A dedicated section listing every potential configuration weakness with:
- Threat name
- Category (Security Header / CORS Configuration)
- Affected header or setting
- Observed value
- Risk level
- Plain-language explanation (with explicit evidence limitations)

If no issues are found: *"No potential issues detected by the current checks"* is displayed.

### 🛠️ Recommended Solutions
One card per detected threat (matched by name, no duplicates), each containing:
- **Why it matters** — context and potential impact
- **Recommended solution** — plain-language fix
- **Example configuration** — Apache, Nginx, and/or Node.js snippets where applicable
- **Verification steps** — numbered steps to confirm the fix

### All Response Headers
Expandable table showing every header returned by the server.

### Download Reports
JSON and CSV download buttons. Both formats include scan metadata, findings, threats, and solutions.

---

## Security Checks

### Security Headers

| Header | Risk if Missing | Heuristic |
|---|---|---|
| `Strict-Transport-Security` | High | `max-age` < 86400 → Needs Review |
| `Content-Security-Policy` | High | `unsafe-inline` / `unsafe-eval` → Needs Review |
| `X-Content-Type-Options` | Medium | Value must be `nosniff` |
| `X-Frame-Options` | Medium | Value must be `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | Low | Presence check |
| `Permissions-Policy` | Low | Presence check |

### CORS Headers

| Header | Check Performed |
|---|---|
| `Access-Control-Allow-Origin` | Wildcard (`*`), explicit origin, or absent |
| `Access-Control-Allow-Credentials` | `true` combined with wildcard origin |
| `Access-Control-Allow-Methods` | `DELETE`, `PUT`, or `PATCH` present |
| `Access-Control-Allow-Headers` | Displayed for reference |

> **Note:** No forged `Origin` header is ever sent. All checks are based solely on the server's unprompted response.

---

## Security Score Formula

Starting score: **100**

| Condition | Deduction | Cap |
|---|---|---|
| Missing High-risk header | −15 pts each | 2 headers max = −30 |
| Missing Medium-risk header | −10 pts each | 2 headers max = −20 |
| Missing Low-risk header | −5 pts each | 2 headers max = −10 |
| Header present but Needs Review | −5 pts each | No cap |
| CORS High-risk finding | −15 pts | Counted once |
| CORS Medium-risk finding | −8 pts | Counted once |

Final score is clamped to `[0, 100]`.

| Score | Rating |
|---|---|
| 85 – 100 | Good |
| 65 – 84 | Fair |
| 40 – 64 | Poor |
| 0 – 39 | Critical |

> This score is an **educational heuristic** and does not represent compliance with PCI-DSS, ISO 27001, OWASP, or any other standard.

---

## Download Reports

Both reports are generated **in memory** — no files are written to disk.

### JSON Report fields
```
scan_info
  ├── timestamp
  ├── target_url
  ├── http_status_code
  └── response_time_ms
security_score
  ├── score
  ├── rating
  └── note
header_findings        [ array ]
cors_findings          [ array ]
security_findings      [ array ]
threats_detected       [ array ]
recommended_solutions  [ array ]
```

### CSV Report sections
```
Row 1-2  : Scan metadata (timestamp, URL, status, score)
Row 4+   : Security findings (Title, Category, Severity, Explanation, Fix)
Section  : --- Threats Detected ---
Section  : --- Recommended Solutions ---
```

---

## Safe Test Targets

These publicly available sites are suitable for educational scanning:

| URL | What to expect |
|---|---|
| `https://example.com` | Minimal headers — most will be flagged missing |
| `https://httpbin.org` | Returns request info; good for CORS observation |
| `http://neverssl.com` | HTTP only — HSTS flagged as Informational |
| `http://localhost:5000` | Local Flask mock server (see below) |

### Local mock server (no internet required)

```python
# mock_server.py — run with: python mock_server.py
from flask import Flask, Response
app = Flask(__name__)

@app.route("/")
def index():
    r = Response("OK")
    r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r

app.run(port=5000)
```

Then scan `http://localhost:5000` in the scanner.

---

## Project Structure

```
Automated Web Security Scanner/
└── app.py          ← entire application (1,904 lines, single file)
└── README.md       ← this file
```

### Key functions inside `app.py`

| Function | Purpose |
|---|---|
| `normalise_url()` | Adds `https://` if scheme is missing |
| `scan_website()` | Sends the HTTP GET request; orchestrates all analysis |
| `_audit_headers()` | Checks the 6 security headers |
| `_header_needs_review()` | Heuristic checks for weak header values |
| `_audit_cors()` | Inspects 4 CORS response headers |
| `_build_threats()` | Derives context-aware threat list |
| `_build_solutions()` | Matches threats to solutions from lookup table |
| `_build_findings()` | Unified findings list for the filterable table |
| `_compute_score()` | Calculates the 0–100 security score |
| `_build_json_report()` | Serialises full result to JSON string |
| `_build_csv_report()` | Serialises full result to CSV string |
| `_render_threats_section()` | Renders ⚠️ Threats Detected UI section |
| `_render_solutions_section()` | Renders 🛠️ Recommended Solutions UI section |
| `main()` | Top-level dashboard orchestration |

---

## Limitations

- **Single endpoint:** Only the URL entered is scanned. Headers may differ across pages.
- **No JavaScript execution:** Headers set via `<meta>` tags or JavaScript are not detected.
- **CDN/proxy layers:** Security headers injected by a CDN may not appear at the application layer.
- **CORS without Origin header:** Some servers only return CORS headers in response to a preflight request; those cases are not tested.
- **No dynamic analysis:** XSS, SQL injection, and business-logic vulnerabilities cannot be detected from response headers alone.
- **Heuristic score:** Not calibrated against any external benchmark or compliance framework.

---

## License

This project is created for educational purposes as part of a Cybersecurity Bootcamp.  
Scan only websites you own or have explicit authorisation to test.
