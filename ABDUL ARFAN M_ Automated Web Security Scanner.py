"""
Automated Web Security Scanner
================================
A beginner-friendly cybersecurity dashboard built with Python, Streamlit, and Pandas.
Audits HTTP security headers and CORS configurations for educational purposes.

Usage:
    pip install streamlit pandas requests
    streamlit run app.py

Disclaimer:
    Only scan websites you own or have explicit permission to test.
    This tool is for educational use. Results are heuristic, not authoritative.
"""

import json
import csv
import io
import time
import datetime

import requests
import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# Page configuration — must be the FIRST Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Automated Web Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Global CSS — dark theme dashboard styling
# ---------------------------------------------------------------------------
DARK_CSS = """
<style>
/* ---- base ---- */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', system-ui, sans-serif;
}
[data-testid="stHeader"] { background-color: #0d1117; }
[data-testid="stSidebar"] { background-color: #161b22; }

/* ---- metric cards ---- */
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px 24px;
    text-align: center;
    margin-bottom: 8px;
}
.metric-card .metric-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #58a6ff;
    line-height: 1.2;
}
.metric-card .metric-label {
    font-size: 0.85rem;
    color: #8b949e;
    margin-top: 4px;
}

/* ---- section headings ---- */
.section-heading {
    font-size: 1.2rem;
    font-weight: 600;
    color: #58a6ff;
    border-bottom: 1px solid #30363d;
    padding-bottom: 6px;
    margin: 24px 0 14px 0;
}

/* ---- status badges ---- */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 600;
}
.badge-present  { background: #1a4731; color: #3fb950; }
.badge-missing  { background: #4d1e1e; color: #f85149; }
.badge-review   { background: #3d2b00; color: #d29922; }
.badge-info     { background: #1c2d3f; color: #58a6ff; }

/* ---- severity colours ---- */
.sev-high   { color: #f85149; font-weight: 600; }
.sev-medium { color: #d29922; font-weight: 600; }
.sev-low    { color: #3fb950; font-weight: 600; }
.sev-info   { color: #58a6ff; font-weight: 600; }

/* ---- score bar ---- */
.score-wrap { text-align: center; padding: 20px 0; }
.score-number {
    font-size: 4rem;
    font-weight: 800;
    line-height: 1;
}
.score-label {
    font-size: 1rem;
    color: #8b949e;
    margin-top: 6px;
}
.score-disclaimer {
    font-size: 0.78rem;
    color: #6e7681;
    margin-top: 10px;
}

/* ---- header detail card ---- */
.header-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.header-name {
    font-size: 0.95rem;
    font-weight: 600;
    color: #e6edf3;
}
.header-value {
    font-size: 0.82rem;
    color: #8b949e;
    font-family: monospace;
    word-break: break-all;
    margin: 4px 0 8px 0;
}
.header-meta {
    font-size: 0.82rem;
    color: #c9d1d9;
    line-height: 1.6;
}

/* ---- disclaimer banner ---- */
.disclaimer-box {
    background: #1c2438;
    border: 1px solid #2d3d5a;
    border-radius: 8px;
    padding: 14px 18px;
    font-size: 0.83rem;
    color: #8b949e;
    margin-bottom: 18px;
    line-height: 1.6;
}

/* ---- Streamlit widget overrides ---- */
div[data-testid="stTextInput"] input {
    background-color: #161b22 !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
}
div[data-testid="stSelectbox"] select {
    background-color: #161b22 !important;
    color: #e6edf3 !important;
}
</style>
"""

st.markdown(DARK_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Constants — security headers to audit
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "risk": "High",
        "explanation": (
            "HSTS tells browsers to only use HTTPS. Without it, the site may be "
            "vulnerable to protocol-downgrade attacks on first visit."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "note": "Only effective over HTTPS connections.",
    },
    "Content-Security-Policy": {
        "risk": "High",
        "explanation": (
            "CSP restricts which resources browsers can load, reducing XSS attack surface."
        ),
        "remediation": (
            "Define a strict policy, e.g.: Content-Security-Policy: default-src 'self'"
        ),
        "note": "Poorly written policies still offer limited protection.",
    },
    "X-Content-Type-Options": {
        "risk": "Medium",
        "explanation": (
            "Prevents browsers from MIME-sniffing responses away from the declared content-type."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "note": "",
    },
    "X-Frame-Options": {
        "risk": "Medium",
        "explanation": (
            "Controls whether the page can be loaded in a frame. Helps mitigate clickjacking."
        ),
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
        "note": "CSP frame-ancestors is the modern replacement.",
    },
    "Referrer-Policy": {
        "risk": "Low",
        "explanation": (
            "Governs how much referrer information is sent with outbound requests."
        ),
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "note": "",
    },
    "Permissions-Policy": {
        "risk": "Low",
        "explanation": (
            "Restricts which browser features (camera, geolocation, etc.) a page may use."
        ),
        "remediation": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
        "note": "",
    },
}

# ---------------------------------------------------------------------------
# Helper — normalise URL
# ---------------------------------------------------------------------------
def normalise_url(raw: str) -> str:
    """Ensure the URL has a scheme so Requests does not reject it."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


# ---------------------------------------------------------------------------
# Core scanner — sends one GET request and returns structured results
# ---------------------------------------------------------------------------
def scan_website(url: str) -> dict:
    """
    Sends a single GET request to *url* and returns a dictionary containing:
      - status_code, response_time_ms, response_headers (dict)
      - header_findings (list of dicts)
      - cors_findings (list of dicts)
      - security_findings (list of dicts)
      - threats (list of dicts)       ← NEW: Threats Detected section
      - solutions (list of dicts)     ← NEW: Recommended Solutions section
      - security_score (int 0-100)
      - score_rating (str)
      - error (str or None)
    """
    result = {
        "url": url,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status_code": None,
        "response_time_ms": None,
        "response_headers": {},
        "header_findings": [],
        "cors_findings": [],
        "security_findings": [],
        "threats": [],
        "solutions": [],
        "security_score": 0,
        "score_rating": "",
        "error": None,
    }

    # ---- make the HTTP request ----------------------------------------
    try:
        start = time.time()
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "AutoWebSecScanner/1.0 (educational)"},
        )
        elapsed_ms = round((time.time() - start) * 1000)
    except requests.exceptions.MissingSchema:
        result["error"] = "Invalid URL: missing scheme (http:// or https://)."
        return result
    except requests.exceptions.InvalidURL:
        result["error"] = "Invalid URL format."
        return result
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed. Check the URL and your network."
        return result
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out after 10 seconds."
        return result
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects. The server may be misconfigured."
        return result
    except requests.exceptions.HTTPError as exc:
        result["error"] = f"HTTP error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Request error: {exc}"
        return result

    result["status_code"] = response.status_code
    result["response_time_ms"] = elapsed_ms
    # Normalise header names to title-case for consistent lookup
    result["response_headers"] = {k: v for k, v in response.headers.items()}

    # ---- audit security headers --------------------------------------
    result["header_findings"] = _audit_headers(response.headers)

    # ---- audit CORS headers ------------------------------------------
    result["cors_findings"] = _audit_cors(response.headers)

    # ---- build unified findings list ---------------------------------
    result["security_findings"] = _build_findings(
        result["header_findings"], result["cors_findings"]
    )

    # ---- build threats and solutions (new sections) ------------------
    result["threats"] = _build_threats(
        result["header_findings"], result["cors_findings"], url
    )
    result["solutions"] = _build_solutions(result["threats"])

    # ---- compute score -----------------------------------------------
    score, rating = _compute_score(result["header_findings"], result["cors_findings"])
    result["security_score"] = score
    result["score_rating"] = rating

    return result


# ---------------------------------------------------------------------------
# Security header auditing
# ---------------------------------------------------------------------------
def _audit_headers(headers: requests.structures.CaseInsensitiveDict) -> list:
    """
    Checks for the six required security headers and returns a list of dicts,
    one per header, describing its status, value, risk, and remediation.
    """
    findings = []
    for header_name, meta in SECURITY_HEADERS.items():
        value = headers.get(header_name)

        if value is None:
            status = "Missing"
        else:
            # Basic "needs review" heuristics
            status = _header_needs_review(header_name, value)

        findings.append(
            {
                "header": header_name,
                "value": value or "—",
                "status": status,
                "risk": meta["risk"] if status != "Present" else "Informational",
                "explanation": meta["explanation"],
                "remediation": meta["remediation"] if status != "Present" else "No action required.",
                "note": meta["note"],
            }
        )
    return findings


def _header_needs_review(name: str, value: str) -> str:
    """
    Returns 'Present', or 'Needs Review' based on simple heuristic checks.
    Does NOT claim to be exhaustive.
    """
    v = value.lower()

    if name == "Strict-Transport-Security":
        # Warn if max-age is very short (< 1 day = 86400 s)
        if "max-age=" in v:
            try:
                age = int(v.split("max-age=")[1].split(";")[0].strip())
                if age < 86400:
                    return "Needs Review"
            except ValueError:
                pass
        return "Present"

    if name == "Content-Security-Policy":
        # Unsafe-inline or unsafe-eval weaken CSP significantly
        if "unsafe-inline" in v or "unsafe-eval" in v:
            return "Needs Review"
        return "Present"

    if name == "X-Content-Type-Options":
        return "Present" if "nosniff" in v else "Needs Review"

    if name == "X-Frame-Options":
        return "Present" if any(x in v for x in ("deny", "sameorigin")) else "Needs Review"

    # Referrer-Policy and Permissions-Policy: just flag as present
    return "Present"


# ---------------------------------------------------------------------------
# CORS header auditing
# ---------------------------------------------------------------------------
def _audit_cors(headers: requests.structures.CaseInsensitiveDict) -> list:
    """
    Inspects CORS-related response headers and returns a list of finding dicts.
    Does NOT send arbitrary Origin headers — only reads what the server returned.
    """
    cors_headers = {
        "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin"),
        "Access-Control-Allow-Credentials": headers.get("Access-Control-Allow-Credentials"),
        "Access-Control-Allow-Methods": headers.get("Access-Control-Allow-Methods"),
        "Access-Control-Allow-Headers": headers.get("Access-Control-Allow-Headers"),
    }

    findings = []

    origin = cors_headers["Access-Control-Allow-Origin"]
    credentials = cors_headers["Access-Control-Allow-Credentials"]

    # -- No CORS headers at all ----------------------------------------
    if all(v is None for v in cors_headers.values()):
        findings.append(
            {
                "header": "Access-Control-Allow-Origin",
                "value": "Not present",
                "risk": "Informational",
                "reason": (
                    "No CORS headers were returned. Cross-origin requests to this "
                    "endpoint will be blocked by browsers by default."
                ),
                "remediation": (
                    "If cross-origin access is intentional, configure an explicit "
                    "Access-Control-Allow-Origin policy."
                ),
            }
        )
        return findings

    # -- Wildcard origin -----------------------------------------------
    if origin == "*":
        cred_enabled = credentials and credentials.lower() == "true"
        if cred_enabled:
            # Browsers actually BLOCK credentials with wildcard origin,
            # but the server config is still contradictory / worth flagging.
            findings.append(
                {
                    "header": "Access-Control-Allow-Origin / Credentials",
                    "value": f"Origin: * | Credentials: {credentials}",
                    "risk": "High",
                    "reason": (
                        "The server returns Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true. Browsers block credentialed "
                        "requests to wildcard origins per the CORS spec, but this combination "
                        "indicates a server misconfiguration that should be corrected."
                    ),
                    "remediation": (
                        "Set an explicit origin (e.g. https://trusted.example.com) instead "
                        "of * when credentials are required."
                    ),
                }
            )
        else:
            findings.append(
                {
                    "header": "Access-Control-Allow-Origin",
                    "value": origin,
                    "risk": "Medium",
                    "reason": (
                        "A wildcard origin (*) allows any domain to read the response. "
                        "This is acceptable for public APIs but inappropriate for endpoints "
                        "that return sensitive user data."
                    ),
                    "remediation": (
                        "For public read-only resources this may be intentional. "
                        "If the endpoint returns user-specific data, restrict the origin "
                        "to an explicit allow-list."
                    ),
                }
            )

    # -- Explicit origin (non-wildcard) --------------------------------
    elif origin is not None:
        findings.append(
            {
                "header": "Access-Control-Allow-Origin",
                "value": origin,
                "risk": "Informational",
                "reason": (
                    f"An explicit origin ({origin}) is configured. "
                    "Verify that this matches the intended trusted domain."
                ),
                "remediation": "Ensure the origin matches your intended trusted domain.",
            }
        )

    # -- Methods -------------------------------------------------------
    methods = cors_headers["Access-Control-Allow-Methods"]
    if methods:
        dangerous = [m.strip().upper() for m in methods.split(",")
                     if m.strip().upper() in ("DELETE", "PUT", "PATCH")]
        if dangerous:
            findings.append(
                {
                    "header": "Access-Control-Allow-Methods",
                    "value": methods,
                    "risk": "Medium",
                    "reason": (
                        f"The allowed methods include {', '.join(dangerous)}. "
                        "These mutating methods should only be permitted from trusted origins."
                    ),
                    "remediation": (
                        "Restrict allowed methods to only those required by your API. "
                        "Ensure the Allow-Origin is not a wildcard when these methods are permitted."
                    ),
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Threats Detected — builds a structured list of potential issues
# ---------------------------------------------------------------------------
def _build_threats(header_findings: list, cors_findings: list, url: str) -> list:
    """
    Derives a list of potential threats from the header and CORS audit results.

    Each threat dict contains:
      - threat_name       : short human-readable label
      - category          : 'Security Header' or 'CORS Configuration'
      - affected          : which header or setting triggered this
      - observed          : the value (or absence) observed
      - risk_level        : High / Medium / Low / Informational
      - explanation       : plain-language description of the potential risk

    Important: threats are potential configuration weaknesses identified
    passively from response headers.  They are NOT confirmed exploits.
    """
    threats = []
    is_https = url.lower().startswith("https://")

    # -- Iterate over header audit results ---------------------------
    for h in header_findings:
        name = h["header"]
        status = h["status"]
        value = h["value"]

        # Strict-Transport-Security — only meaningful over HTTPS
        if name == "Strict-Transport-Security":
            if status == "Missing" and is_https:
                threats.append({
                    "threat_name": "Missing HSTS Header",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "High",
                    "explanation": (
                        "The site is served over HTTPS but does not include a "
                        "Strict-Transport-Security (HSTS) header. Without HSTS, browsers "
                        "will not automatically enforce HTTPS on subsequent visits, leaving "
                        "the site potentially exposed to protocol-downgrade interception on "
                        "first visit. Note: this check is limited to the observed response "
                        "and cannot confirm whether HSTS is configured at a CDN layer."
                    ),
                })
            elif status == "Missing" and not is_https:
                threats.append({
                    "threat_name": "HSTS Not Applicable (HTTP)",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "Informational",
                    "explanation": (
                        "HSTS was not found, but the URL uses plain HTTP. HSTS is only "
                        "effective and meaningful over HTTPS. If this site also has an "
                        "HTTPS endpoint, verify that HSTS is set there."
                    ),
                })
            elif status == "Needs Review":
                threats.append({
                    "threat_name": "Weak HSTS Configuration",
                    "category": "Security Header",
                    "affected": name,
                    "observed": value,
                    "risk_level": "Medium",
                    "explanation": (
                        "A Strict-Transport-Security header is present but may be "
                        "too short-lived (max-age below 86400 seconds / 1 day). "
                        "A very short max-age reduces the effectiveness of HSTS "
                        "because browsers will re-check more frequently."
                    ),
                })

        # Content-Security-Policy
        elif name == "Content-Security-Policy":
            if status == "Missing":
                threats.append({
                    "threat_name": "Missing Content-Security-Policy",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "High",
                    "explanation": (
                        "No Content-Security-Policy (CSP) header was returned. "
                        "Without CSP, the browser applies no restrictions on which "
                        "scripts, styles, or resources the page may load, increasing "
                        "the potential attack surface for Cross-Site Scripting (XSS). "
                        "Note: the absence of a CSP header alone does not confirm "
                        "that the page is vulnerable to XSS."
                    ),
                })
            elif status == "Needs Review":
                threats.append({
                    "threat_name": "Potentially Weak CSP Directives",
                    "category": "Security Header",
                    "affected": name,
                    "observed": value,
                    "risk_level": "Medium",
                    "explanation": (
                        "The Content-Security-Policy header is present but includes "
                        "'unsafe-inline' or 'unsafe-eval' directives. These keywords "
                        "significantly reduce the protection CSP can provide against "
                        "inline script injection. The actual risk depends on the "
                        "full policy and the application's content."
                    ),
                })

        # X-Content-Type-Options
        elif name == "X-Content-Type-Options":
            if status == "Missing":
                threats.append({
                    "threat_name": "Missing X-Content-Type-Options",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "Medium",
                    "explanation": (
                        "The X-Content-Type-Options header is absent. Without it, "
                        "some older browsers may attempt to 'MIME-sniff' response "
                        "content, potentially interpreting a non-script file as "
                        "executable script. Modern browsers largely mitigate this "
                        "by default, but the header remains best practice."
                    ),
                })
            elif status == "Needs Review":
                threats.append({
                    "threat_name": "X-Content-Type-Options Not Set to nosniff",
                    "category": "Security Header",
                    "affected": name,
                    "observed": value,
                    "risk_level": "Low",
                    "explanation": (
                        "The X-Content-Type-Options header is present but does not "
                        "contain the expected 'nosniff' value. Only 'nosniff' instructs "
                        "browsers to block MIME-type sniffing."
                    ),
                })

        # X-Frame-Options (clickjacking)
        elif name == "X-Frame-Options":
            if status == "Missing":
                threats.append({
                    "threat_name": "Missing Clickjacking Protection",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "Medium",
                    "explanation": (
                        "Neither X-Frame-Options nor a CSP frame-ancestors directive "
                        "was detected. Without framing controls, the page may be "
                        "embeddable in an iframe by any third-party site, which is a "
                        "prerequisite for clickjacking attacks. Whether this is "
                        "exploitable depends on the page's functionality and authentication."
                    ),
                })
            elif status == "Needs Review":
                threats.append({
                    "threat_name": "X-Frame-Options Value Needs Review",
                    "category": "Security Header",
                    "affected": name,
                    "observed": value,
                    "risk_level": "Low",
                    "explanation": (
                        "X-Frame-Options is present but does not use a recognised "
                        "value (DENY or SAMEORIGIN). Browsers may ignore unrecognised "
                        "values, leaving the clickjacking protection ineffective."
                    ),
                })

        # Referrer-Policy
        elif name == "Referrer-Policy":
            if status == "Missing":
                threats.append({
                    "threat_name": "Missing Referrer-Policy",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "Low",
                    "explanation": (
                        "No Referrer-Policy header was found. Without it, browsers "
                        "apply their default referrer behaviour, which may include "
                        "sending the full URL of the originating page in the Referer "
                        "header to third-party sites. This could leak path or query "
                        "string data depending on the site's URL structure."
                    ),
                })

        # Permissions-Policy
        elif name == "Permissions-Policy":
            if status == "Missing":
                threats.append({
                    "threat_name": "Missing Permissions-Policy",
                    "category": "Security Header",
                    "affected": name,
                    "observed": "Not present",
                    "risk_level": "Low",
                    "explanation": (
                        "No Permissions-Policy header was returned. Without it, "
                        "the page does not explicitly restrict which browser features "
                        "(such as geolocation, camera, or microphone) embedded iframes "
                        "or third-party scripts may request. The actual risk depends "
                        "on whether the page embeds untrusted third-party content."
                    ),
                })

    # -- CORS-derived threats ----------------------------------------
    for c in cors_findings:
        risk = c["risk"]
        header = c["header"]
        value = c["value"]

        if risk == "High":
            threats.append({
                "threat_name": "CORS Wildcard Origin with Credentials",
                "category": "CORS Configuration",
                "affected": header,
                "observed": value,
                "risk_level": "High",
                "explanation": (
                    "The server is configured to return both Access-Control-Allow-Origin: * "
                    "and Access-Control-Allow-Credentials: true. Modern browsers refuse "
                    "to honour credentials (cookies, auth headers) with a wildcard origin, "
                    "so this combination will not function as intended. However, it reveals "
                    "a server misconfiguration that should be corrected before it could be "
                    "inadvertently 'fixed' in a way that does introduce a real risk."
                ),
            })
        elif risk == "Medium" and "Access-Control-Allow-Origin" in header:
            threats.append({
                "threat_name": "CORS Wildcard Origin",
                "category": "CORS Configuration",
                "affected": header,
                "observed": value,
                "risk_level": "Medium",
                "explanation": (
                    "Access-Control-Allow-Origin: * permits any origin to read the "
                    "response cross-origin. For public, read-only, unauthenticated "
                    "resources this is often intentional. For endpoints that return "
                    "user-specific data or accept mutations, a wildcard origin is "
                    "a configuration weakness worth reviewing."
                ),
            })
        elif risk == "Medium" and "Methods" in header:
            threats.append({
                "threat_name": "CORS Allows Mutating Methods",
                "category": "CORS Configuration",
                "affected": header,
                "observed": value,
                "risk_level": "Medium",
                "explanation": (
                    "The CORS policy permits mutating HTTP methods (DELETE, PUT, or PATCH) "
                    "from cross-origin callers. Combined with a permissive Allow-Origin, "
                    "this could allow unintended modification of server-side resources. "
                    "Verify the Allow-Origin is appropriately restricted."
                ),
            })
        elif risk == "Informational":
            threats.append({
                "threat_name": "CORS Configuration Note",
                "category": "CORS Configuration",
                "affected": header,
                "observed": value,
                "risk_level": "Informational",
                "explanation": c["reason"],
            })

    # -- If nothing was found, return a friendly placeholder ----------
    if not threats:
        threats.append({
            "threat_name": "No potential issues detected by the current checks",
            "category": "—",
            "affected": "—",
            "observed": "—",
            "risk_level": "Informational",
            "explanation": (
                "All checked headers are present and no CORS configuration concerns "
                "were identified. This does not mean the website is completely secure — "
                "many vulnerabilities cannot be detected from HTTP response headers alone."
            ),
        })

    return threats


# ---------------------------------------------------------------------------
# Recommended Solutions — one solution dict per threat
# ---------------------------------------------------------------------------

# A lookup table mapping threat_name → solution details.
# This avoids duplication: the data is defined once here and reused by
# _build_solutions() to match solutions to threats at runtime.
_SOLUTION_LOOKUP = {
    "Missing HSTS Header": {
        "why_it_matters": (
            "Without HSTS, a user's first visit to the site over HTTP can be "
            "intercepted and downgraded. HSTS instructs the browser to always "
            "use HTTPS after the first visit, preventing protocol-downgrade "
            "interception for returning users."
        ),
        "recommended_solution": (
            "Add the Strict-Transport-Security header to all HTTPS responses. "
            "Start with a short max-age while testing, then increase to at least "
            "one year once you have confirmed all content and subdomains work over HTTPS."
        ),
        "example_config": (
            "# Apache (.htaccess or httpd.conf)\n"
            "Header always set Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains; preload\"\n\n"
            "# Nginx\n"
            "add_header Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains; preload\" always;\n\n"
            "# Express (Node.js) — use the helmet package\n"
            "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));"
        ),
        "verification_steps": (
            "1. Send a GET request to the HTTPS URL and check the response headers.\n"
            "2. Confirm Strict-Transport-Security is present with the intended max-age.\n"
            "3. Visit https://hstspreload.org to check eligibility for browser preloading.\n"
            "4. Test with curl: curl -I https://yoursite.com | grep -i strict"
        ),
    },
    "HSTS Not Applicable (HTTP)": {
        "why_it_matters": (
            "HSTS only works over HTTPS. If the site serves any content over "
            "plain HTTP, that traffic is unencrypted and cannot be protected by HSTS."
        ),
        "recommended_solution": (
            "Enable HTTPS across the entire site (e.g. with a free Let's Encrypt "
            "certificate), redirect all HTTP traffic to HTTPS, then add an HSTS header "
            "to the HTTPS responses."
        ),
        "example_config": (
            "# Redirect HTTP → HTTPS in Nginx\n"
            "server {\n"
            "    listen 80;\n"
            "    return 301 https://$host$request_uri;\n"
            "}"
        ),
        "verification_steps": (
            "1. Confirm the site responds on https:// without certificate errors.\n"
            "2. Confirm http:// redirects to https://.\n"
            "3. Check that the HTTPS response includes Strict-Transport-Security."
        ),
    },
    "Weak HSTS Configuration": {
        "why_it_matters": (
            "A very short max-age means the browser's HSTS record expires quickly, "
            "reducing the window of protection for returning users."
        ),
        "recommended_solution": (
            "Increase max-age to at least 86400 (1 day) during testing and to "
            "31536000 (1 year) in production. Add includeSubDomains after verifying "
            "all subdomains support HTTPS."
        ),
        "example_config": (
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        "verification_steps": (
            "1. Check the Strict-Transport-Security value in the response headers.\n"
            "2. Confirm max-age is 31536000 or greater in production."
        ),
    },
    "Missing Content-Security-Policy": {
        "why_it_matters": (
            "CSP is the primary browser-enforced defence against Cross-Site Scripting "
            "(XSS). Without it, any injected script runs with full page privileges. "
            "Deploying even a basic policy reduces the attack surface."
        ),
        "recommended_solution": (
            "Define a Content-Security-Policy appropriate for your application. "
            "Start in report-only mode (Content-Security-Policy-Report-Only) to "
            "identify violations before enforcing the policy."
        ),
        "example_config": (
            "# Strict starting policy — tighten based on your app's actual needs\n"
            "Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; form-action 'self'\n\n"
            "# Report-only mode for initial rollout\n"
            "Content-Security-Policy-Report-Only: default-src 'self'; "
            "report-uri /csp-violation-report"
        ),
        "verification_steps": (
            "1. Check the response for a Content-Security-Policy header.\n"
            "2. Paste the policy value into https://csp-evaluator.withgoogle.com "
            "to identify weaknesses.\n"
            "3. Monitor browser console for CSP violation reports during testing."
        ),
    },
    "Potentially Weak CSP Directives": {
        "why_it_matters": (
            "'unsafe-inline' allows arbitrary inline scripts and styles. "
            "'unsafe-eval' allows dynamic code execution via eval(). "
            "Both directives largely negate the XSS protection that CSP provides."
        ),
        "recommended_solution": (
            "Replace 'unsafe-inline' with nonces or hashes for legitimate inline scripts. "
            "Replace 'unsafe-eval' by refactoring code that uses eval(), setTimeout "
            "with strings, or similar patterns."
        ),
        "example_config": (
            "# Using a nonce (generated fresh per response)\n"
            "Content-Security-Policy: "
            "script-src 'self' 'nonce-{random_base64_value}'\n\n"
            "# The matching script tag\n"
            "<script nonce=\"{random_base64_value}\">/* inline code here */</script>"
        ),
        "verification_steps": (
            "1. Remove 'unsafe-inline' and 'unsafe-eval' from the policy.\n"
            "2. Test the site — check the browser console for CSP violations.\n"
            "3. Add nonces for any remaining legitimate inline scripts."
        ),
    },
    "Missing X-Content-Type-Options": {
        "why_it_matters": (
            "MIME-sniffing can cause browsers to execute files as a different type "
            "than intended. For example, a server returning a JSON file could be "
            "interpreted as HTML or script by older browsers, enabling injection attacks."
        ),
        "recommended_solution": (
            "Add X-Content-Type-Options: nosniff to all HTTP responses. "
            "This is one of the simplest security headers to deploy."
        ),
        "example_config": (
            "# Apache\nHeader always set X-Content-Type-Options \"nosniff\"\n\n"
            "# Nginx\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n"
            "# Express (Node.js)\napp.use(helmet.noSniff());"
        ),
        "verification_steps": (
            "1. Check the response headers for X-Content-Type-Options: nosniff.\n"
            "2. Confirm the header is present on all content types, not just HTML."
        ),
    },
    "X-Content-Type-Options Not Set to nosniff": {
        "why_it_matters": (
            "Only the value 'nosniff' is meaningful. Any other value (or a misspelling) "
            "will not prevent MIME-type sniffing in browsers."
        ),
        "recommended_solution": "Set the header value to exactly: nosniff",
        "example_config": "X-Content-Type-Options: nosniff",
        "verification_steps": (
            "1. Check the response — the value should be exactly 'nosniff'.\n"
            "2. Confirm there are no trailing spaces or typos."
        ),
    },
    "Missing Clickjacking Protection": {
        "why_it_matters": (
            "Without framing restrictions, a malicious site can embed your page in "
            "an invisible or transparent iframe and trick users into clicking UI "
            "elements they cannot see (clickjacking). Authenticated pages are "
            "particularly sensitive."
        ),
        "recommended_solution": (
            "Add X-Frame-Options: DENY (or SAMEORIGIN) or, preferably, use the "
            "modern Content-Security-Policy frame-ancestors directive."
        ),
        "example_config": (
            "# Legacy approach\nX-Frame-Options: DENY\n\n"
            "# Modern CSP approach (takes precedence over X-Frame-Options)\n"
            "Content-Security-Policy: frame-ancestors 'none'\n\n"
            "# Allow embedding only from the same origin\n"
            "Content-Security-Policy: frame-ancestors 'self'"
        ),
        "verification_steps": (
            "1. Check the response for X-Frame-Options or a CSP frame-ancestors directive.\n"
            "2. Open the browser DevTools → Network tab, load the page, and confirm "
            "the header is present.\n"
            "3. Try embedding the page in a test iframe — the browser should block it."
        ),
    },
    "X-Frame-Options Value Needs Review": {
        "why_it_matters": (
            "Only DENY and SAMEORIGIN are standard, widely-supported values. "
            "Non-standard values may be silently ignored by browsers."
        ),
        "recommended_solution": (
            "Change the value to DENY (to block all framing) or "
            "SAMEORIGIN (to allow framing from the same origin only)."
        ),
        "example_config": "X-Frame-Options: DENY",
        "verification_steps": (
            "1. Check the header value is either DENY or SAMEORIGIN.\n"
            "2. Validate using https://securityheaders.com (on sites you own)."
        ),
    },
    "Missing Referrer-Policy": {
        "why_it_matters": (
            "Without a Referrer-Policy, browsers send the full URL of the "
            "current page as the Referer header to third-party sites. "
            "If URLs contain sensitive path segments or query parameters "
            "(e.g. search terms, user IDs), this data can be leaked."
        ),
        "recommended_solution": (
            "Add a Referrer-Policy header. 'strict-origin-when-cross-origin' is "
            "a safe default that sends only the origin (not path/query) on "
            "cross-origin requests while preserving the full URL for same-origin."
        ),
        "example_config": (
            "# Apache\nHeader always set Referrer-Policy "
            "\"strict-origin-when-cross-origin\"\n\n"
            "# Nginx\nadd_header Referrer-Policy "
            "\"strict-origin-when-cross-origin\" always;"
        ),
        "verification_steps": (
            "1. Check the response for a Referrer-Policy header.\n"
            "2. Confirm the chosen policy aligns with the application's "
            "privacy requirements."
        ),
    },
    "Missing Permissions-Policy": {
        "why_it_matters": (
            "Without a Permissions-Policy, embedded iframes and third-party "
            "scripts may be able to request browser features (camera, microphone, "
            "geolocation) that the page itself never uses. Restricting these "
            "reduces the potential damage from a compromised third-party component."
        ),
        "recommended_solution": (
            "Add a Permissions-Policy header that disables all features the "
            "application does not intentionally use. Start restrictive and open "
            "only what is needed."
        ),
        "example_config": (
            "Permissions-Policy: "
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        ),
        "verification_steps": (
            "1. Check the response for a Permissions-Policy header.\n"
            "2. Verify that only the features your application actually needs "
            "are enabled."
        ),
    },
    "CORS Wildcard Origin with Credentials": {
        "why_it_matters": (
            "Combining a wildcard origin with credentials is both a specification "
            "violation (browsers will block it) and a sign that the CORS configuration "
            "was not written carefully. If someone later 'fixes' this by reflecting "
            "the request origin back without validation, a real CORS vulnerability "
            "would be introduced."
        ),
        "recommended_solution": (
            "Replace Access-Control-Allow-Origin: * with the specific trusted origin "
            "that requires credentialed access. Validate the incoming Origin header "
            "server-side against a strict allow-list before reflecting it."
        ),
        "example_config": (
            "# Server-side origin validation (pseudocode)\n"
            "ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "if request.headers['Origin'] in ALLOWED_ORIGINS:\n"
            "    response.headers['Access-Control-Allow-Origin'] = "
            "request.headers['Origin']\n"
            "    response.headers['Access-Control-Allow-Credentials'] = 'true'"
        ),
        "verification_steps": (
            "1. Check that the response no longer returns Access-Control-Allow-Origin: *.\n"
            "2. Confirm the server returns the specific trusted origin.\n"
            "3. Test with a browser request using credentials to confirm it works as expected."
        ),
    },
    "CORS Wildcard Origin": {
        "why_it_matters": (
            "Any website can send a cross-origin request and read the response. "
            "For truly public, unauthenticated data this is usually intentional. "
            "For endpoints that return user-specific or sensitive data, this "
            "allows unauthorised cross-origin reads."
        ),
        "recommended_solution": (
            "If the endpoint serves public data, the wildcard origin is acceptable. "
            "If it serves authenticated or sensitive data, replace * with an "
            "explicit allow-list of trusted origins."
        ),
        "example_config": (
            "Access-Control-Allow-Origin: https://trusted.example.com\n\n"
            "# For multiple origins, validate server-side and reflect the matching origin:\n"
            "# Access-Control-Allow-Origin: https://app.example.com"
        ),
        "verification_steps": (
            "1. Confirm the origin restriction matches your intended access policy.\n"
            "2. If restricting, test cross-origin requests from allowed and disallowed "
            "origins to verify the server behaves correctly."
        ),
    },
    "CORS Allows Mutating Methods": {
        "why_it_matters": (
            "Allowing DELETE, PUT, or PATCH from any cross-origin caller (especially "
            "combined with a wildcard origin) could permit unintended modifications to "
            "server-side resources via cross-origin requests."
        ),
        "recommended_solution": (
            "Restrict Access-Control-Allow-Methods to only the HTTP verbs actually "
            "required by your API. Ensure the corresponding Allow-Origin is not a "
            "wildcard when mutating methods are in use."
        ),
        "example_config": (
            "# If only GET and POST are needed:\n"
            "Access-Control-Allow-Methods: GET, POST\n\n"
            "# If PUT is needed, restrict the origin:\n"
            "Access-Control-Allow-Origin: https://trusted.example.com\n"
            "Access-Control-Allow-Methods: GET, POST, PUT"
        ),
        "verification_steps": (
            "1. Review which HTTP methods the API actually needs to expose cross-origin.\n"
            "2. Remove any methods not required.\n"
            "3. Confirm the Allow-Origin is appropriately restricted."
        ),
    },
    "CORS Configuration Note": {
        "why_it_matters": (
            "The CORS configuration contains an item that is worth reviewing to "
            "ensure it matches the intended access policy."
        ),
        "recommended_solution": (
            "Review the observed CORS headers against your application's intended "
            "cross-origin access requirements and update accordingly."
        ),
        "example_config": "N/A — review specific CORS headers as appropriate.",
        "verification_steps": (
            "1. Confirm the CORS policy matches the intended design.\n"
            "2. Test cross-origin requests from expected client origins."
        ),
    },
}


def _build_solutions(threats: list) -> list:
    """
    Matches each threat to a pre-defined solution and returns a list of solution dicts.
    Each dict contains: threat_name, why_it_matters, recommended_solution,
    example_config, and verification_steps.
    """
    solutions = []
    seen = set()  # avoid duplicate solutions for the same threat type

    for threat in threats:
        name = threat["threat_name"]

        # Skip the "no issues found" placeholder — no solution needed
        if name == "No potential issues detected by the current checks":
            continue

        # Skip duplicates (the same threat type should not appear twice)
        if name in seen:
            continue
        seen.add(name)

        # Look up the matching solution; fall back to a generic entry if not found
        sol = _SOLUTION_LOOKUP.get(name, {
            "why_it_matters": "See the threat explanation for context.",
            "recommended_solution": (
                "Review the identified configuration and apply the remediation "
                "guidance provided in the Security Header Audit section."
            ),
            "example_config": "N/A",
            "verification_steps": (
                "1. Apply the recommended fix.\n"
                "2. Re-scan to confirm the issue no longer appears."
            ),
        })

        solutions.append({
            "threat_name": name,
            "why_it_matters": sol["why_it_matters"],
            "recommended_solution": sol["recommended_solution"],
            "example_config": sol["example_config"],
            "verification_steps": sol["verification_steps"],
        })

    return solutions


# ---------------------------------------------------------------------------
# Unified findings builder
# ---------------------------------------------------------------------------
def _build_findings(header_findings: list, cors_findings: list) -> list:
    """
    Converts header and CORS audit results into a unified findings list
    suitable for the findings table and download reports.
    """
    findings = []

    # -- Header findings -----------------------------------------------
    for h in header_findings:
        if h["status"] == "Present":
            continue  # Only report issues
        severity_map = {"High": "High", "Medium": "Medium", "Low": "Low"}
        severity = severity_map.get(h["risk"], "Informational")
        title = (
            f"Missing header: {h['header']}"
            if h["status"] == "Missing"
            else f"Header needs review: {h['header']}"
        )
        findings.append(
            {
                "title": title,
                "category": "Security Header",
                "severity": severity,
                "explanation": h["explanation"],
                "fix": h["remediation"],
            }
        )

    # -- CORS findings -------------------------------------------------
    cors_sev_map = {"High": "High", "Medium": "Medium", "Informational": "Informational"}
    for c in cors_findings:
        findings.append(
            {
                "title": f"CORS: {c['header']}",
                "category": "CORS Configuration",
                "severity": cors_sev_map.get(c["risk"], "Informational"),
                "explanation": c["reason"],
                "fix": c["remediation"],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Security score computation
# ---------------------------------------------------------------------------
def _compute_score(header_findings: list, cors_findings: list) -> tuple:
    """
    Computes an educational security score (0-100).

    Scoring formula (documented):
      - Start at 100.
      - Each MISSING High-risk header:  -15 points  (max 2 headers × -15 = -30)
      - Each MISSING Medium-risk header: -10 points (max 2 headers × -10 = -20)
      - Each MISSING Low-risk header:    -5 points  (max 2 headers × -5  = -10)
      - Header 'Needs Review' (any risk): -5 points per header
      - CORS High finding:               -15 points (capped at 1 occurrence)
      - CORS Medium finding:             -8 points  (capped at 1 occurrence)

    Score is clamped to [0, 100].
    This is a heuristic for educational purposes, not an industry-standard rating.
    """
    score = 100
    deductions = []

    for h in header_findings:
        if h["status"] == "Missing":
            pts = {"High": 15, "Medium": 10, "Low": 5}.get(h["risk"], 5)
            score -= pts
            deductions.append(f"-{pts} ({h['header']} missing)")
        elif h["status"] == "Needs Review":
            score -= 5
            deductions.append(f"-5 ({h['header']} needs review)")

    cors_high_counted = False
    cors_medium_counted = False
    for c in cors_findings:
        if c["risk"] == "High" and not cors_high_counted:
            score -= 15
            deductions.append("-15 (CORS High risk)")
            cors_high_counted = True
        elif c["risk"] == "Medium" and not cors_medium_counted:
            score -= 8
            deductions.append("-8 (CORS Medium risk)")
            cors_medium_counted = True

    score = max(0, min(100, score))

    # Descriptive rating
    if score >= 85:
        rating = "Good"
    elif score >= 65:
        rating = "Fair"
    elif score >= 40:
        rating = "Poor"
    else:
        rating = "Critical"

    return score, rating


# ---------------------------------------------------------------------------
# Score colour helper
# ---------------------------------------------------------------------------
def _score_colour(score: int) -> str:
    if score >= 85:
        return "#3fb950"
    if score >= 65:
        return "#d29922"
    if score >= 40:
        return "#f0883e"
    return "#f85149"


# ---------------------------------------------------------------------------
# Report generation helpers
# ---------------------------------------------------------------------------
def _build_json_report(result: dict) -> str:
    """Serialises the scan result to a formatted JSON string."""
    report = {
        "scan_info": {
            "timestamp": result["timestamp"],
            "target_url": result["url"],
            "http_status_code": result["status_code"],
            "response_time_ms": result["response_time_ms"],
        },
        "security_score": {
            "score": result["security_score"],
            "rating": result["score_rating"],
            "note": (
                "This score is an educational heuristic and does not represent "
                "a certified security assessment."
            ),
        },
        "header_findings": result["header_findings"],
        "cors_findings": result["cors_findings"],
        "security_findings": result["security_findings"],
        # New sections included in report
        "threats_detected": result.get("threats", []),
        "recommended_solutions": result.get("solutions", []),
    }
    return json.dumps(report, indent=2)


def _build_csv_report(result: dict) -> str:
    """Serialises security findings, threats, and solutions to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    # -- Scan metadata -------------------------------------------------
    writer.writerow(
        ["Timestamp", "Target URL", "HTTP Status", "Response Time (ms)",
         "Security Score", "Score Rating"]
    )
    writer.writerow(
        [result["timestamp"], result["url"], result["status_code"],
         result["response_time_ms"], result["security_score"], result["score_rating"]]
    )
    writer.writerow([])

    # -- Security findings ---------------------------------------------
    writer.writerow(["Title", "Category", "Severity", "Explanation", "Recommended Fix"])
    for f in result["security_findings"]:
        writer.writerow([f["title"], f["category"], f["severity"],
                         f["explanation"], f["fix"]])
    writer.writerow([])

    # -- Threats Detected ----------------------------------------------
    writer.writerow(["--- Threats Detected ---"])
    writer.writerow(["Threat Name", "Category", "Affected Header/Setting",
                     "Observed Value", "Risk Level", "Explanation"])
    for t in result.get("threats", []):
        writer.writerow([
            t["threat_name"], t["category"], t["affected"],
            t["observed"], t["risk_level"], t["explanation"],
        ])
    writer.writerow([])

    # -- Recommended Solutions -----------------------------------------
    writer.writerow(["--- Recommended Solutions ---"])
    writer.writerow(["Threat Name", "Why It Matters", "Recommended Solution",
                     "Example Configuration", "Verification Steps"])
    for s in result.get("solutions", []):
        writer.writerow([
            s["threat_name"], s["why_it_matters"], s["recommended_solution"],
            s["example_config"], s["verification_steps"],
        ])

    return output.getvalue()


# ---------------------------------------------------------------------------
# UI rendering helpers
# ---------------------------------------------------------------------------
def _render_metric_card(label: str, value) -> str:
    return (
        f'<div class="metric-card">'
        f'<div class="metric-value">{value}</div>'
        f'<div class="metric-label">{label}</div>'
        f'</div>'
    )


def _badge(status: str) -> str:
    cls = {
        "Present": "badge-present",
        "Missing": "badge-missing",
        "Needs Review": "badge-review",
    }.get(status, "badge-info")
    return f'<span class="badge {cls}">{status}</span>'


def _sev_span(sev: str) -> str:
    cls = {
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
        "Informational": "sev-info",
    }.get(sev, "sev-info")
    return f'<span class="{cls}">{sev}</span>'


# ---------------------------------------------------------------------------
# Section 1 UI — Threats Detected
# ---------------------------------------------------------------------------
def _render_threats_section(threats: list) -> None:
    """
    Renders the 'Threats Detected' dashboard section.

    Displays a summary table of all detected potential threats, with
    risk-level colour coding and an expandable detail card per threat.
    No additional HTTP requests are made — all data comes from session state.
    """
    st.markdown(
        '<div class="section-heading">⚠️ Threats Detected</div>',
        unsafe_allow_html=True,
    )

    # -- Friendly message when no issues were found --------------------
    if len(threats) == 1 and threats[0]["threat_name"].startswith("No potential"):
        st.success(
            "✅ No potential issues detected by the current checks.  "
            "This does not mean the website is completely secure — many vulnerabilities "
            "cannot be detected from HTTP response headers alone."
        )
        return

    # -- Summary table -------------------------------------------------
    # Build a list of plain dicts for the DataFrame (no HTML in table cells)
    table_rows = []
    for t in threats:
        table_rows.append({
            "Threat Name": t["threat_name"],
            "Category": t["category"],
            "Affected": t["affected"],
            "Observed": t["observed"],
            "Risk Level": t["risk_level"],
        })

    df_threats = pd.DataFrame(table_rows)
    st.dataframe(df_threats, use_container_width=True, hide_index=True)

    st.caption(
        "These findings are potential configuration weaknesses identified passively "
        "from HTTP response headers. They are not confirmed exploits."
    )

    # -- Expandable detail cards per threat ----------------------------
    with st.expander("🔍 Detailed Threat Explanations"):
        for t in threats:
            # Pick a colour for the risk level
            risk_colour = {
                "High": "#f85149",
                "Medium": "#d29922",
                "Low": "#3fb950",
                "Informational": "#58a6ff",
            }.get(t["risk_level"], "#58a6ff")

            sev_html = _sev_span(t["risk_level"])

            st.markdown(
                f'<div class="header-card">'
                f'<div class="header-name" style="color:{risk_colour};">'
                f'{t["threat_name"]} &nbsp; {sev_html}'
                f'</div>'
                f'<div class="header-value">'
                f'Affected: {t["affected"]} &nbsp;|&nbsp; Observed: {t["observed"]}'
                f'</div>'
                f'<div class="header-meta">'
                f'<strong>Category:</strong> {t["category"]}<br>'
                f'<strong>Explanation:</strong> {t["explanation"]}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Section 2 UI — Recommended Solutions
# ---------------------------------------------------------------------------
def _render_solutions_section(solutions: list) -> None:
    """
    Renders the 'Recommended Solutions' dashboard section.

    For each threat that was detected, shows: why it matters, the recommended
    fix, an example configuration, and verification steps.
    All data comes from session state — no new HTTP requests.
    """
    st.markdown(
        '<div class="section-heading">🛠️ Recommended Solutions</div>',
        unsafe_allow_html=True,
    )

    if not solutions:
        st.info(
            "No recommendations to display. Either no threats were detected, "
            "or all detected items are informational only."
        )
        return

    # -- One card per solution -----------------------------------------
    for sol in solutions:
        # Render example config as a monospace code block inside the card
        example_html = (
            f'<pre style="background:#0d1117;color:#c9d1d9;border:1px solid #30363d;'
            f'border-radius:6px;padding:10px 14px;font-size:0.80rem;'
            f'white-space:pre-wrap;word-break:break-word;margin:6px 0;">'
            f'{sol["example_config"]}'
            f'</pre>'
        )

        # Verification steps — convert newlines to <br> for HTML display
        steps_html = sol["verification_steps"].replace("\n", "<br>")

        st.markdown(
            f'<div class="header-card">'
            f'<div class="header-name">{sol["threat_name"]}</div>'
            f'<div class="header-meta">'
            f'<strong>Why it matters:</strong><br>'
            f'{sol["why_it_matters"]}'
            f'<br><br>'
            f'<strong>Recommended solution:</strong><br>'
            f'{sol["recommended_solution"]}'
            f'<br><br>'
            f'<strong>Example configuration:</strong>'
            f'</div>'
            f'{example_html}'
            f'<div class="header-meta">'
            f'<strong>Verification steps:</strong><br>'
            f'{steps_html}'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
def main():
    # ---- title & subtitle -------------------------------------------
    st.markdown(
        '<h1 style="color:#58a6ff;margin-bottom:2px;">🛡️ Automated Web Security Scanner</h1>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<p style="color:#8b949e;font-size:1rem;margin-top:0;">Website Security Header and CORS Configuration Auditor</p>',
        unsafe_allow_html=True,
    )

    # ---- disclaimer --------------------------------------------------
    st.markdown(
        '<div class="disclaimer-box">'
        '<strong style="color:#d29922;">⚠️ Responsible Use:</strong> '
        'Only scan websites you own or have explicit permission to test. '
        'This tool performs a passive read of HTTP response headers — it does not '
        'exploit vulnerabilities, bypass authentication, or crawl links. '
        'Results are educational heuristics, not certified security assessments.'
        '</div>',
        unsafe_allow_html=True,
    )

    # ---- URL input & scan button ------------------------------------
    col_input, col_btn = st.columns([5, 1])
    with col_input:
        raw_url = st.text_input(
            "Website URL",
            placeholder="https://example.com",
            label_visibility="collapsed",
        )
    with col_btn:
        scan_clicked = st.button("🔍 Scan Website", use_container_width=True)

    # ---- initialise session state ------------------------------------
    if "scan_result" not in st.session_state:
        st.session_state.scan_result = None

    # ---- trigger scan ------------------------------------------------
    if scan_clicked:
        if not raw_url.strip():
            st.warning("Please enter a URL before scanning.")
        else:
            url = normalise_url(raw_url)
            with st.spinner(f"Scanning {url} …"):
                st.session_state.scan_result = scan_website(url)

    result = st.session_state.scan_result

    # ---- nothing scanned yet -----------------------------------------
    if result is None:
        st.markdown(
            '<p style="color:#8b949e;text-align:center;margin-top:60px;">'
            'Enter a URL above and click <strong>Scan Website</strong> to begin.'
            '</p>',
            unsafe_allow_html=True,
        )
        return

    # ---- error state -------------------------------------------------
    if result.get("error"):
        st.error(f"**Scan failed:** {result['error']}")
        return

    # ==================================================================
    # Results section
    # ==================================================================

    # ---- scan metadata -----------------------------------------------
    st.markdown('<div class="section-heading">Scan Summary</div>', unsafe_allow_html=True)
    meta_c1, meta_c2, meta_c3 = st.columns(3)
    with meta_c1:
        st.markdown(
            f'<div style="color:#8b949e;font-size:0.85rem;">Target URL</div>'
            f'<div style="color:#e6edf3;font-size:0.92rem;word-break:break-all;">{result["url"]}</div>',
            unsafe_allow_html=True,
        )
    with meta_c2:
        status_colour = "#3fb950" if result["status_code"] == 200 else "#d29922"
        st.markdown(
            f'<div style="color:#8b949e;font-size:0.85rem;">HTTP Status</div>'
            f'<div style="color:{status_colour};font-size:0.92rem;font-weight:600;">'
            f'{result["status_code"]}</div>',
            unsafe_allow_html=True,
        )
    with meta_c3:
        st.markdown(
            f'<div style="color:#8b949e;font-size:0.85rem;">Response Time</div>'
            f'<div style="color:#e6edf3;font-size:0.92rem;">{result["response_time_ms"]} ms</div>',
            unsafe_allow_html=True,
        )

    # ---- metric cards ------------------------------------------------
    st.markdown('<div class="section-heading">Overview</div>', unsafe_allow_html=True)

    headers_checked = len(SECURITY_HEADERS)
    missing_count = sum(1 for h in result["header_findings"] if h["status"] == "Missing")
    cors_warnings = sum(
        1 for c in result["cors_findings"] if c["risk"] in ("High", "Medium")
    )
    total_findings = len(result["security_findings"])

    mc1, mc2, mc3, mc4 = st.columns(4)
    for col, label, value in [
        (mc1, "Headers Checked", headers_checked),
        (mc2, "Missing Headers", missing_count),
        (mc3, "CORS Warnings", cors_warnings),
        (mc4, "Total Findings", total_findings),
    ]:
        with col:
            st.markdown(_render_metric_card(label, value), unsafe_allow_html=True)

    # ---- security score ----------------------------------------------
    st.markdown('<div class="section-heading">Security Score</div>', unsafe_allow_html=True)
    score = result["security_score"]
    rating = result["score_rating"]
    colour = _score_colour(score)
    score_c1, score_c2 = st.columns([1, 3])
    with score_c1:
        st.markdown(
            f'<div class="score-wrap">'
            f'<div class="score-number" style="color:{colour};">{score}</div>'
            f'<div class="score-label" style="color:{colour};">/ 100 — {rating}</div>'
            f'<div class="score-disclaimer">'
            f'Educational heuristic only. Not a certified security rating.'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with score_c2:
        # Mini score bar using Streamlit's built-in progress bar
        st.markdown(
            '<div style="padding-top:28px;"></div>',
            unsafe_allow_html=True,
        )
        st.progress(score / 100)
        scoring_note = (
            "**Score formula (educational):** Starts at 100. "
            "Deducts 15 pts per missing High-risk header, 10 pts per missing Medium-risk header, "
            "5 pts per missing Low-risk header, 5 pts per header needing review, "
            "15 pts for a High CORS risk, and 8 pts for a Medium CORS risk. "
            "Clamped to [0, 100]. Does not double-count the same issue."
        )
        st.caption(scoring_note)

    # ---- charts ------------------------------------------------------
    st.markdown('<div class="section-heading">Visual Analysis</div>', unsafe_allow_html=True)
    chart_c1, chart_c2 = st.columns(2)

    with chart_c1:
        # Findings grouped by severity
        sev_counts = {}
        for f in result["security_findings"]:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        if sev_counts:
            df_sev = pd.DataFrame(
                list(sev_counts.items()), columns=["Severity", "Count"]
            ).sort_values("Severity")
            st.bar_chart(df_sev.set_index("Severity"), color="#58a6ff")
            st.caption("Findings by severity level")
        else:
            st.info("No findings to chart.")

    with chart_c2:
        # Present vs missing headers
        status_counts = {}
        for h in result["header_findings"]:
            status_counts[h["status"]] = status_counts.get(h["status"], 0) + 1
        df_status = pd.DataFrame(
            list(status_counts.items()), columns=["Status", "Count"]
        )
        st.bar_chart(df_status.set_index("Status"), color="#3fb950")
        st.caption("Security headers: Present / Missing / Needs Review")

    # ---- security header details ------------------------------------
    st.markdown(
        '<div class="section-heading">Security Header Audit</div>',
        unsafe_allow_html=True,
    )
    for h in result["header_findings"]:
        badge_html = _badge(h["status"])
        note_html = (
            f'<br><em style="color:#6e7681;font-size:0.78rem;">Note: {h["note"]}</em>'
            if h["note"]
            else ""
        )
        st.markdown(
            f'<div class="header-card">'
            f'<div class="header-name">{h["header"]} &nbsp; {badge_html}</div>'
            f'<div class="header-value">Value: {h["value"]}</div>'
            f'<div class="header-meta">'
            f'<strong>Risk:</strong> {h["risk"]}<br>'
            f'<strong>Explanation:</strong> {h["explanation"]}<br>'
            f'<strong>Remediation:</strong> {h["remediation"]}'
            f'{note_html}'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ---- CORS analysis -----------------------------------------------
    st.markdown(
        '<div class="section-heading">CORS Configuration Analysis</div>',
        unsafe_allow_html=True,
    )
    # Show raw CORS header values
    cors_header_names = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
    ]
    raw_cors_rows = []
    for name in cors_header_names:
        value = result["response_headers"].get(name, "—")
        raw_cors_rows.append({"Header": name, "Value": value})
    df_cors_raw = pd.DataFrame(raw_cors_rows)
    st.dataframe(df_cors_raw, use_container_width=True, hide_index=True)

    # CORS findings
    if result["cors_findings"]:
        for c in result["cors_findings"]:
            risk_colour = {"High": "#f85149", "Medium": "#d29922"}.get(
                c["risk"], "#58a6ff"
            )
            st.markdown(
                f'<div class="header-card">'
                f'<div class="header-name" style="color:{risk_colour};">'
                f'{c["header"]} — {c["risk"]} Risk'
                f'</div>'
                f'<div class="header-value">Value: {c["value"]}</div>'
                f'<div class="header-meta">'
                f'<strong>Reason:</strong> {c["reason"]}<br>'
                f'<strong>Remediation:</strong> {c["remediation"]}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No CORS findings.")

    # ---- findings table with filters ---------------------------------
    st.markdown(
        '<div class="section-heading">Security Findings</div>',
        unsafe_allow_html=True,
    )
    if result["security_findings"]:
        df_findings = pd.DataFrame(result["security_findings"])
        df_findings.columns = ["Title", "Category", "Severity", "Explanation", "Recommended Fix"]

        # Filters (operate on session-state data, no new HTTP request)
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            severity_options = ["All"] + sorted(df_findings["Severity"].unique().tolist())
            sev_filter = st.selectbox("Filter by Severity", severity_options)
        with f_col2:
            cat_options = ["All"] + sorted(df_findings["Category"].unique().tolist())
            cat_filter = st.selectbox("Filter by Category", cat_options)

        df_display = df_findings.copy()
        if sev_filter != "All":
            df_display = df_display[df_display["Severity"] == sev_filter]
        if cat_filter != "All":
            df_display = df_display[df_display["Category"] == cat_filter]

        st.dataframe(df_display, use_container_width=True, hide_index=True)

        # Expandable detail view
        with st.expander("📋 Detailed Findings Explanation"):
            for _, row in df_display.iterrows():
                sev_html = _sev_span(row["Severity"])
                st.markdown(
                    f'<div class="header-card">'
                    f'<div class="header-name">{row["Title"]} &nbsp; {sev_html}</div>'
                    f'<div class="header-meta">'
                    f'<strong>Category:</strong> {row["Category"]}<br>'
                    f'<strong>Explanation:</strong> {row["Explanation"]}<br>'
                    f'<strong>Recommended Fix:</strong> {row["Recommended Fix"]}'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
    else:
        st.success("✅ No security findings were identified.")

    # ---- SECTION 1: Threats Detected ---------------------------------
    # Renders from session-state data; no new HTTP request is made.
    _render_threats_section(result.get("threats", []))

    # ---- SECTION 2: Recommended Solutions ----------------------------
    # Matched 1-to-1 with threats; no new HTTP request.
    _render_solutions_section(result.get("solutions", []))

    # ---- response headers expander -----------------------------------
    with st.expander("🔎 All Response Headers"):
        if result["response_headers"]:
            df_headers = pd.DataFrame(
                list(result["response_headers"].items()),
                columns=["Header", "Value"],
            )
            st.dataframe(df_headers, use_container_width=True, hide_index=True)
        else:
            st.write("No response headers captured.")

    # ---- download buttons -------------------------------------------
    st.markdown(
        '<div class="section-heading">Download Reports</div>',
        unsafe_allow_html=True,
    )
    dl_c1, dl_c2 = st.columns(2)

    json_report = _build_json_report(result)
    csv_report = _build_csv_report(result)
    ts_safe = result["timestamp"].replace(":", "-").replace(".", "-")

    with dl_c1:
        st.download_button(
            label="⬇️ Download JSON Report",
            data=json_report,
            file_name=f"security_scan_{ts_safe}.json",
            mime="application/json",
            use_container_width=True,
        )
    with dl_c2:
        st.download_button(
            label="⬇️ Download CSV Report",
            data=csv_report,
            file_name=f"security_scan_{ts_safe}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # ---- footer ------------------------------------------------------
    st.markdown(
        '<div style="text-align:center;color:#6e7681;font-size:0.78rem;'
        'border-top:1px solid #30363d;margin-top:40px;padding-top:16px;">'
        'Automated Web Security Scanner — Educational Use Only. '
        'Scan only websites you own or have explicit permission to test.'
        '</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
