# Content-Type Validation Checker

A real, no-mock-data security auditing tool that issues a genuine HTTP GET request to a URL you authorize and inspects the **actual live `Content-Type` and `X-Content-Type-Options` response headers** (plus a small, capped prefix of the real response body for lightweight content sniffing) to flag MIME-sniffing risk factors — missing or absent Content-Type, missing `nosniff` protection, missing charsets on renderable types, and JSON bodies mislabeled with a renderable Content-Type.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from an actual response received from the target server at scan time.

- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a single, harmless-looking GET request.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit (PCI-DSS, SOC 2, ISO 27001, etc.), or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and API engineers who want to verify their endpoints declare correct, precise Content-Types.
- AppSec engineers auditing MIME-sniffing protections (`X-Content-Type-Options: nosniff`) on in-scope assets.
- Teams that serve user-uploaded content or reflect JSON/API data and want to confirm browsers can't be tricked into rendering it as HTML/script.
- Students and educators studying real-world MIME-sniffing-based XSS attack surfaces with a genuine, working tool.

## Why use this project

An incorrect or missing `Content-Type` is not a cosmetic issue — it is the root enabling condition behind entire classes of MIME-sniffing XSS and content-spoofing attacks. Browsers that can't trust the declared type will guess one from the body, and historically that guess has been abused to make a "safe" JSON or plain-text response execute as HTML/JavaScript. This tool automates detection of the concrete, real-world patterns that enable this — using a single real HTTP request, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility — all self-hosted, all open, all inspectable.

---

## Detection Rules

Every rule below is evaluated against the **actual response headers (and a small capped body prefix)** of the one real HTTP GET request made during a scan.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| CTV-001 | Missing Content-Type Header | High | The response has no `Content-Type` header at all, forcing browsers to MIME-sniff the body to guess a type. |
| CTV-002 | Missing X-Content-Type-Options: nosniff | Medium | The response lacks `X-Content-Type-Options: nosniff`, a prerequisite protection against MIME-confusion attacks. |
| CTV-003 | Renderable Content-Type Missing Explicit Charset | Medium | An HTML/XHTML/SVG response declares no charset, which has historically enabled charset-sniffing-based XSS bypasses. |
| CTV-004 | JSON-Looking Body Served With Renderable Content-Type | High | A response body that looks like JSON is served with a renderable type like `text/html` instead of `application/json`. |
| CTV-005 | Multiple/Ambiguous Content-Type Values | Medium | More than one `Content-Type` value is present, risking parser confusion between the browser, proxies, and security filters. |
| CTV-006 | octet-stream Response Without Content-Disposition | Low | A generic `application/octet-stream` response has no `Content-Disposition` to force a download, leaving type handling ambiguous. |
| CTV-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a MIME finding — an operational note. |

---

## Architecture

```
content-type-validation-checker/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — issues the real HTTP GET request via `requests`
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating real headers/body prefix
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-HTTP-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd content-type-validation-checker
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# Skip TLS verification (e.g. internal self-signed hosts you control)
python3 cli/main.py scan https://internal.example.com --no-verify-tls

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic response dicts, and genuine end-to-end tests that boot a real local HTTP server on an ephemeral `127.0.0.1` port and perform an actual HTTP request against it via the real Security Engine — no third-party network calls are made during testing.

---

## Frequently Asked Questions

**What does the Content-Type Validation Checker check?**
It issues one real HTTP GET request to a URL you authorize and inspects the live `Content-Type` and `X-Content-Type-Options` response headers, flagging a missing Content-Type, missing nosniff protection, missing charset on renderable types, JSON bodies mislabeled with a renderable Content-Type, and other real MIME-sniffing risk factors — never sample data.

**Who should use the Content-Type Validation Checker?**
Web developers and security engineers auditing Content-Type correctness and MIME-sniffing protections on sites and applications they own or are explicitly authorized to test.

**Is the Content-Type Validation Checker a replacement for a professional security audit?**
No. It is an educational and productivity aid only. It does not replace a certified penetration test, compliance audit, or professional security assessment.

**Why does a missing charset matter for security, not just correctness?**
Without an explicit charset, some browsers historically fell back to sniffing an encoding (such as UTF-7) from the document body itself — a technique that has been used to smuggle executable script past filters that assumed a fixed encoding.

**Does this tool send more than one request per scan?**
No. Each scan is a single, standard HTTP GET request with redirects followed by the underlying HTTP client — no repeated requests, no brute-forcing, no payload injection. Only a small, capped prefix of the response body is inspected in memory for lightweight content sniffing; it is never stored or exported.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
