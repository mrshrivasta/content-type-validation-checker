"""
Detection Rules — Content-Type Validation Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects REAL HTTP response headers (and a small, size-capped
prefix of the real response body used only for lightweight content
sniffing) collected from a live GET request to a target URL you provide.
No sample HTTP data is ever generated — every value comes from the actual
server response at scan time.

An incorrect or missing Content-Type is a genuine, exploitable security
issue: it enables browser MIME-sniffing, which is the root cause behind
several classes of stored/reflected XSS and content-spoofing attacks.
"""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

TEXTUAL_TYPES = ("text/", "application/json", "application/javascript",
                  "application/xml", "application/xhtml+xml", "image/svg+xml")

DANGEROUS_RENDERABLE_TYPES = ("text/html", "application/xhtml+xml", "image/svg+xml")


def _content_type(response):
    return response["headers_lower"].get("content-type", "")


def rule_missing_content_type(response):
    """CTV-001: The response has no Content-Type header at all. Without
    one, browsers fall back to MIME-sniffing the body to guess a type,
    which can cause a response intended as plain data to be rendered and
    executed as HTML/JS."""
    if not _content_type(response):
        return {
            "rule_id": "CTV-001",
            "rule_name": "Missing Content-Type Header",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{response['url']} returned no Content-Type header. "
                f"Browsers will MIME-sniff the body to guess a type, which "
                f"can lead to unintended rendering/execution of the response."
            ),
        }
    return None


def rule_missing_nosniff(response):
    """CTV-002: The response lacks 'X-Content-Type-Options: nosniff'. This
    header instructs browsers to strictly honor the declared Content-Type
    instead of sniffing the body — its absence is a prerequisite for many
    MIME-confusion/XSS attacks."""
    headers = response["headers_lower"]
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        return {
            "rule_id": "CTV-002",
            "rule_name": "Missing X-Content-Type-Options: nosniff",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} does not send "
                f"'X-Content-Type-Options: nosniff'. Without it, some "
                f"browsers may MIME-sniff the response body regardless of "
                f"the declared Content-Type."
            ),
        }
    return None


def rule_html_type_missing_charset(response):
    """CTV-003: An HTML/XHTML/SVG response declares no charset in its
    Content-Type. Without an explicit charset, the browser may fall back
    to sniffing the encoding from the document, which has historically
    enabled charset-based XSS bypasses (e.g. UTF-7 sniffing attacks)."""
    ct = _content_type(response).lower()
    if any(ct.startswith(t) for t in DANGEROUS_RENDERABLE_TYPES) and "charset=" not in ct:
        return {
            "rule_id": "CTV-003",
            "rule_name": "Renderable Content-Type Missing Explicit Charset",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} has Content-Type '{ct}' with no "
                f"explicit charset. Missing charset declarations have "
                f"historically enabled charset-sniffing-based XSS bypasses."
            ),
        }
    return None


def rule_json_served_as_renderable_type(response):
    """CTV-004: A response whose body starts with '{' or '[' (looks like
    JSON) is served with a renderable Content-Type such as text/html
    instead of application/json. If user-controlled data appears in that
    body, the browser may render/execute it as HTML/script instead of
    treating it as inert data."""
    ct = _content_type(response).lower()
    body_prefix = (response.get("body_prefix") or "").strip()
    looks_like_json = body_prefix[:1] in ("{", "[")
    if looks_like_json and any(ct.startswith(t) for t in DANGEROUS_RENDERABLE_TYPES):
        return {
            "rule_id": "CTV-004",
            "rule_name": "JSON-Looking Body Served With Renderable Content-Type",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{response['url']} returns a body that looks like JSON "
                f"but declares Content-Type '{ct}'. If any part of the "
                f"body reflects user input, browsers may render/execute it "
                f"instead of treating it as inert JSON data."
            ),
        }
    return None


def rule_multiple_content_type_values(response):
    """CTV-005: More than one Content-Type value was present in the raw
    response headers. Ambiguous/duplicate Content-Type headers have been
    used historically to bypass security filters and proxies that only
    inspect the first or last value, while the browser picks a different
    one (a request/response-smuggling-adjacent parser-confusion issue)."""
    raw_headers = response.get("headers", {})
    count = 0
    for k in raw_headers.keys():
        if k.lower() == "content-type":
            count += 1
    combined = _content_type(response)
    if count > 1 or "," in combined.split(";")[0]:
        return {
            "rule_id": "CTV-005",
            "rule_name": "Multiple/Ambiguous Content-Type Values",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} appears to send more than one "
                f"Content-Type value ('{combined}'). Parser-confusion "
                f"between the browser, proxies, and security filters can "
                f"result from ambiguous header values."
            ),
        }
    return None


def rule_octet_stream_without_disposition(response):
    """CTV-006: A generic/binary Content-Type (application/octet-stream)
    is returned without a Content-Disposition header. Combined with
    certain legacy browser MIME-sniffing behavior, a response with no
    strong type hint and no forced-download disposition can still be
    sniffed and rendered as HTML in some contexts."""
    ct = _content_type(response).lower()
    headers = response["headers_lower"]
    if ct.startswith("application/octet-stream") and "content-disposition" not in headers:
        return {
            "rule_id": "CTV-006",
            "rule_name": "octet-stream Response Without Content-Disposition",
            "severity": SEVERITY_LOW,
            "description": (
                f"{response['url']} serves Content-Type: "
                f"application/octet-stream with no Content-Disposition "
                f"header. Consider explicitly forcing a download "
                f"('attachment') for binary content to reduce ambiguity."
            ),
        }
    return None


ALL_RULES = [
    rule_missing_content_type,
    rule_missing_nosniff,
    rule_html_type_missing_charset,
    rule_json_served_as_renderable_type,
    rule_multiple_content_type_values,
    rule_octet_stream_without_disposition,
]
