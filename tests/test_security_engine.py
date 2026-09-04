"""Tests for the Content-Type Validation Checker's Security Engine and rules.

Rule-level tests use synthetic response dicts (no network calls). The
engine-level tests spin up a REAL local HTTP server (Python's http.server,
on an ephemeral localhost port) with controlled headers/body and perform a
REAL HTTP request against it via the actual ScanEngine/requests code path —
genuine end-to-end HTTP testing without touching any third-party site.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_missing_content_type,
    rule_missing_nosniff,
    rule_html_type_missing_charset,
    rule_json_served_as_renderable_type,
    rule_multiple_content_type_values,
    rule_octet_stream_without_disposition,
)


def resp(url="https://example.com/", headers=None, body_prefix=""):
    headers = headers or {}
    return {
        "url": url, "status_code": 200, "headers": headers,
        "headers_lower": {k.lower(): v for k, v in headers.items()},
        "body_prefix": body_prefix,
    }


def test_missing_content_type_flagged():
    result = rule_missing_content_type(resp(headers={}))
    assert result is not None
    assert result["rule_id"] == "CTV-001"


def test_content_type_present_not_flagged():
    result = rule_missing_content_type(resp(headers={"Content-Type": "text/html"}))
    assert result is None


def test_missing_nosniff_flagged():
    result = rule_missing_nosniff(resp(headers={"Content-Type": "text/html"}))
    assert result is not None
    assert result["rule_id"] == "CTV-002"


def test_nosniff_present_not_flagged():
    result = rule_missing_nosniff(resp(headers={"X-Content-Type-Options": "nosniff"}))
    assert result is None


def test_html_missing_charset_flagged():
    result = rule_html_type_missing_charset(resp(headers={"Content-Type": "text/html"}))
    assert result is not None
    assert result["rule_id"] == "CTV-003"


def test_html_with_charset_not_flagged():
    result = rule_html_type_missing_charset(resp(headers={"Content-Type": "text/html; charset=utf-8"}))
    assert result is None


def test_json_body_served_as_html_flagged():
    result = rule_json_served_as_renderable_type(resp(headers={"Content-Type": "text/html"}, body_prefix='{"key": "value"}'))
    assert result is not None
    assert result["rule_id"] == "CTV-004"


def test_json_body_served_as_json_not_flagged():
    result = rule_json_served_as_renderable_type(resp(headers={"Content-Type": "application/json"}, body_prefix='{"key": "value"}'))
    assert result is None


def test_multiple_content_type_values_flagged():
    result = rule_multiple_content_type_values(resp(headers={"Content-Type": "text/html, text/plain"}))
    assert result is not None
    assert result["rule_id"] == "CTV-005"


def test_single_content_type_not_flagged():
    result = rule_multiple_content_type_values(resp(headers={"Content-Type": "text/html; charset=utf-8"}))
    assert result is None


def test_octet_stream_without_disposition_flagged():
    result = rule_octet_stream_without_disposition(resp(headers={"Content-Type": "application/octet-stream"}))
    assert result is not None
    assert result["rule_id"] == "CTV-006"


def test_octet_stream_with_disposition_not_flagged():
    result = rule_octet_stream_without_disposition(resp(headers={
        "Content-Type": "application/octet-stream",
        "Content-Disposition": "attachment; filename=data.bin",
    }))
    assert result is None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        # No Content-Type header at all, and body looks like JSON reflected
        # without a proper type -- a realistic multi-finding scenario.
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        pass  # silence test server logging


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real request, real response, real
    findings — against a local server we control (not a third party)."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "CTV-001" in rule_ids  # no Content-Type header at all
        assert "CTV-002" in rule_ids  # no nosniff either
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "CTV-000" for f in result["findings"])
