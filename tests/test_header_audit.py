from unittest.mock import patch
from header_audit import audit_target


@patch("header_audit.check_tls", return_value=None)
@patch("header_audit.fetch_headers")
def test_audit_target_full_hardened_headers(mock_fetch, _mock_tls):
    mock_fetch.return_value = (
        200,
        {
            "Server": "Apache",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
    )

    report = audit_target("http://127.0.0")
    assert report["posture_score"] == "100/100"
    assert report["grade"] == "A"
    assert report["missing_security_headers"] == []
    assert report["version_disclosures"] == {}


@patch("header_audit.check_tls", return_value=None)
@patch("header_audit.fetch_headers")
def test_audit_target_detects_missing_headers_and_version_leak(mock_fetch, _mock_tls):
    mock_fetch.return_value = (
        200,
        {
            "Server": "Apache/2.4.57 (Debian)",
            "X-Powered-By": "PHP/8.2.10",
        },
    )

    report = audit_target("http://127.0.0")
    assert report["posture_score"] == "0/100"
    assert report["grade"] == "F"
    assert len(report["missing_security_headers"]) == 6
    assert "Server" in report["version_disclosures"]
    assert "X-Powered-By" in report["version_disclosures"]
