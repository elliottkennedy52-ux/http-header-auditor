#!/usr/bin/env python3
"""
HTTP Security Header & Server Banner Posture Auditor
Inspects target URLs for missing HTTP security headers, server/framework version
disclosure, and TLS certificate metadata, generating a graded security report.
"""

import argparse
import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' over HTTPS.",
    },
    "Content-Security-Policy": {
        "weight": 25,
        "remediation": "Define a restrictive 'Content-Security-Policy' to mitigate XSS and data injection.",
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "remediation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    },
    "X-Frame-Options": {
        "weight": 15,
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    "Referrer-Policy": {
        "weight": 15,
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
    },
    "Permissions-Policy": {
        "weight": 10,
        "remediation": "Set 'Permissions-Policy' (e.g., 'geolocation=(), microphone=(), camera=()').",
    },
}

LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


def fetch_headers(url: str, timeout: int = 10) -> tuple[int, dict[str, str]]:
    """Send an HTTP HEAD/GET request and return status code and normalized headers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": "SecurityHeaderAuditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers.items())
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers.items())


def check_tls(hostname: str, port: int = 443) -> dict | None:
    """Retrieve TLS protocol version and certificate expiration for HTTPS targets."""
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, port), timeout=5) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert()
            return {
                "tls_version": ssock.version(),
                "cipher": ssock.cipher(),
                "expires": cert.get("notAfter", "Unknown"),
            }
    except (OSError, ssl.SSLError):
        return None


def audit_target(url: str) -> dict:
    """Evaluate response headers, calculate posture score, and list remediations."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    status_code, headers = fetch_headers(url)
    lower_headers = {k.lower(): v for k, v in headers.items()}

    present = {}
    missing = []
    score = 0

    for header, meta in SECURITY_HEADERS.items():
        val = lower_headers.get(header.lower())
        if val:
            present[header] = val
            score += meta["weight"]
        else:
            missing.append({"header": header, "remediation": meta["remediation"]})

    disclosures = {
        h: lower_headers[h.lower()]
        for h in LEAKY_HEADERS
        if h.lower() in lower_headers and any(ch.isdigit() for ch in lower_headers[h.lower()])
    }

    grade = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 60 else
        "D" if score >= 40 else "F"
    )

    tls_info = check_tls(parsed.hostname, parsed.port or 443) if parsed.scheme == "https" else None

    return {
        "target": url,
        "audited_at": datetime.now().isoformat(timespec="seconds"),
        "http_status": status_code,
        "posture_score": f"{score}/100",
        "grade": grade,
        "tls": tls_info,
        "present_security_headers": present,
        "missing_security_headers": missing,
        "version_disclosures": disclosures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HTTP Security Header & Server Banner Posture Auditor"
    )
    parser.add_argument("url", help="Target URL (e.g., http://127.0.0)")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    args = parser.parse_args()

    report = audit_target(args.url)

    print(f"[*] Target: {report['target']} (HTTP {report['http_status']})")
    print(f"[*] Security Header Score: {report['posture_score']} (Grade: {report['grade']})")
    print("-" * 60)

    if report["present_security_headers"]:
        print("[+] PRESENT HEADERS:")
        for k, v in report["present_security_headers"].items():
            print(f"    - {k}: {v}")

    if report["missing_security_headers"]:
        print("\n[!] MISSING SECURITY HEADERS & REMEDIATIONS:")
        for item in report["missing_security_headers"]:
            print(f"    - {item['header']}: {item['remediation']}")

    if report["version_disclosures"]:
        print("\n[!] INFORMATION DISCLOSURE DETECTED:")
        for k, v in report["version_disclosures"].items():
            print(f"    - {k}: {v} (Suppress version banners in web server config)")

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report saved to {args.output}")


if __name__ == "__main__":
    main()
