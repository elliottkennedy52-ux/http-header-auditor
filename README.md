# HTTP Security Header & Server Banner Posture Auditor

A zero-dependency Python CLI tool that audits web applications for missing HTTP security headers, server/framework version banner leakage, and TLS posture—providing a weighted security score (`0–100`) and actionable remediation steps.

## Checks Performed
- **Security Header Coverage:** Evaluates `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Information Disclosure Detection:** Flags `Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-Generator` headers leaking exact software versions.
- **TLS Posture Inspection:** Verifies active TLS protocol version, cipher suite, and certificate expiration for HTTPS targets.
- **JSON Reporting:** Exports structured findings for remediation tracking and compliance documentation.

## Usage

### Audit a Local Lab or Web App
```bash
python3 header_audit.py http://localhost:4280/login.php
```

### Export Findings to JSON
```bash
python3 header_audit.py https://example.com -o header_report.json
```
