"""
Automated Web Security Header Scanner
Scans a website you own or are authorized to test for common HTTP security headers
and basic CORS configuration signals. This is a defensive, non-invasive checker.
"""
import argparse
import json
from datetime import datetime
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce cross-site scripting and content injection risks.",
    "Strict-Transport-Security": "Tells browsers to use HTTPS for future connections.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (usually set to nosniff).",
    "X-Frame-Options": "Helps reduce clickjacking risk.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Restricts access to browser features such as camera and microphone.",
}


def validate_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please provide a website URL.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid URL. Use a valid http:// or https:// URL.")
    return raw_url


def scan_website(url: str, timeout: int = 10) -> dict:
    """Make one ordinary GET request and inspect the response headers."""
    url = validate_url(url)
    result = {
        "url": url,
        "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "status_code": None,
        "final_url": None,
        "https": urlparse(url).scheme == "https",
        "headers": {},
        "cors": {},
        "findings": [],
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "AutomatedWebScanner/1.0 (authorized defensive check)"},
        )
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        response_headers = response.headers

        if urlparse(response.url).scheme != "https":
            result["findings"].append({
                "severity": "High",
                "title": "Final page is not using HTTPS",
                "details": "The final URL uses HTTP. HTTPS helps protect data in transit."
            })

        for header, explanation in SECURITY_HEADERS.items():
            value = response_headers.get(header)
            present = value is not None
            result["headers"][header] = {"present": present, "value": value}
            if not present:
                result["findings"].append({
                    "severity": "Medium",
                    "title": f"Missing security header: {header}",
                    "details": explanation
                })

        allow_origin = response_headers.get("Access-Control-Allow-Origin")
        allow_credentials = response_headers.get("Access-Control-Allow-Credentials", "").lower()
        result["cors"] = {
            "access_control_allow_origin": allow_origin,
            "access_control_allow_credentials": allow_credentials or None,
        }

        if allow_origin == "*" and allow_credentials == "true":
            result["findings"].append({
                "severity": "High",
                "title": "Potentially risky CORS header combination",
                "details": "The response advertises wildcard origin and credentials. Browsers generally reject this combination for credentialed requests, but review the CORS policy and avoid overly broad access."
            })
        elif allow_origin == "*":
            result["findings"].append({
                "severity": "Low",
                "title": "Wildcard CORS origin",
                "details": "Any origin may be allowed to read eligible responses. Confirm this is intentional and that the endpoint contains no sensitive data."
            })

        if response.status_code >= 400:
            result["findings"].append({
                "severity": "Info",
                "title": f"HTTP response status: {response.status_code}",
                "details": "The server returned an HTTP error status. This is not by itself proof of a security vulnerability."
            })

    except requests.RequestException as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "Info",
            "title": "Scan could not be completed",
            "details": "Check the URL, network connection, TLS configuration, or timeout. No vulnerability conclusion can be drawn."
        })

    return result


def print_report(report: dict) -> None:
    print("\n" + "=" * 64)
    print("          AUTOMATED WEB SECURITY SCANNER REPORT")
    print("=" * 64)
    print(f"URL:        {report['url']}")
    print(f"Final URL:  {report.get('final_url') or 'Not available'}")
    print(f"Scanned at: {report['scanned_at']}")
    print(f"HTTP code:  {report.get('status_code') or 'Not available'}")
    print("\nSECURITY HEADERS")
    print("-" * 64)
    if report["headers"]:
        for name, info in report["headers"].items():
            state = "PRESENT" if info["present"] else "MISSING"
            print(f"{name}: {state}" + (f" — {info['value']}" if info["value"] else ""))
    else:
        print("No header data available.")
    print("\nFINDINGS")
    print("-" * 64)
    if report["findings"]:
        for index, finding in enumerate(report["findings"], start=1):
            print(f"{index}. [{finding['severity']}] {finding['title']}")
            print(f"   {finding['details']}")
    else:
        print("No findings from these basic checks. This does not guarantee the site is secure.")
    if report["error"]:
        print(f"\nRequest error: {report['error']}")
    print("\nNote: This tool performs basic checks only; it is not a full penetration test.")
    print("=" * 64)


def main():
    parser = argparse.ArgumentParser(
        description="Check HTTP security headers and basic CORS signals on an authorized website."
    )
    parser.add_argument("url", help="Website URL you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", default="scan_report.json", help="JSON report path (default: scan_report.json)")
    args = parser.parse_args()

    try:
        report = scan_website(args.url, timeout=max(1, min(args.timeout, 60)))
    except ValueError as exc:
        parser.error(str(exc))
    print_report(report)
    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)
    print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
