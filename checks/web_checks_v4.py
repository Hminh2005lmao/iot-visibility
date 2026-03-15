# checks/web_checks_v4.py
from __future__ import annotations

import argparse
import html
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
INV_FILE = DATA_DIR / "inventory.json"
OUT_FILE = DATA_DIR / "findings.json"

HTTP_PORTS = [80, 8080, 8000, 8888, 10000]
HTTPS_PORTS = [443, 8443, 10443]

PROFILE_LEVEL = {"safe": 1, "audit": 2, "research": 3}
CHECK_PROFILES = {
    "safe": {
        "timeout": 3,
        "paths": ["/", "/admin", "/login", "/index.html", "/setup", "/manager", "/cgi-bin/"],
        "sensitive_paths": ["/admin", "/setup", "/manager", "/cgi-bin/"],
    },
    "audit": {
        "timeout": 4,
        "paths": ["/", "/admin", "/login", "/index.html", "/setup", "/manager", "/cgi-bin/", "/api", "/config", "/status"],
        "sensitive_paths": ["/admin", "/setup", "/manager", "/cgi-bin/", "/api", "/config"],
    },
    "research": {
        "timeout": 5,
        "paths": [
            "/",
            "/admin",
            "/login",
            "/index.html",
            "/setup",
            "/manager",
            "/cgi-bin/",
            "/api",
            "/config",
            "/status",
            "/system",
            "/debug",
            "/backup",
        ],
        "sensitive_paths": ["/admin", "/setup", "/manager", "/cgi-bin/", "/api", "/config", "/system", "/debug", "/backup"],
    },
}

PROTOCOL_EXPOSURE_RULES = [
    {
        "min_profile": "audit",
        "port": 23,
        "issue_type": "telnet_exposed",
        "severity": "H",
        "note": "Telnet service is exposed; credentials and sessions are unencrypted.",
    },
    {
        "min_profile": "audit",
        "port": 21,
        "issue_type": "ftp_plaintext_exposed",
        "severity": "M",
        "note": "FTP service is exposed; plaintext authentication may be used.",
    },
    {
        "min_profile": "audit",
        "port": 445,
        "issue_type": "smb_exposed",
        "severity": "M",
        "note": "SMB service is exposed; restrict to trusted segments only.",
    },
    {
        "min_profile": "research",
        "port": 554,
        "issue_type": "rtsp_exposed",
        "severity": "M",
        "note": "RTSP stream service is exposed; verify authentication and segmentation.",
    },
    {
        "min_profile": "research",
        "port": 1900,
        "issue_type": "upnp_exposed",
        "severity": "L",
        "note": "UPnP/SSDP exposure can increase attack surface.",
    },
]

LOGIN_KEYWORDS = [
    "login",
    "sign in",
    "admin",
    "password",
    "username",
    "user name",
]

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
]

UA = "Mozilla/5.0 (IoT-Visibility-Student-Project)"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run non-intrusive web and management checks.")
    parser.add_argument("--inventory", type=Path, default=INV_FILE, help="Input inventory JSON path.")
    parser.add_argument("--output", type=Path, default=OUT_FILE, help="Output findings JSON path.")
    parser.add_argument(
        "--check-profile",
        choices=["safe", "audit", "research"],
        default="safe",
        help="Check profile controls path depth and protocol exposure checks.",
    )
    return parser.parse_args()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def extract_title(html_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, flags=re.I | re.S)
    if not match:
        return ""
    title = match.group(1).strip()
    title = re.sub(r"\s+", " ", title)
    return html.unescape(title)[:120]


def looks_like_login(html_text: str) -> tuple[bool, str]:
    low = html_text.lower()
    if re.search(r'type\s*=\s*["\']password["\']', low):
        return True, "password_input"
    for keyword in LOGIN_KEYWORDS:
        if keyword in low:
            return True, f"keyword:{keyword}"
    return False, ""


def safe_get(url: str, verify: bool, timeout: int):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
            headers={"User-Agent": UA},
        )
        content_type = response.headers.get("Content-Type", "").lower()
        body = response.text if "text/html" in content_type else ""
        return {
            "ok": True,
            "status": response.status_code,
            "final_url": response.url,
            "server": response.headers.get("Server", ""),
            "title": extract_title(body) if body else "",
            "headers": {k.lower(): v for k, v in response.headers.items()},
            "body": body,
        }
    except requests.exceptions.SSLError as err:
        return {"ok": False, "error": "ssl_error", "detail": str(err)[:200]}
    except requests.exceptions.RequestException as err:
        return {"ok": False, "error": "request_error", "detail": str(err)[:200]}


def is_no_auth_endpoint(path: str, res: dict, sensitive_paths: list[str]) -> tuple[bool, str]:
    """Heuristic: sensitive endpoint returns success without obvious auth challenge."""
    if path not in sensitive_paths:
        return False, ""

    status = int(res.get("status", 0) or 0)
    if status not in {200, 204}:
        return False, ""

    final_url = str(res.get("final_url", "")).lower()
    if any(x in final_url for x in ["login", "signin", "auth"]):
        return False, ""

    body = str(res.get("body", "") or "")
    if body:
        is_login, _ = looks_like_login(body)
        if is_login:
            return False, ""
        if "404" in body[:300].lower() and "not found" in body[:300].lower():
            return False, ""

    return True, "sensitive_endpoint_returned_success_without_auth_prompt"


def add_finding(findings, ip, issue_type, severity, evidence):
    findings.append(
        {
            "device_id": ip,
            "ip": ip,
            "issue_type": issue_type,
            "severity": severity,
            "evidence": evidence,
            "timestamp": now_iso(),
        }
    )


def url_for(ip: str, scheme: str, port: int, path: str = "/") -> str:
    if scheme == "http" and port == 80:
        return f"http://{ip}{path}"
    if scheme == "https" and port == 443:
        return f"https://{ip}{path}"
    return f"{scheme}://{ip}:{port}{path}"


def add_protocol_exposure_findings(findings: list[dict], ip: str, open_ports: set[int], check_profile: str):
    active_level = PROFILE_LEVEL[check_profile]
    for rule in PROTOCOL_EXPOSURE_RULES:
        if active_level < PROFILE_LEVEL[rule["min_profile"]]:
            continue
        if rule["port"] not in open_ports:
            continue
        add_finding(
            findings,
            ip,
            rule["issue_type"],
            rule["severity"],
            {
                "port": rule["port"],
                "note": rule["note"],
                "check_profile": check_profile,
            },
        )


def main():
    args = parse_args()
    profile = CHECK_PROFILES[args.check_profile]
    timeout = int(profile["timeout"])
    paths = list(profile["paths"])
    sensitive_paths = list(profile["sensitive_paths"])

    inventory_path: Path = args.inventory
    output_path: Path = args.output

    if not inventory_path.exists():
        raise FileNotFoundError(f"Missing {inventory_path}. Run scanner/discover.py first.")

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    findings = []
    start = time.time()

    for dev in inventory:
        ip = dev.get("ip")
        open_ports = set(dev.get("open_tcp_ports", dev.get("open_ports", [])) or [])
        login_recorded = False
        no_auth_recorded = False

        http_open = [p for p in HTTP_PORTS if p in open_ports]
        https_open = [p for p in HTTPS_PORTS if p in open_ports]

        add_protocol_exposure_findings(findings, ip, open_ports, args.check_profile)

        if not http_open and not https_open:
            continue

        if http_open and not https_open:
            add_finding(
                findings,
                ip,
                "http_only",
                "M",
                {
                    "ports": http_open,
                    "note": "HTTP exposed without HTTPS alternative",
                    "check_profile": args.check_profile,
                },
            )

        for port in http_open:
            for path in paths:
                url = url_for(ip, "http", port, path)
                res = safe_get(url, verify=True, timeout=timeout)
                if not res.get("ok"):
                    continue

                body = res.get("body", "")
                if body:
                    is_login, why = looks_like_login(body)
                    if is_login and not login_recorded:
                        add_finding(
                            findings,
                            ip,
                            "default_login_like",
                            "H",
                            {
                                "url": res.get("final_url", url),
                                "status": res.get("status"),
                                "server": res.get("server", ""),
                                "title": res.get("title", ""),
                                "matched": why,
                                "check_profile": args.check_profile,
                            },
                        )
                        login_recorded = True

                if not no_auth_recorded:
                    no_auth, marker = is_no_auth_endpoint(path, res, sensitive_paths)
                    if no_auth:
                        add_finding(
                            findings,
                            ip,
                            "no_auth_endpoint",
                            "H",
                            {
                                "url": res.get("final_url", url),
                                "path": path,
                                "status": res.get("status"),
                                "server": res.get("server", ""),
                                "title": res.get("title", ""),
                                "matched": marker,
                                "check_profile": args.check_profile,
                            },
                        )
                        no_auth_recorded = True

        for port in https_open:
            base = url_for(ip, "https", port, "/")
            res = safe_get(base, verify=True, timeout=timeout)

            if not res.get("ok") and res.get("error") == "ssl_error":
                add_finding(
                    findings,
                    ip,
                    "self_signed_tls",
                    "L",
                    {"url": base, "detail": res.get("detail", ""), "check_profile": args.check_profile},
                )
                res = safe_get(base, verify=False, timeout=timeout)

            if res.get("ok"):
                add_finding(
                    findings,
                    ip,
                    "https_available",
                    "I",
                    {
                        "url": res.get("final_url", base),
                        "status": res.get("status"),
                        "server": res.get("server", ""),
                        "title": res.get("title", ""),
                        "check_profile": args.check_profile,
                    },
                )

                hdrs = res.get("headers", {})
                missing = [h for h in SEC_HEADERS if h not in hdrs]
                if missing:
                    add_finding(
                        findings,
                        ip,
                        "headers_missing",
                        "L",
                        {"url": res.get("final_url", base), "missing": missing, "check_profile": args.check_profile},
                    )

                body = res.get("body", "")
                if body:
                    is_login, why = looks_like_login(body)
                    if is_login and not login_recorded:
                        add_finding(
                            findings,
                            ip,
                            "default_login_like",
                            "H",
                            {
                                "url": res.get("final_url", base),
                                "status": res.get("status"),
                                "server": res.get("server", ""),
                                "title": res.get("title", ""),
                                "matched": why,
                                "check_profile": args.check_profile,
                            },
                        )
                        login_recorded = True

            if not no_auth_recorded:
                for path in sensitive_paths:
                    url = url_for(ip, "https", port, path)
                    endpoint_res = safe_get(url, verify=False, timeout=timeout)
                    if not endpoint_res.get("ok"):
                        continue
                    no_auth, marker = is_no_auth_endpoint(path, endpoint_res, sensitive_paths)
                    if no_auth:
                        add_finding(
                            findings,
                            ip,
                            "no_auth_endpoint",
                            "H",
                            {
                                "url": endpoint_res.get("final_url", url),
                                "path": path,
                                "status": endpoint_res.get("status"),
                                "server": endpoint_res.get("server", ""),
                                "title": endpoint_res.get("title", ""),
                                "matched": marker,
                                "check_profile": args.check_profile,
                            },
                        )
                        no_auth_recorded = True
                        break

    output_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    elapsed = time.time() - start
    print(f"[+] Check profile: {args.check_profile}")
    print(f"[+] Wrote {len(findings)} findings to {output_path}")
    print(f"[+] Runtime: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
