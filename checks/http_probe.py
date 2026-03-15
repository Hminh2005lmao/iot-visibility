# checks/http_probe.py
from __future__ import annotations

from pathlib import Path
import json
import time
import requests
import urllib3
from datetime import datetime, timezone

# Silence HTTPS warnings when verify=False
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(category=InsecureRequestWarning)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
INV_FILE = DATA_DIR / "inventory.json"
OUT_FILE = DATA_DIR / "findings.json"

TIMEOUT = 3  # seconds


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def extract_title(html: str) -> str:
    low = html.lower()
    si = low.find("<title>")
    if si == -1:
        return ""
    ei = low.find("</title>", si)
    if ei == -1:
        return ""
    return html[si + 7:ei].strip()[:120]

def safe_get(url: str, verify: bool):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=True)
        content_type = r.headers.get("Content-Type", "").lower()
        title = extract_title(r.text) if "text/html" in content_type else ""
        return {
            "ok": True,
            "final_url": r.url,
            "status": r.status_code,
            "server": r.headers.get("Server", ""),
            "title": title,
            "headers": dict(r.headers)
        }
    except requests.exceptions.SSLError as e:
        return {"ok": False, "error": "ssl_error", "detail": str(e)[:200]}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": "request_error", "detail": str(e)[:200]}

def main():
    if not INV_FILE.exists():
        raise FileNotFoundError(f"Missing {INV_FILE}. Run scanner/discover.py first.")

    inventory = json.loads(INV_FILE.read_text(encoding="utf-8"))
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    findings = []
    start = time.time()

    for dev in inventory:
        ip = dev.get("ip")
        open_tcp = set(dev.get("open_tcp_ports", dev.get("open_ports", [])))

        http_open = 80 in open_tcp
        https_open = 443 in open_tcp

        # Probe HTTP lightly (only if port 80 open)
        http_result = None
        if http_open:
            http_result = safe_get(f"http://{ip}/", verify=True)

        # Probe HTTPS lightly (only if port 443 open)
        https_result = None
        if https_open:
            # First try strict verify=True, then fall back to verify=False for self-signed
            https_result = safe_get(f"https://{ip}/", verify=True)
            if not https_result.get("ok") and https_result.get("error") == "ssl_error":
                # self-signed or invalid cert
                https_result2 = safe_get(f"https://{ip}/", verify=False)
                findings.append({
                    "device_id": ip,
                    "ip": ip,
                    "issue_type": "self_signed_tls",
                    "severity": "L",
                    "evidence": {
                        "url": f"https://{ip}/",
                        "detail": https_result.get("detail", "")
                    },
                    "timestamp": now_iso()
                })
                https_result = https_result2

        # Issue: HTTP-only management surface
        if http_open and not https_open:
            ev = {
                "url": f"http://{ip}/",
                "status": http_result.get("status") if http_result else None,
                "server": (http_result or {}).get("server", ""),
                "title": (http_result or {}).get("title", "")
            }
            findings.append({
                "device_id": ip,
                "ip": ip,
                "issue_type": "http_only",
                "severity": "M",
                "evidence": ev,
                "timestamp": now_iso()
            })

        # Optional info: HTTPS available (useful in dashboard later)
        if https_open and https_result and https_result.get("ok"):
            findings.append({
                "device_id": ip,
                "ip": ip,
                "issue_type": "https_available",
                "severity": "I",
                "evidence": {
                    "url": https_result.get("final_url", f"https://{ip}/"),
                    "status": https_result.get("status"),
                    "server": https_result.get("server", ""),
                    "title": https_result.get("title", "")
                },
                "timestamp": now_iso()
            })

    OUT_FILE.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    elapsed = time.time() - start
    print(f"[+] Wrote {len(findings)} findings to {OUT_FILE}")
    print(f"[+] Runtime: {elapsed:.1f}s")

if __name__ == "__main__":
    main()
