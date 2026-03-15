from __future__ import annotations

import json
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
INV_FILE = DATA_DIR / "inventory.json"
OUT_FILE = DATA_DIR / "findings.json"


def extract_title(html: str) -> str:
    low = html.lower()
    start, end = low.find("<title>"), low.find("</title>")
    if start == -1 or end == -1:
        return ""
    return html[start + 7 : end].strip()[:120]


def main() -> None:
    if not INV_FILE.exists():
        raise FileNotFoundError(f"Missing {INV_FILE}. Run discovery first.")

    with INV_FILE.open("r", encoding="utf-8") as f:
        inventory = json.load(f)

    findings = []
    for device in inventory:
        ip = device.get("ip")
        if not ip:
            continue

        open_ports = set(device.get("open_tcp_ports", device.get("open_ports", [])) or [])
        if 80 not in open_ports:
            continue

        url = f"http://{ip}/"
        try:
            response = requests.get(url, timeout=3)
        except requests.RequestException:
            continue

        findings.append(
            {
                "device_id": ip,
                "ip": ip,
                "issue_type": "http_only",
                "evidence": {
                    "url": url,
                    "title": extract_title(response.text),
                    "header": response.headers.get("Server", ""),
                },
                "severity": "M",
            }
        )

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(f"Wrote {len(findings)} HTTP findings to {OUT_FILE}")


if __name__ == "__main__":
    main()
