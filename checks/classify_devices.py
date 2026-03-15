from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
INV_FILE = DATA_DIR / "inventory.json"
FINDINGS_FILE = DATA_DIR / "findings.json"
OUT_FILE = DATA_DIR / "inventory_labeled.json"

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 10000, 10443}
PC_PORTS = {135, 139, 445, 3389}
PRINTER_PORTS = {631, 9100}

CAMERA_VENDOR_WORDS = {"hikvision", "dahua", "axis", "foscam", "reolink", "ezviz"}
PRINTER_VENDOR_WORDS = {"hp", "epson", "brother", "canon", "xerox", "lexmark"}
ROUTER_IOT_VENDOR_WORDS = {
    "tp-link",
    "tplink",
    "ubiquiti",
    "netgear",
    "d-link",
    "mikrotik",
    "zyxel",
    "zte",
    "huawei",
    "xiaomi",
    "tenda",
    "asus",
    "lg",
    "samsung",
    "sony",
}
PC_VENDOR_WORDS = {"dell", "lenovo", "intel", "microsoft", "vmware"}

CAMERA_BANNER_WORDS = {"camera", "nvr", "dvr", "ipc"}
PRINTER_BANNER_WORDS = {"printer", "ipp", "laserjet", "cups"}
ROUTER_BANNER_WORDS = {"router", "gateway", "modem", "wifi", "f660", "openwrt", "admin"}
PC_BANNER_WORDS = {"microsoft-iis", "smb", "windows"}


def is_locally_administered(mac: str) -> bool:
    """True if MAC looks randomized (locally administered)."""
    if not mac or ":" not in mac:
        return False
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)


def has_any_keyword(text: str, keywords: set[str]) -> bool:
    return any(k in text for k in keywords)


def extract_finding_hints(findings: list[dict]) -> dict[str, str]:
    hints_by_ip: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        ip = f.get("ip")
        if not ip:
            continue

        parts: list[str] = [str(f.get("issue_type", ""))]
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            for key in ("title", "server", "url", "matched", "detail", "note"):
                val = evidence.get(key)
                if isinstance(val, str):
                    parts.append(val)
        elif isinstance(evidence, str):
            parts.append(evidence)

        merged = " ".join(parts).strip()
        if merged:
            hints_by_ip[ip].append(merged)

    return {ip: " | ".join(parts).lower() for ip, parts in hints_by_ip.items()}


def confidence_label(score: int, ambiguous: bool) -> str:
    if ambiguous:
        return "low"
    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def classify(dev: dict, hints_text: str) -> tuple[str, str, str, list[str]]:
    ports = set(dev.get("open_tcp_ports", []) or dev.get("open_ports", []) or [])
    mac = dev.get("mac", "")
    vendor_text = (dev.get("vendor_guess", "") or "").lower()
    laa = is_locally_administered(mac)

    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, list[str]] = defaultdict(list)
    signals: list[str] = []

    def add_signal(device_type: str, points: int, reason: str):
        scores[device_type] += points
        reasons[device_type].append(reason)
        signals.append(f"{device_type}: +{points} {reason}")

    # Port-based signals
    if ports & PC_PORTS:
        add_signal("likely_pc", 6, "Windows/SMB/RDP style ports exposed")
    if ports & PRINTER_PORTS:
        add_signal("likely_printer", 7, "Printer service ports exposed (9100/631)")
    if 554 in ports:
        add_signal("likely_camera", 7, "RTSP port 554 exposed")
    if ports & WEB_PORTS:
        add_signal("likely_iot_or_router", 4, "Web management style ports exposed")
    if 1900 in ports:
        add_signal("likely_iot_or_router", 3, "SSDP/UPnP port exposed")
    if laa and not ports:
        add_signal("likely_phone_or_laptop", 4, "Randomized MAC + no common ports")

    # Vendor-based signals
    if has_any_keyword(vendor_text, CAMERA_VENDOR_WORDS):
        add_signal("likely_camera", 4, "Vendor signature resembles camera/NVR vendor")
    if has_any_keyword(vendor_text, PRINTER_VENDOR_WORDS):
        add_signal("likely_printer", 5, "Vendor signature resembles printer vendor")
    if has_any_keyword(vendor_text, ROUTER_IOT_VENDOR_WORDS):
        add_signal("likely_iot_or_router", 4, "Vendor signature resembles consumer IoT/network vendor")
    if has_any_keyword(vendor_text, PC_VENDOR_WORDS):
        add_signal("likely_pc", 3, "Vendor signature resembles endpoint/PC vendor")

    # HTTP banner/title finding hints
    if hints_text:
        if has_any_keyword(hints_text, CAMERA_BANNER_WORDS):
            add_signal("likely_camera", 5, "Web title/server hints indicate camera or recorder")
        if has_any_keyword(hints_text, PRINTER_BANNER_WORDS):
            add_signal("likely_printer", 5, "Web title/server hints indicate printer services")
        if has_any_keyword(hints_text, ROUTER_BANNER_WORDS):
            add_signal("likely_iot_or_router", 4, "Web title/server hints indicate router/admin interface")
        if has_any_keyword(hints_text, PC_BANNER_WORDS):
            add_signal("likely_pc", 4, "Banner hints indicate desktop/server stack")

    if not scores:
        return (
            "unknown",
            "Insufficient signals from ports, vendor, and passive web banners",
            "low",
            [],
        )

    top_score = max(scores.values())
    winners = [k for k, v in scores.items() if v == top_score]
    ambiguous = len(winners) > 1

    if ambiguous:
        winner_names = ", ".join(sorted(winners))
        return (
            "unknown",
            f"Ambiguous passive signals across {winner_names}",
            "low",
            signals[:12],
        )

    winner = winners[0]
    confidence = confidence_label(top_score, ambiguous=False)
    top_reasons = reasons.get(winner, [])[:2]
    reason = "; ".join(top_reasons) if top_reasons else "Heuristic match from passive signals"
    return winner, reason, confidence, signals[:12]


def run_classification(inventory: list[dict], findings: list[dict]) -> list[dict]:
    """Classify all inventory devices using passive hints from findings."""
    hints_by_ip = extract_finding_hints(findings)

    labeled = [dict(item) for item in inventory]
    for d in labeled:
        ip = d.get("ip", "")
        hints_text = hints_by_ip.get(ip, "")
        guess, reason, confidence, signals = classify(d, hints_text)
        d["device_class_guess"] = guess
        d["class_reason"] = reason
        d["device_class_confidence"] = confidence
        d["class_signals"] = signals
        d["mac_randomized_likely"] = is_locally_administered(d.get("mac", ""))

    return labeled


def parse_args():
    parser = argparse.ArgumentParser(description="Classify devices from inventory using passive signals.")
    parser.add_argument("--inventory", type=Path, default=INV_FILE, help="Input inventory JSON path")
    parser.add_argument("--findings", type=Path, default=FINDINGS_FILE, help="Input findings JSON path")
    parser.add_argument("--output", type=Path, default=OUT_FILE, help="Output labeled inventory JSON path")
    return parser.parse_args()


def main():
    args = parse_args()
    inventory_path: Path = args.inventory
    findings_path: Path = args.findings
    output_path: Path = args.output

    if not inventory_path.exists():
        raise FileNotFoundError(f"Missing {inventory_path}. Run scanner/discover.py first.")

    inv = json.loads(inventory_path.read_text(encoding="utf-8"))
    findings = []
    if findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))

    labeled = run_classification(inv, findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(labeled, indent=2), encoding="utf-8")
    print(f"[+] Wrote labeled inventory to {output_path}")


if __name__ == "__main__":
    main()
