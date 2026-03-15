from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

REPORT_FILE = DATA_DIR / "devices_report.json"
SCAN_META_FILE = DATA_DIR / "scan_meta.json"
STATE_FILE = DATA_DIR / "asset_state.json"
CHANGES_FILE = DATA_DIR / "asset_changes.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    return mac.strip().lower().replace("-", ":")


def identity_key(device: dict) -> str:
    mac = normalize_mac(str(device.get("mac", "")))
    if mac:
        return f"mac:{mac}"
    ip = str(device.get("ip", "")).strip()
    return f"ip:{ip}"


def summarize_device(device: dict) -> dict:
    return {
        "identity_key": identity_key(device),
        "ip": device.get("ip", ""),
        "mac": normalize_mac(str(device.get("mac", ""))),
        "vendor_guess": device.get("vendor_guess", ""),
        "device_type": device.get("device_type", "unknown"),
        "risk_score": int(device.get("risk_score", 0)),
        "risk_grade": device.get("risk_grade", "N/A"),
        "is_secure": bool(device.get("is_secure", False)),
        "is_iot": bool(device.get("is_iot", False)),
        "open_tcp_ports": sorted(device.get("open_tcp_ports", [])),
    }


def build_change_summary(prev: dict, curr: dict) -> dict | None:
    changes = []
    if prev.get("ip") != curr.get("ip"):
        changes.append(
            {
                "field": "ip",
                "from": prev.get("ip"),
                "to": curr.get("ip"),
            }
        )
    if prev.get("device_type") != curr.get("device_type"):
        changes.append(
            {
                "field": "device_type",
                "from": prev.get("device_type"),
                "to": curr.get("device_type"),
            }
        )
    if prev.get("risk_grade") != curr.get("risk_grade"):
        changes.append(
            {
                "field": "risk_grade",
                "from": prev.get("risk_grade"),
                "to": curr.get("risk_grade"),
            }
        )
    if prev.get("is_secure") != curr.get("is_secure"):
        changes.append(
            {
                "field": "is_secure",
                "from": prev.get("is_secure"),
                "to": curr.get("is_secure"),
            }
        )
    if prev.get("open_tcp_ports", []) != curr.get("open_tcp_ports", []):
        changes.append(
            {
                "field": "open_tcp_ports",
                "from": prev.get("open_tcp_ports", []),
                "to": curr.get("open_tcp_ports", []),
            }
        )

    prev_score = int(prev.get("risk_score", 0))
    curr_score = int(curr.get("risk_score", 0))
    delta = curr_score - prev_score
    if abs(delta) >= 3:
        changes.append(
            {
                "field": "risk_score",
                "from": prev_score,
                "to": curr_score,
                "delta": delta,
            }
        )

    if not changes:
        return None

    out = summarize_device(curr)
    out["changes"] = changes
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build persistent asset history and drift summary.")
    parser.add_argument("--report", type=Path, default=REPORT_FILE, help="Input devices_report.json")
    parser.add_argument("--scan-meta", type=Path, default=SCAN_META_FILE, help="Input scan_meta.json")
    parser.add_argument("--state", type=Path, default=STATE_FILE, help="Output persistent asset_state.json")
    parser.add_argument("--changes", type=Path, default=CHANGES_FILE, help="Output run delta asset_changes.json")
    return parser.parse_args()


def main():
    args = parse_args()
    report = load_json(args.report, {})
    scan_meta = load_json(args.scan_meta, {})
    prev_state = load_json(args.state, {"assets": []})

    current_devices = report.get("devices", [])
    prev_assets = prev_state.get("assets", [])
    prev_by_key = {str(item.get("identity_key", "")): item for item in prev_assets if item.get("identity_key")}

    generated_at = now_iso()
    current_keys = set()
    next_assets = []
    new_devices = []
    changed_devices = []

    for device in current_devices:
        current = summarize_device(device)
        key = current["identity_key"]
        current_keys.add(key)

        prev = prev_by_key.get(key)
        if prev is None:
            first_seen = generated_at
            seen_count = 1
            new_devices.append(current)
        else:
            first_seen = str(prev.get("first_seen_utc", generated_at))
            seen_count = int(prev.get("seen_count", 0)) + 1
            change = build_change_summary(prev, current)
            if change:
                changed_devices.append(change)

        asset_entry = dict(current)
        asset_entry["first_seen_utc"] = first_seen
        asset_entry["last_seen_utc"] = generated_at
        asset_entry["seen_count"] = seen_count
        asset_entry["status"] = "active"
        asset_entry["missing_since_utc"] = None
        next_assets.append(asset_entry)

    disappeared_devices = []
    for key, prev in prev_by_key.items():
        if key in current_keys:
            continue
        missing = {
            "identity_key": key,
            "ip": prev.get("ip", ""),
            "mac": prev.get("mac", ""),
            "vendor_guess": prev.get("vendor_guess", ""),
            "device_type": prev.get("device_type", "unknown"),
            "risk_score": int(prev.get("risk_score", 0)),
            "risk_grade": prev.get("risk_grade", "N/A"),
            "is_secure": bool(prev.get("is_secure", False)),
            "is_iot": bool(prev.get("is_iot", False)),
            "open_tcp_ports": sorted(prev.get("open_tcp_ports", [])),
            "first_seen_utc": prev.get("first_seen_utc"),
            "last_seen_utc": prev.get("last_seen_utc"),
            "seen_count": int(prev.get("seen_count", 0)),
            "status": "missing",
            "missing_since_utc": generated_at,
        }
        disappeared_devices.append(missing)
        next_assets.append(missing)

    next_assets.sort(key=lambda item: (item.get("status") != "active", item.get("identity_key", "")))
    state_doc = {
        "updated_at_utc": generated_at,
        "active_count": sum(1 for item in next_assets if item.get("status") == "active"),
        "missing_count": sum(1 for item in next_assets if item.get("status") == "missing"),
        "assets": next_assets,
    }
    args.state.write_text(json.dumps(state_doc, indent=2), encoding="utf-8")

    changes_doc = {
        "generated_at_utc": generated_at,
        "scan_finished_utc": scan_meta.get("scan_finished_utc"),
        "scan_mode": scan_meta.get("scan_mode"),
        "target_cidr": scan_meta.get("cidr"),
        "current_device_count": len(current_devices),
        "new_count": len(new_devices),
        "changed_count": len(changed_devices),
        "disappeared_count": len(disappeared_devices),
        "new_devices": new_devices,
        "changed_devices": changed_devices,
        "disappeared_devices": disappeared_devices,
    }
    args.changes.write_text(json.dumps(changes_doc, indent=2), encoding="utf-8")

    print(f"[+] Wrote asset state to {args.state}")
    print(
        "[+] Drift summary:",
        f"new={changes_doc['new_count']}",
        f"changed={changes_doc['changed_count']}",
        f"disappeared={changes_doc['disappeared_count']}",
    )
    print(f"[+] Wrote asset changes to {args.changes}")


if __name__ == "__main__":
    main()
