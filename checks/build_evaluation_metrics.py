from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from classify_devices import run_classification
from score_devices import build_report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"
TEST_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "lab_baseline"

REPORT_FILE = DATA_DIR / "devices_report.json"
INVENTORY_FILE = DATA_DIR / "inventory.json"
FINDINGS_FILE = DATA_DIR / "findings.json"
SCAN_META_FILE = DATA_DIR / "scan_meta.json"
POLICY_FILE = DOCS_DIR / "policy.json"
OUT_FILE = DATA_DIR / "evaluation_metrics.json"

HTTP_PORTS = {80, 8080, 8000, 8888, 10000}
HTTPS_PORTS = {443, 8443, 10443}
CONF_LEVEL = {"low": 1, "medium": 2, "high": 3}


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_fixture(policy: dict) -> dict:
    inv_path = TEST_FIXTURE / "inventory.json"
    fin_path = TEST_FIXTURE / "findings.json"
    exp_path = TEST_FIXTURE / "expected.json"
    if not inv_path.exists() or not fin_path.exists() or not exp_path.exists():
        return {"available": False}

    inventory = load_json(inv_path, [])
    findings = load_json(fin_path, [])
    expected = load_json(exp_path, {})

    labeled = run_classification(inventory, findings)
    report = build_report(labeled, findings, policy)
    by_ip = {d.get("ip"): d for d in report.get("devices", [])}

    checks = 0
    pass_type = 0
    pass_iot = 0
    pass_score_range = 0
    pass_conf = 0

    for item in expected.get("devices", []):
        ip = item.get("ip")
        dev = by_ip.get(ip)
        if not dev:
            continue
        checks += 1

        if dev.get("device_type") == item.get("expected_type"):
            pass_type += 1
        if bool(dev.get("is_iot")) == bool(item.get("expected_is_iot")):
            pass_iot += 1

        score = int(dev.get("risk_score", 0))
        min_score = int(item.get("min_score", 0))
        max_score = int(item.get("max_score", 100))
        if min_score <= score <= max_score:
            pass_score_range += 1

        min_conf = str(item.get("min_confidence", "low"))
        actual_conf = str(dev.get("device_type_confidence", "low"))
        if CONF_LEVEL.get(actual_conf, 0) >= CONF_LEVEL.get(min_conf, 0):
            pass_conf += 1

    def pct(v: int) -> float | None:
        return round(v * 100.0 / checks, 2) if checks else None

    return {
        "available": True,
        "fixture_name": TEST_FIXTURE.name,
        "devices_checked": checks,
        "type_precision_percent": pct(pass_type),
        "iot_flag_accuracy_percent": pct(pass_iot),
        "score_band_accuracy_percent": pct(pass_score_range),
        "confidence_target_pass_percent": pct(pass_conf),
    }


def main():
    report = load_json(REPORT_FILE, {})
    inventory = load_json(INVENTORY_FILE, [])
    findings = load_json(FINDINGS_FILE, [])
    scan_meta = load_json(SCAN_META_FILE, {})
    policy = load_json(POLICY_FILE, {})

    devices = report.get("devices", [])
    total = len(devices)
    http_exposed = 0
    https_exposed = 0
    for d in devices:
        ports = set(d.get("open_tcp_ports", []))
        if ports & HTTP_PORTS:
            http_exposed += 1
        if ports & HTTPS_PORTS:
            https_exposed += 1

    issue_counts = {}
    for f in findings:
        issue = f.get("issue_type", "unknown")
        issue_counts[issue] = issue_counts.get(issue, 0) + 1

    metrics = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "based_on_scan_finished_utc": scan_meta.get("scan_finished_utc"),
        "summary": {
            "target_cidr": scan_meta.get("cidr"),
            "target_host_count": scan_meta.get("target_host_count"),
            "discovered_hosts": len(inventory),
            "discovery_rate_percent": scan_meta.get("discovery_rate_percent"),
            "http_exposed_count": http_exposed,
            "http_exposure_rate_percent": round(http_exposed * 100.0 / total, 2) if total else 0.0,
            "https_exposed_count": https_exposed,
            "https_exposure_rate_percent": round(https_exposed * 100.0 / total, 2) if total else 0.0,
            "devices_with_findings": sum(1 for d in devices if d.get("issues")),
            "devices_with_findings_rate_percent": round(
                sum(1 for d in devices if d.get("issues")) * 100.0 / total, 2
            )
            if total
            else 0.0,
        },
        "issue_counts": issue_counts,
        "fixture_validation": evaluate_fixture(policy),
    }

    OUT_FILE.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"[+] Wrote evaluation metrics to {OUT_FILE}")


if __name__ == "__main__":
    main()
