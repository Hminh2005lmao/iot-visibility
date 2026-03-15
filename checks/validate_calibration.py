from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from classify_devices import run_classification
from score_devices import build_report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "lab_baseline"
DEFAULT_POLICY = PROJECT_ROOT / "docs" / "policy.json"
DEFAULT_OUT_DIR = PROJECT_ROOT / "tests" / "output"

CONF_LEVEL = {"low": 1, "medium": 2, "high": 3}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args():
    parser = argparse.ArgumentParser(description="Validate classifier/scorer behavior on fixed lab fixtures.")
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR, help="Fixture directory")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="Policy JSON path")
    parser.add_argument("--write-output", action="store_true", help="Write labeled/report outputs under tests/output")
    return parser.parse_args()


def check_min_confidence(actual: str, expected_min: str) -> bool:
    return CONF_LEVEL.get(actual, 0) >= CONF_LEVEL.get(expected_min, 0)


def main():
    args = parse_args()
    fixture_dir: Path = args.fixture_dir
    policy_path: Path = args.policy

    inventory_path = fixture_dir / "inventory.json"
    findings_path = fixture_dir / "findings.json"
    expected_path = fixture_dir / "expected.json"

    for required in (inventory_path, findings_path, expected_path, policy_path):
        if not required.exists():
            raise FileNotFoundError(f"Missing required file: {required}")

    inventory = load_json(inventory_path)
    findings = load_json(findings_path)
    expected = load_json(expected_path)
    policy = load_json(policy_path)

    labeled = run_classification(inventory, findings)
    report = build_report(labeled, findings, policy)

    if args.write_output:
        out_dir = DEFAULT_OUT_DIR / fixture_dir.name
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "inventory_labeled.json").write_text(json.dumps(labeled, indent=2), encoding="utf-8")
        (out_dir / "devices_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Wrote validation outputs to {out_dir}")

    by_ip = {d.get("ip"): d for d in report.get("devices", [])}
    failures: list[str] = []

    for item in expected.get("devices", []):
        ip = item.get("ip")
        actual = by_ip.get(ip)
        if not actual:
            failures.append(f"{ip}: device missing from generated report")
            continue

        expected_type = item.get("expected_type")
        if expected_type and actual.get("device_type") != expected_type:
            failures.append(
                f"{ip}: expected type '{expected_type}', got '{actual.get('device_type')}'"
            )

        if "expected_is_iot" in item and bool(actual.get("is_iot")) != bool(item.get("expected_is_iot")):
            failures.append(
                f"{ip}: expected is_iot={item.get('expected_is_iot')}, got {actual.get('is_iot')}"
            )

        min_score = item.get("min_score")
        max_score = item.get("max_score")
        score = int(actual.get("risk_score", 0))
        if min_score is not None and score < int(min_score):
            failures.append(f"{ip}: expected score >= {min_score}, got {score}")
        if max_score is not None and score > int(max_score):
            failures.append(f"{ip}: expected score <= {max_score}, got {score}")

        min_conf = item.get("min_confidence")
        actual_conf = str(actual.get("device_type_confidence", "low"))
        if min_conf and not check_min_confidence(actual_conf, str(min_conf)):
            failures.append(
                f"{ip}: expected confidence >= {min_conf}, got {actual_conf}"
            )

    summary = expected.get("summary", {})
    actual_iot = sum(1 for d in report.get("devices", []) if d.get("is_iot"))
    actual_devices = len(report.get("devices", []))

    min_iot = summary.get("min_iot")
    max_iot = summary.get("max_iot")
    expected_devices = summary.get("expected_device_count")

    if expected_devices is not None and actual_devices != int(expected_devices):
        failures.append(
            f"summary: expected device_count={expected_devices}, got {actual_devices}"
        )
    if min_iot is not None and actual_iot < int(min_iot):
        failures.append(f"summary: expected iot_count >= {min_iot}, got {actual_iot}")
    if max_iot is not None and actual_iot > int(max_iot):
        failures.append(f"summary: expected iot_count <= {max_iot}, got {actual_iot}")

    if failures:
        print("[!] Validation FAILED")
        for f in failures:
            print(" -", f)
        return 1

    print("[+] Validation PASSED")
    print(f"[+] Devices checked: {actual_devices}")
    print(f"[+] IoT detected: {actual_iot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
