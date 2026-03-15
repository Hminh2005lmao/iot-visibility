from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"

INV_FILE = DATA_DIR / "inventory.json"
INV_LABELED_FILE = DATA_DIR / "inventory_labeled.json"
FINDINGS_FILE = DATA_DIR / "findings.json"
POLICY_FILE = DOCS_DIR / "policy.json"
OUT_FILE = DATA_DIR / "devices_report.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_inventory() -> list[dict]:
    # Prefer labeled inventory when available because it adds device class hints.
    if INV_LABELED_FILE.exists():
        return load_json(INV_LABELED_FILE, [])
    return load_json(INV_FILE, [])


def grade_for_score(score: int, thresholds: list[dict]) -> str:
    for item in thresholds:
        if score <= int(item["max_score"]):
            return str(item["grade"])
    return "F"


def to_points(base_points: int, multiplier: float) -> int:
    """Scale points and keep deterministic integer values for reporting."""
    return int(round(base_points * multiplier))


def issue_multiplier(issue_type: str, issue_items: list[dict], issue_tuning: dict) -> tuple[float, str]:
    if issue_type != "default_login_like":
        return 1.0, ""

    cfg = issue_tuning.get("default_login_like", {})
    has_password_input = False
    has_keyword_only = False
    for item in issue_items:
        evidence = item.get("evidence", {})
        matched = ""
        if isinstance(evidence, dict):
            matched = str(evidence.get("matched", "")).lower()
        if matched == "password_input":
            has_password_input = True
        elif matched.startswith("keyword:"):
            has_keyword_only = True

    if has_password_input:
        return float(cfg.get("password_input_match", 1.0)), "password field observed"
    if has_keyword_only:
        return float(cfg.get("keyword_match_only", 0.6)), "keyword-only login hint"
    return 1.0, "generic login heuristic"


def is_iot_device(device_type: str, open_ports: set[int], vendor_guess: str) -> bool:
    iot_types = {"likely_iot_or_router", "likely_camera", "likely_printer"}
    if device_type in iot_types:
        return True

    # Port-only fallback when classification is unknown.
    if open_ports & {80, 443, 8080, 8443, 554, 1900}:
        return True

    vg = (vendor_guess or "").lower()
    iot_vendor_keywords = [
        "hikvision",
        "dahua",
        "tp-link",
        "tplink",
        "ubiquiti",
        "xiaomi",
        "axis",
        "foscam",
        "netgear",
        "d-link",
        "lg",
        "samsung",
        "sony",
        "huawei",
        "zte",
    ]
    return any(k in vg for k in iot_vendor_keywords)


def friendly_type(device_type: str) -> str:
    mapping = {
        "likely_iot_or_router": "iot_or_router",
        "likely_camera": "camera",
        "likely_printer": "printer",
        "likely_pc": "pc",
        "likely_phone_or_laptop": "phone_or_laptop",
        "unknown": "unknown",
    }
    return mapping.get(device_type, "unknown")


def build_report(inventory: list[dict], findings: list[dict], policy: dict) -> dict:
    """Create explainable, policy-based risk scoring report for all devices."""

    if not policy:
        raise FileNotFoundError(f"Missing scoring policy: {POLICY_FILE}")

    rules = policy.get("rules", {})
    tuning = policy.get("tuning", {})

    issue_weights = rules.get("issue_weights", {})
    port_weights = rules.get("port_weights", {})
    type_base_weights = rules.get("device_type_base_weights", {})

    confidence_multipliers = tuning.get("confidence_multipliers", {"high": 1.0, "medium": 0.7, "low": 0.4})
    endpoint_port_multipliers = tuning.get("endpoint_port_multipliers", {})
    issue_tuning = tuning.get("issue_multipliers", {})
    low_signal_cap = tuning.get("low_signal_cap", {"enabled": True, "max_score": 8})

    thresholds = policy.get("grade_thresholds", [])
    secure_threshold = int(policy.get("secure_threshold_max_score", 24))
    hard_fail_cfg = policy.get("hard_fail_conditions", {})

    findings_by_ip: dict[str, list[dict]] = defaultdict(list)
    for item in findings:
        ip = item.get("ip")
        if ip:
            findings_by_ip[ip].append(item)

    device_reports: list[dict] = []
    for dev in inventory:
        ip = dev.get("ip")
        if not ip:
            continue

        open_ports = set(dev.get("open_tcp_ports", dev.get("open_ports", [])) or [])
        device_class_guess = dev.get("device_class_guess", "unknown")
        confidence = dev.get("device_class_confidence", "medium")
        vendor_guess = dev.get("vendor_guess", "")
        device_findings = findings_by_ip.get(ip, [])

        score = 0
        breakdown = []
        risky_port_hit = False

        # Base type risk is reduced for lower-confidence classification to avoid over-scoring weak signals.
        base_raw = int(type_base_weights.get(device_class_guess, type_base_weights.get("unknown", 0)))
        conf_mult = float(confidence_multipliers.get(confidence, 1.0))
        base_points = to_points(base_raw, conf_mult)
        if base_points:
            score += base_points
            breakdown.append({
                "rule_id": f"type:{device_class_guess}",
                "points": base_points,
                "reason": f"Base risk for type '{friendly_type(device_class_guess)}' scaled by confidence '{confidence}' (x{conf_mult:.2f})",
                "source": "classification",
            })

        # Score each issue type once per device; tune severity by evidence quality when needed.
        issue_items_by_type: dict[str, list[dict]] = defaultdict(list)
        for item in device_findings:
            issue = item.get("issue_type")
            if issue:
                issue_items_by_type[issue].append(item)

        for issue_type, items in issue_items_by_type.items():
            base_issue_points = int(issue_weights.get(issue_type, 0))
            if not base_issue_points:
                continue

            mult, why_mult = issue_multiplier(issue_type, items, issue_tuning)
            issue_points = to_points(base_issue_points, mult)
            if not issue_points:
                continue

            score += issue_points
            reason = f"Observed issue '{issue_type}' ({len(items)} time(s))"
            if mult != 1.0:
                reason += f"; adjusted by evidence quality {why_mult} (x{mult:.2f})"
            breakdown.append({
                "rule_id": f"issue:{issue_type}",
                "points": issue_points,
                "reason": reason,
                "source": "findings",
            })

        # Port risk can be tuned by endpoint class to reduce false positives on non-IoT endpoints.
        class_port_multipliers = endpoint_port_multipliers.get(device_class_guess, {})
        for p in sorted(open_ports):
            base_port_points = int(port_weights.get(str(p), 0))
            if not base_port_points:
                continue

            risky_port_hit = True
            port_mult = float(class_port_multipliers.get(str(p), 1.0))
            port_points = to_points(base_port_points, port_mult)
            if not port_points:
                continue

            score += port_points
            reason = f"Risky service port {p} is exposed"
            if port_mult != 1.0:
                reason += f"; class-adjusted (x{port_mult:.2f})"
            breakdown.append({
                "rule_id": f"port:{p}",
                "points": port_points,
                "reason": reason,
                "source": "network",
            })

        raw_score = max(0, min(100, score))
        score = raw_score

        cap_enabled = bool(low_signal_cap.get("enabled", True))
        cap_max = int(low_signal_cap.get("max_score", 8))
        if cap_enabled and confidence == "low" and not device_findings and not risky_port_hit and score > cap_max:
            delta = cap_max - score
            score = cap_max
            breakdown.append({
                "rule_id": "tuning:low_signal_cap",
                "points": delta,
                "reason": f"Low-confidence classification without findings or risky ports; capped at {cap_max}",
                "source": "tuning",
            })

        score = max(0, min(100, score))

        issue_types_seen = set(issue_items_by_type.keys())
        hard_fail_rules_applied: list[str] = []
        force_insecure = False
        if bool(hard_fail_cfg.get("enabled", False)):
            for rule in hard_fail_cfg.get("rules", []):
                rule_id = str(rule.get("rule_id", "unnamed"))
                issue_types = [str(x) for x in rule.get("issue_types", []) if str(x)]
                matched = sorted(issue_types_seen.intersection(issue_types))
                if not matched:
                    continue

                min_score = int(rule.get("min_score", secure_threshold + 1))
                if score < min_score:
                    delta = min_score - score
                    score = min_score
                    reason = str(rule.get("reason", "High-risk condition triggered score floor"))
                    breakdown.append(
                        {
                            "rule_id": f"hard_fail:{rule_id}",
                            "points": delta,
                            "reason": (
                                f"{reason}; enforced minimum score {min_score} because "
                                f"issue(s) {', '.join(matched)} were detected"
                            ),
                            "source": "policy_guardrail",
                        }
                    )
                if bool(rule.get("force_insecure", True)):
                    force_insecure = True
                hard_fail_rules_applied.append(rule_id)

        score = max(0, min(100, score))
        grade = grade_for_score(score, thresholds)
        secure = score <= secure_threshold
        if force_insecure:
            secure = False

        why_this_score = [
            f"{b['points']:+d} {b['reason']}" for b in sorted(breakdown, key=lambda x: x["points"], reverse=True)
        ]
        if not why_this_score:
            why_this_score = ["+0 No risky signals matched policy rules"]

        report_item = {
            "ip": ip,
            "mac": dev.get("mac", ""),
            "vendor_guess": vendor_guess,
            "open_tcp_ports": sorted(open_ports),
            "is_iot": is_iot_device(device_class_guess, open_ports, vendor_guess),
            "device_type": friendly_type(device_class_guess),
            "device_type_raw": device_class_guess,
            "device_type_reason": dev.get("class_reason", ""),
            "device_type_confidence": confidence,
            "device_type_signals": dev.get("class_signals", []),
            "risk_score": score,
            "risk_score_raw": raw_score,
            "risk_grade": grade,
            "is_secure": secure,
            "hard_fail_triggered": bool(hard_fail_rules_applied),
            "hard_fail_rules": hard_fail_rules_applied,
            "why_this_score": why_this_score,
            "score_breakdown": breakdown,
            "issues": device_findings,
        }
        device_reports.append(report_item)

    device_reports.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "generated_at_utc": now_iso(),
        "policy_version": policy.get("version", "unknown"),
        "secure_threshold_max_score": secure_threshold,
        "device_count": len(device_reports),
        "devices": device_reports,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Score devices using policy-based passive risk rules.")
    parser.add_argument("--inventory", type=Path, default=INV_LABELED_FILE, help="Input labeled inventory JSON path")
    parser.add_argument("--findings", type=Path, default=FINDINGS_FILE, help="Input findings JSON path")
    parser.add_argument("--policy", type=Path, default=POLICY_FILE, help="Input policy JSON path")
    parser.add_argument("--output", type=Path, default=OUT_FILE, help="Output scored report JSON path")
    return parser.parse_args()


def main():
    args = parse_args()
    inventory_path: Path = args.inventory
    findings_path: Path = args.findings
    policy_path: Path = args.policy
    output_path: Path = args.output

    # Preserve previous behavior: if no explicit inventory path is given and labeled file is missing,
    # fall back to raw inventory.
    if inventory_path == INV_LABELED_FILE and not inventory_path.exists():
        inventory = load_inventory()
    else:
        inventory = load_json(inventory_path, [])

    findings = load_json(findings_path, [])
    policy = load_json(policy_path, {})
    report = build_report(inventory, findings, policy)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Wrote scored device report to {output_path}")
    print(f"[+] Devices scored: {len(report.get('devices', []))}")


if __name__ == "__main__":
    main()
