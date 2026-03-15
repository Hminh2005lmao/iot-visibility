# api/app.py
from flask import Flask, jsonify, render_template, send_file, Response, request
from pathlib import Path
import hmac
import json
import os
from collections import Counter, defaultdict
import csv
import io
import ipaddress
import subprocess
import threading
from datetime import datetime, timezone

app = Flask(__name__, template_folder="templates")

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPORT_FILE = DATA / "devices_report.json"
EVAL_FILE = DATA / "evaluation_metrics.json"
ASSET_CHANGES_FILE = DATA / "asset_changes.json"
THREAT_INTEL_FILE = DATA / "threat_intel.json"
RUNS_INDEX_FILE = DATA / "runs" / "index.json"
SCAN_LOG_FILE = DATA / "scan_job.log"
SCAN_STATUS_FILE = DATA / "scan_status.json"
RUN_PIPELINE_FILE = ROOT / "run_pipeline.py"
PYTHON_EXE = ROOT / ".venv" / "Scripts" / "python.exe"
DISCOVERY_PROFILES = {"standard", "balanced", "aggressive"}
SCAN_MODES = {"active", "hybrid", "passive"}
CHECK_PROFILES = {"safe", "audit", "research"}
ADMIN_API_KEY = os.environ.get("IOT_ADMIN_API_KEY", "").strip()
PUBLIC_MODE = os.environ.get("IOT_PUBLIC_MODE", "0").strip().lower() in {"1", "true", "yes"}
FORCE_ADMIN_KEY = os.environ.get("IOT_REQUIRE_ADMIN_KEY", "0").strip().lower() in {"1", "true", "yes"} or PUBLIC_MODE

SCORE = {"H": 3, "M": 2, "L": 1, "I": 0}

RECOMMEND = {
    "http_only": "Enable HTTPS if supported; otherwise restrict access to the admin interface (LAN only) and avoid exposing management pages.",
    "default_login_like": "Ensure strong, unique admin credentials; disable default accounts; restrict admin UI to trusted hosts.",
    "no_auth_endpoint": "Sensitive admin/setup endpoint appears reachable without authentication. Require auth for all management paths and disable anonymous admin access.",
    "telnet_exposed": "Disable Telnet and use SSH or HTTPS-based management only; restrict management plane access by network policy.",
    "ftp_plaintext_exposed": "Disable FTP where possible; prefer SFTP/FTPS and limit management services to trusted hosts.",
    "smb_exposed": "Restrict SMB to required segments only; disable SMBv1 and enforce strong authentication controls.",
    "rtsp_exposed": "Protect RTSP streams with authentication and isolate camera/NVR traffic from user endpoints.",
    "upnp_exposed": "Disable unnecessary UPnP and limit discovery protocols to local trusted segments.",
    "self_signed_tls": "Replace with a trusted certificate if possible, or pin/trust the device certificate in controlled environments. Avoid remote admin over untrusted networks.",
    "headers_missing": "Harden the web interface by adding common security headers (HSTS/CSP/X-Frame-Options) where feasible.",
    "https_available": "HTTPS is available. Prefer HTTPS for management access."
}

STANDARDS_URLS = {
    "etsi_en_303_645": "https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf",
    "nistir_8259a": "https://csrc.nist.gov/pubs/ir/8259/a/final",
    "rfc_8520_mud": "https://www.rfc-editor.org/rfc/rfc8520",
    "nist_sp_1800_15": "https://csrc.nist.gov/pubs/sp/1800/15/final",
}

STANDARDS_MAP = {
    "default_login_like": [
        {"code": "ETSI EN 303 645", "focus": "Authentication and credential hardening", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Logical access to device interfaces", "url": STANDARDS_URLS["nistir_8259a"]},
    ],
    "no_auth_endpoint": [
        {"code": "ETSI EN 303 645", "focus": "Interface access control and attack-surface reduction", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Access control capability for local/network interfaces", "url": STANDARDS_URLS["nistir_8259a"]},
        {"code": "RFC 8520 (MUD)", "focus": "Restrict management-plane reachability", "url": STANDARDS_URLS["rfc_8520_mud"]},
    ],
    "http_only": [
        {"code": "ETSI EN 303 645", "focus": "Secure communication for management access", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Protect data in transit for management operations", "url": STANDARDS_URLS["nistir_8259a"]},
    ],
    "telnet_exposed": [
        {"code": "ETSI EN 303 645", "focus": "Avoid insecure legacy management protocols", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Secure interface access control", "url": STANDARDS_URLS["nistir_8259a"]},
        {"code": "NIST SP 1800-15", "focus": "Segment and restrict IoT management services", "url": STANDARDS_URLS["nist_sp_1800_15"]},
    ],
    "ftp_plaintext_exposed": [
        {"code": "ETSI EN 303 645", "focus": "Secure communication channels", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Protect interface communication", "url": STANDARDS_URLS["nistir_8259a"]},
    ],
    "smb_exposed": [
        {"code": "RFC 8520 (MUD)", "focus": "Least-privilege network policy between devices", "url": STANDARDS_URLS["rfc_8520_mud"]},
        {"code": "NIST SP 1800-15", "focus": "Constrain east-west device traffic", "url": STANDARDS_URLS["nist_sp_1800_15"]},
    ],
    "rtsp_exposed": [
        {"code": "ETSI EN 303 645", "focus": "Secure service exposure and communications", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "RFC 8520 (MUD)", "focus": "Policy-limit camera stream reachability", "url": STANDARDS_URLS["rfc_8520_mud"]},
    ],
    "upnp_exposed": [
        {"code": "ETSI EN 303 645", "focus": "Minimize exposed attack surfaces", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NIST SP 1800-15", "focus": "Reduce unintended service exposure through policy", "url": STANDARDS_URLS["nist_sp_1800_15"]},
    ],
    "self_signed_tls": [
        {"code": "ETSI EN 303 645", "focus": "Secure communications and trust model", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Data protection for network interfaces", "url": STANDARDS_URLS["nistir_8259a"]},
    ],
    "headers_missing": [
        {"code": "ETSI EN 303 645", "focus": "Web/admin interface hardening baseline", "url": STANDARDS_URLS["etsi_en_303_645"]},
        {"code": "NISTIR 8259A", "focus": "Cybersecurity configuration capability", "url": STANDARDS_URLS["nistir_8259a"]},
    ],
    "https_available": [
        {"code": "ETSI EN 303 645", "focus": "Positive signal: encrypted management path exists", "url": STANDARDS_URLS["etsi_en_303_645"]},
    ],
}

SCAN_LOCK = threading.Lock()
SCAN_STATE = {
    "running": False,
    "pid": None,
    "cidr": None,
    "scan_mode": "hybrid",
    "discovery_profile": "balanced",
    "check_profile": "safe",
    "note": "",
    "started_utc": None,
    "finished_utc": None,
    "returncode": None,
    "last_status": "idle",
}
if SCAN_STATUS_FILE.exists():
    try:
        persisted = json.loads(SCAN_STATUS_FILE.read_text(encoding="utf-8"))
        if isinstance(persisted, dict):
            SCAN_STATE.update(persisted)
            # Prevent stale "running" state after restart.
            if SCAN_STATE.get("running"):
                SCAN_STATE["running"] = False
                SCAN_STATE["pid"] = None
                SCAN_STATE["last_status"] = "unknown_after_restart"
    except Exception:
        pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def save_scan_status():
    DATA.mkdir(parents=True, exist_ok=True)
    SCAN_STATUS_FILE.write_text(json.dumps(SCAN_STATE, indent=2), encoding="utf-8")


def scan_snapshot():
    with SCAN_LOCK:
        snap = dict(SCAN_STATE)
    return snap


def read_scan_log_tail(max_lines: int = 40) -> list[str]:
    if not SCAN_LOG_FILE.exists():
        return []
    lines = SCAN_LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def _scan_worker(cidr: str, note: str, discovery_profile: str, scan_mode: str, check_profile: str):
    py = str(PYTHON_EXE if PYTHON_EXE.exists() else "python")
    cmd = [py, str(RUN_PIPELINE_FILE), cidr]
    # run_pipeline.py defines note as positional arg after cidr, so place it before options.
    if note:
        cmd.append(note)
    if scan_mode:
        cmd.extend(["--scan-mode", scan_mode])
    if discovery_profile:
        cmd.extend(["--discovery-profile", discovery_profile])
    if check_profile:
        cmd.extend(["--check-profile", check_profile])

    with SCAN_LOCK:
        SCAN_STATE["running"] = True
        SCAN_STATE["cidr"] = cidr
        SCAN_STATE["scan_mode"] = scan_mode
        SCAN_STATE["discovery_profile"] = discovery_profile
        SCAN_STATE["check_profile"] = check_profile
        SCAN_STATE["note"] = note
        SCAN_STATE["started_utc"] = utc_now()
        SCAN_STATE["finished_utc"] = None
        SCAN_STATE["returncode"] = None
        SCAN_STATE["last_status"] = "running"
        SCAN_STATE["pid"] = None
        save_scan_status()

    DATA.mkdir(parents=True, exist_ok=True)
    with SCAN_LOG_FILE.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT, text=True)
        with SCAN_LOCK:
            SCAN_STATE["pid"] = proc.pid
            save_scan_status()
        rc = proc.wait()

    with SCAN_LOCK:
        SCAN_STATE["running"] = False
        SCAN_STATE["finished_utc"] = utc_now()
        SCAN_STATE["returncode"] = rc
        SCAN_STATE["last_status"] = "success" if rc == 0 else "failed"
        SCAN_STATE["pid"] = None
        save_scan_status()

def load_json(path: Path, default):
    p = path
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def standards_for_issue(issue_type: str) -> list[dict]:
    refs = STANDARDS_MAP.get(str(issue_type), [])
    return [dict(item) for item in refs]


def annotate_standards(devices: list[dict], findings: list[dict]) -> None:
    for finding in findings:
        finding["standards_refs"] = standards_for_issue(finding.get("issue_type", ""))

    for device in devices:
        issues = device.get("issues", [])
        for issue in issues:
            issue["standards_refs"] = standards_for_issue(issue.get("issue_type", ""))


def is_admin_key_required() -> bool:
    return FORCE_ADMIN_KEY or bool(ADMIN_API_KEY)


def get_supplied_api_key() -> str:
    return request.headers.get("X-API-Key", "").strip()


def require_admin_key():
    if not is_admin_key_required():
        return None
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "server_misconfigured_admin_key_missing"}), 503
    supplied_key = get_supplied_api_key()
    if hmac.compare_digest(supplied_key, ADMIN_API_KEY):
        return None
    return jsonify({"ok": False, "error": "unauthorized"}), 401

def build_analytics(devices, issue_counts, sev_counts, grade_counts, asset_changes=None):
    total = len(devices)
    iot_count = sum(1 for d in devices if d.get("is_iot"))
    secure_count = sum(1 for d in devices if d.get("is_secure"))
    avg_score = round(sum(d.get("risk_score", 0) for d in devices) / total, 1) if total else 0.0

    high_risk_count = sum(1 for d in devices if d.get("risk_grade") in {"D", "F"})

    type_counts = Counter(d.get("device_type", "unknown") for d in devices)
    top_risky = [
        {
            "ip": d.get("ip", ""),
            "score": d.get("risk_score", 0),
            "grade": d.get("risk_grade", "N/A"),
            "device_type": d.get("device_type", "unknown"),
            "issues_count": len(d.get("issues", [])),
        }
        for d in devices[:5]
    ]

    asset_changes = asset_changes or {}
    drift = {
        "new_count": int(asset_changes.get("new_count", 0) or 0),
        "changed_count": int(asset_changes.get("changed_count", 0) or 0),
        "disappeared_count": int(asset_changes.get("disappeared_count", 0) or 0),
    }

    return {
        "total_devices": total,
        "iot_count": iot_count,
        "secure_count": secure_count,
        "insecure_count": max(0, total - secure_count),
        "high_risk_count": high_risk_count,
        "avg_score": avg_score,
        "type_counts": dict(type_counts),
        "top_issues": issue_counts.most_common(6),
        "grade_counts": dict(grade_counts),
        "severity_counts": dict(sev_counts),
        "top_risky": top_risky,
        "asset_drift": drift,
    }


def _pdf_escape(text: str) -> str:
    safe = (text or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return safe.encode("latin-1", errors="replace").decode("latin-1")


def _build_simple_pdf(lines: list[str]) -> bytes:
    """Generate a minimal multi-page PDF from plain text lines without external libs."""
    page_height = 842
    top_margin = 60
    line_height = 14
    lines_per_page = 50

    pages = [lines[i : i + lines_per_page] for i in range(0, len(lines), lines_per_page)] or [["No data"]]

    objects: list[str] = []
    # 1: Catalog, 2: Pages
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")

    page_obj_nums = []
    content_obj_nums = []
    next_obj = 3
    for _ in pages:
        page_obj_nums.append(next_obj)
        content_obj_nums.append(next_obj + 1)
        next_obj += 2

    font_obj = next_obj
    kids = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects.append(f"<< /Type /Pages /Count {len(page_obj_nums)} /Kids [{kids}] >>")

    for idx, page_lines in enumerate(pages):
        page_obj = page_obj_nums[idx]
        content_obj = content_obj_nums[idx]
        y_start = page_height - top_margin
        stream_lines = ["BT", "/F1 10 Tf", f"50 {y_start} Td", f"{line_height} TL"]
        for i, line in enumerate(page_lines):
            escaped = _pdf_escape(line)
            if i == 0:
                stream_lines.append(f"({escaped}) Tj")
            else:
                stream_lines.append("T*")
                stream_lines.append(f"({escaped}) Tj")
        stream_lines.append("ET")
        stream = "\n".join(stream_lines)

        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
            f"/Contents {content_obj} 0 R >>"
        )
        objects.append(f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream")

    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = ["%PDF-1.4\n"]
    offsets = [0]
    pos = len(pdf[0].encode("latin-1"))
    for i, obj in enumerate(objects, start=1):
        block = f"{i} 0 obj\n{obj}\nendobj\n"
        offsets.append(pos)
        pdf.append(block)
        pos += len(block.encode("latin-1"))

    xref_pos = pos
    xref = [f"xref\n0 {len(offsets)}\n", "0000000000 65535 f \n"]
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n")
    trailer = (
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    )

    out = "".join(pdf) + "".join(xref) + trailer
    return out.encode("latin-1", errors="replace")


def build_print_lines(devices, findings, summary, analytics) -> list[str]:
    lines = []
    lines.append("IoT Security Command Center - Printable Report")
    lines.append("")
    lines.append(f"Policy version: {summary.get('policy_version')}")
    lines.append(f"Secure threshold: {summary.get('secure_threshold')}")
    lines.append(f"Devices: {analytics.get('total_devices')}")
    lines.append(f"IoT detected: {analytics.get('iot_count')}")
    lines.append(f"Secure devices: {analytics.get('secure_count')}")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")
    lines.append("Top risky devices:")
    for d in devices[:10]:
        lines.append(
            f"- {d.get('ip')}  type={d.get('device_type')}  score={d.get('risk_score')}  "
            f"grade={d.get('risk_grade')}  secure={d.get('is_secure')}"
        )
    lines.append("")
    lines.append("Findings summary:")
    issue_counts = Counter(f.get("issue_type", "unknown") for f in findings)
    for issue, count in issue_counts.most_common():
        lines.append(f"- {issue}: {count}")
    lines.append("")
    lines.append("Per-device short notes:")
    for d in devices:
        why = d.get("why_this_score", [])
        first_reason = why[0] if why else "No score explanation"
        lines.append(f"- {d.get('ip')}: {first_reason}")
    return lines


def build_view():
    report = load_json(REPORT_FILE, {})
    findings = load_json(DATA / "findings.json", [])
    asset_changes = load_asset_changes()

    # Preferred path: use scored report generated by checks/score_devices.py.
    if report and isinstance(report.get("devices"), list):
        devices = report.get("devices", [])
        devices.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        if not findings:
            for d in devices:
                findings.extend(d.get("issues", []))

        annotate_standards(devices, findings)

        issue_counts = Counter(f.get("issue_type", "unknown") for f in findings)
        sev_counts = Counter(f.get("severity", "I") for f in findings)
        grade_counts = Counter(d.get("risk_grade", "N/A") for d in devices)

        summary = {
            "device_count": report.get("device_count", len(devices)),
            "iot_count": sum(1 for d in devices if d.get("is_iot")),
            "secure_count": sum(1 for d in devices if d.get("is_secure")),
            "policy_version": report.get("policy_version", "unknown"),
            "secure_threshold": report.get("secure_threshold_max_score"),
        }
        analytics = build_analytics(devices, issue_counts, sev_counts, grade_counts, asset_changes=asset_changes)
        return devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics

    # Fallback path for old output files.
    inventory = load_json(DATA / "inventory.json", [])

    by_ip = defaultdict(list)
    for f in findings:
        by_ip[f["ip"]].append(f)

    devices = []
    for d in inventory:
        ip = d.get("ip")
        issues = by_ip.get(ip, [])
        score = sum(SCORE.get(x.get("severity","I"), 0) for x in issues)
        devices.append({
            "ip": ip,
            "mac": d.get("mac",""),
            "vendor_guess": d.get("vendor_guess",""),
            "open_tcp_ports": d.get("open_tcp_ports", []),
            "device_type": d.get("fingerprint_hint", "unknown"),
            "is_iot": d.get("fingerprint_hint", "").startswith("web_managed"),
            "risk_score": score,
            "risk_grade": "N/A",
            "is_secure": score <= 2,
            "why_this_score": ["Fallback score from findings severities only"],
            "issues": issues
        })

    devices.sort(key=lambda x: x["risk_score"], reverse=True)
    annotate_standards(devices, findings)

    issue_counts = Counter(f["issue_type"] for f in findings)
    sev_counts = Counter(f.get("severity","I") for f in findings)
    grade_counts = Counter(d.get("risk_grade", "N/A") for d in devices)
    summary = {
        "device_count": len(devices),
        "iot_count": sum(1 for d in devices if d.get("is_iot")),
        "secure_count": sum(1 for d in devices if d.get("is_secure")),
        "policy_version": "fallback",
        "secure_threshold": "n/a",
    }
    analytics = build_analytics(devices, issue_counts, sev_counts, grade_counts, asset_changes=asset_changes)

    return devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics


def load_evaluation_metrics():
    metrics = load_json(EVAL_FILE, {})
    if not metrics:
        return {
            "summary": {
                "target_cidr": None,
                "target_host_count": 0,
                "discovered_hosts": 0,
                "discovery_rate_percent": None,
                "http_exposed_count": 0,
                "http_exposure_rate_percent": 0.0,
                "https_exposed_count": 0,
                "https_exposure_rate_percent": 0.0,
                "devices_with_findings": 0,
                "devices_with_findings_rate_percent": 0.0,
            },
            "issue_counts": {},
            "fixture_validation": {"available": False},
        }
    return metrics


def load_asset_changes():
    changes = load_json(ASSET_CHANGES_FILE, {})
    if not changes:
        return {
            "generated_at_utc": None,
            "new_count": 0,
            "changed_count": 0,
            "disappeared_count": 0,
            "new_devices": [],
            "changed_devices": [],
            "disappeared_devices": [],
        }
    return changes


def load_threat_intel():
    intel = load_json(THREAT_INTEL_FILE, {})
    if not intel:
        return {
            "generated_at_utc": None,
            "source_findings_count": 0,
            "summary": {
                "priority_counts": {},
                "top_priorities": [],
                "issue_priority": [],
            },
            "enriched_findings": [],
        }
    return intel


def infer_check_profile(scan_meta: dict, findings: list[dict]) -> str:
    profile = str(scan_meta.get("check_profile", "")).strip().lower()
    if profile in CHECK_PROFILES:
        return profile
    for finding in findings:
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            candidate = str(evidence.get("check_profile", "")).strip().lower()
            if candidate in CHECK_PROFILES:
                return candidate
    return "unknown"


def load_check_profile_comparison(max_runs: int = 40):
    idx = load_json(RUNS_INDEX_FILE, {"runs": []})
    runs = idx.get("runs", []) if isinstance(idx, dict) else []
    if not runs:
        return {
            "available": False,
            "compared_profiles": [],
            "latest_by_profile": {},
            "recommended_profile": None,
            "recommendation_reason": "No archived runs available for profile comparison.",
            "total_runs_checked": 0,
        }

    latest_by_profile: dict[str, dict] = {}
    checked = 0

    for run in runs[:max_runs]:
        run_dir_raw = run.get("run_dir", "")
        if not run_dir_raw:
            continue
        run_dir = Path(run_dir_raw)
        if not run_dir.exists():
            continue

        scan_meta = load_json(run_dir / "scan_meta.json", {})
        findings = load_json(run_dir / "findings.json", [])
        report = load_json(run_dir / "devices_report.json", {})
        profile = infer_check_profile(scan_meta, findings)
        if profile not in CHECK_PROFILES:
            continue

        checked += 1
        summary = {
            "run_id": run.get("run_id"),
            "created_utc": run.get("created_utc"),
            "scan_mode": scan_meta.get("scan_mode"),
            "discovery_profile": scan_meta.get("discovery_profile"),
            "check_profile": profile,
            "device_count": int(report.get("device_count", len(report.get("devices", [])))),
            "findings_count": len(findings),
            "high_count": sum(1 for f in findings if f.get("severity") == "H"),
            "medium_count": sum(1 for f in findings if f.get("severity") == "M"),
            "low_count": sum(1 for f in findings if f.get("severity") == "L"),
            "issue_type_count": len({f.get("issue_type", "unknown") for f in findings}),
        }

        current = latest_by_profile.get(profile)
        if not current:
            latest_by_profile[profile] = summary
            continue

        if str(summary.get("created_utc", "")) > str(current.get("created_utc", "")):
            latest_by_profile[profile] = summary

    compared_profiles = sorted(latest_by_profile.keys())
    if len(compared_profiles) < 2:
        return {
            "available": True,
            "compared_profiles": compared_profiles,
            "latest_by_profile": latest_by_profile,
            "recommended_profile": compared_profiles[0] if compared_profiles else None,
            "recommendation_reason": "Run at least two different check profiles on a similar subnet to compare impact.",
            "total_runs_checked": checked,
        }

    safe = latest_by_profile.get("safe")
    audit = latest_by_profile.get("audit")
    research = latest_by_profile.get("research")

    recommended = "safe"
    reason = "Safe checks are sufficient based on currently stored run deltas."

    if audit:
        safe_high = int(safe.get("high_count", 0)) if safe else 0
        safe_findings = int(safe.get("findings_count", 0)) if safe else 0
        if int(audit.get("high_count", 0)) > safe_high or int(audit.get("findings_count", 0)) > safe_findings:
            recommended = "audit"
            reason = "Audit profile reveals additional risk signals compared to safe profile."

    if research:
        baseline = audit if audit else safe
        baseline_high = int(baseline.get("high_count", 0)) if baseline else 0
        if int(research.get("high_count", 0)) > baseline_high:
            recommended = "research"
            reason = "Research profile detected additional high-severity issues over lower-depth profiles."

    return {
        "available": True,
        "compared_profiles": compared_profiles,
        "latest_by_profile": latest_by_profile,
        "recommended_profile": recommended,
        "recommendation_reason": reason,
        "total_runs_checked": checked,
    }


def get_default_scan_cidr() -> str:
    eval_metrics = load_evaluation_metrics()
    cidr = eval_metrics.get("summary", {}).get("target_cidr")
    if cidr:
        return str(cidr)
    scan_meta = load_json(DATA / "scan_meta.json", {})
    if scan_meta.get("cidr"):
        return str(scan_meta.get("cidr"))
    return "192.168.1.0/24"


def get_default_discovery_profile() -> str:
    scan_meta = load_json(DATA / "scan_meta.json", {})
    profile = str(scan_meta.get("discovery_profile", "")).strip().lower()
    if profile in DISCOVERY_PROFILES:
        return profile
    current = str(scan_snapshot().get("discovery_profile", "")).strip().lower()
    if current in DISCOVERY_PROFILES:
        return current
    return "balanced"


def get_default_scan_mode() -> str:
    scan_meta = load_json(DATA / "scan_meta.json", {})
    mode = str(scan_meta.get("scan_mode", "")).strip().lower()
    if mode in SCAN_MODES:
        return mode
    current = str(scan_snapshot().get("scan_mode", "")).strip().lower()
    if current in SCAN_MODES:
        return current
    return "hybrid"


def get_default_check_profile() -> str:
    scan_meta = load_json(DATA / "scan_meta.json", {})
    from_meta = str(scan_meta.get("check_profile", "")).strip().lower()
    if from_meta in CHECK_PROFILES:
        return from_meta
    current = str(scan_snapshot().get("check_profile", "")).strip().lower()
    if current in CHECK_PROFILES:
        return current
    return "safe"


@app.route("/")
def landing_home():
    return render_template(
        "home.html",
        default_scan_cidr=get_default_scan_cidr(),
        default_scan_mode=get_default_scan_mode(),
        default_discovery_profile=get_default_discovery_profile(),
        default_check_profile=get_default_check_profile(),
        api_key_required=is_admin_key_required(),
    )


@app.route("/visibility")
def visibility_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    eval_metrics = load_evaluation_metrics()
    return render_template(
        "visibility.html",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        eval_metrics=eval_metrics,
        default_scan_cidr=get_default_scan_cidr(),
        default_scan_mode=get_default_scan_mode(),
        default_discovery_profile=get_default_discovery_profile(),
        default_check_profile=get_default_check_profile(),
        api_key_required=is_admin_key_required(),
    )


@app.route("/scan/loading")
def scan_loading_page():
    return render_template("scan_loading.html", api_key_required=is_admin_key_required())


@app.route("/dashboard")
def home():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    asset_changes = load_asset_changes()
    return render_template(
        "dashboard.html",
        devices=devices,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        default_scan_cidr=get_default_scan_cidr(),
        default_scan_mode=get_default_scan_mode(),
        default_discovery_profile=get_default_discovery_profile(),
        default_check_profile=get_default_check_profile(),
        api_key_required=is_admin_key_required(),
        asset_changes=asset_changes,
        standards_map=STANDARDS_MAP,
        recommend=RECOMMEND
    )

@app.route("/report")
def report_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    return render_template(
        "section_report.html",
        active_tab="report",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        api_key_required=is_admin_key_required(),
        standards_map=STANDARDS_MAP,
        recommend=RECOMMEND,
    )

@app.route("/devices")
def devices_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    return render_template(
        "section_devices.html",
        active_tab="devices",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        api_key_required=is_admin_key_required(),
        standards_map=STANDARDS_MAP,
        recommend=RECOMMEND,
    )

@app.route("/findings")
def findings_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    threat_intel = load_threat_intel()
    return render_template(
        "section_findings.html",
        active_tab="findings",
        devices=devices,
        findings=findings,
        threat_intel=threat_intel,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        api_key_required=is_admin_key_required(),
        standards_map=STANDARDS_MAP,
        recommend=RECOMMEND,
    )

@app.route("/exports")
def exports_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    return render_template(
        "section_exports.html",
        active_tab="exports",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        api_key_required=is_admin_key_required(),
        recommend=RECOMMEND,
    )

@app.route("/evaluation")
def evaluation_page():
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    metrics = load_evaluation_metrics()
    check_profile_comparison = load_check_profile_comparison()
    return render_template(
        "section_evaluation.html",
        active_tab="evaluation",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        eval_metrics=metrics,
        check_profile_comparison=check_profile_comparison,
        api_key_required=is_admin_key_required(),
        recommend=RECOMMEND,
    )

@app.route("/report/print")
def report_print_page():
    auth = require_admin_key()
    if auth:
        return auth
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    return render_template(
        "report_print.html",
        devices=devices,
        findings=findings,
        issue_counts=issue_counts,
        sev_counts=sev_counts,
        grade_counts=grade_counts,
        summary=summary,
        analytics=analytics,
        standards_map=STANDARDS_MAP,
        recommend=RECOMMEND,
    )

@app.route("/api/devices")
def api_devices():
    auth = require_admin_key()
    if auth:
        return auth
    devices, *_ = build_view()
    return jsonify(devices)

@app.route("/api/findings")
def api_findings():
    auth = require_admin_key()
    if auth:
        return auth
    _, findings, *_ = build_view()
    return jsonify(findings)


@app.route("/api/threat-intel")
def api_threat_intel():
    auth = require_admin_key()
    if auth:
        return auth
    return jsonify(load_threat_intel())

@app.route("/api/report")
def api_report():
    auth = require_admin_key()
    if auth:
        return auth
    devices, findings, issue_counts, sev_counts, grade_counts, summary, analytics = build_view()
    metrics = load_evaluation_metrics()
    asset_changes = load_asset_changes()
    threat_intel = load_threat_intel()
    return jsonify({
        "summary": summary,
        "analytics": analytics,
        "evaluation_metrics": metrics,
        "asset_changes": asset_changes,
        "threat_intel": threat_intel,
        "standards_map": STANDARDS_MAP,
        "grade_counts": grade_counts,
        "issue_counts": issue_counts,
        "severity_counts": sev_counts,
        "devices": devices,
        "findings": findings,
    })


@app.route("/api/evaluation")
def api_evaluation():
    auth = require_admin_key()
    if auth:
        return auth
    metrics = load_evaluation_metrics()
    metrics["check_profile_comparison"] = load_check_profile_comparison()
    return jsonify(metrics)


@app.route("/api/asset-changes")
def api_asset_changes():
    auth = require_admin_key()
    if auth:
        return auth
    return jsonify(load_asset_changes())


@app.route("/api/scan/status")
def api_scan_status():
    auth = require_admin_key()
    if auth:
        return auth
    snap = scan_snapshot()
    snap["log_tail"] = read_scan_log_tail()
    return jsonify(snap)


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    payload = request.get_json(silent=True) or {}
    cidr = str(payload.get("cidr", "")).strip()
    note = str(payload.get("note", "")).strip()
    scan_mode = str(payload.get("scan_mode", "")).strip().lower() or get_default_scan_mode()
    discovery_profile = str(payload.get("discovery_profile", "")).strip().lower() or get_default_discovery_profile()
    check_profile = str(payload.get("check_profile", "")).strip().lower() or get_default_check_profile()

    if not cidr:
        return jsonify({"ok": False, "error": "cidr_required"}), 400

    auth = require_admin_key()
    if auth:
        return auth

    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return jsonify({"ok": False, "error": "invalid_cidr"}), 400
    if scan_mode not in SCAN_MODES:
        return jsonify({"ok": False, "error": "invalid_scan_mode", "allowed_modes": sorted(SCAN_MODES)}), 400
    if discovery_profile not in DISCOVERY_PROFILES:
        return jsonify(
            {
                "ok": False,
                "error": "invalid_discovery_profile",
                "allowed_profiles": sorted(DISCOVERY_PROFILES),
            }
        ), 400
    if check_profile not in CHECK_PROFILES:
        return jsonify(
            {
                "ok": False,
                "error": "invalid_check_profile",
                "allowed_check_profiles": sorted(CHECK_PROFILES),
            }
        ), 400

    with SCAN_LOCK:
        if SCAN_STATE.get("running"):
            return jsonify({"ok": False, "error": "scan_already_running", "status": SCAN_STATE}), 409
        # Reserve scan slot before launching worker to prevent double-start race.
        SCAN_STATE["running"] = True
        SCAN_STATE["cidr"] = cidr
        SCAN_STATE["scan_mode"] = scan_mode
        SCAN_STATE["discovery_profile"] = discovery_profile
        SCAN_STATE["check_profile"] = check_profile
        SCAN_STATE["note"] = note
        SCAN_STATE["started_utc"] = utc_now()
        SCAN_STATE["finished_utc"] = None
        SCAN_STATE["returncode"] = None
        SCAN_STATE["last_status"] = "starting"
        SCAN_STATE["pid"] = None
        save_scan_status()

    try:
        t = threading.Thread(
            target=_scan_worker,
            args=(cidr, note, discovery_profile, scan_mode, check_profile),
            daemon=True,
        )
        t.start()
    except Exception:
        with SCAN_LOCK:
            SCAN_STATE["running"] = False
            SCAN_STATE["last_status"] = "start_failed"
            SCAN_STATE["finished_utc"] = utc_now()
            SCAN_STATE["returncode"] = None
            SCAN_STATE["pid"] = None
            save_scan_status()
        return jsonify({"ok": False, "error": "scan_start_failed"}), 500
    return jsonify(
        {
            "ok": True,
            "message": "scan_started",
            "cidr": cidr,
            "note": note,
            "scan_mode": scan_mode,
            "discovery_profile": discovery_profile,
            "check_profile": check_profile,
        }
    )

@app.route("/export/findings.csv")
def export_findings_csv():
    auth = require_admin_key()
    if auth:
        return auth
    _, findings, *_ = build_view()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["ip","issue_type","severity","timestamp","evidence"])
    for f in findings:
        w.writerow([f.get("ip"), f.get("issue_type"), f.get("severity"), f.get("timestamp"), json.dumps(f.get("evidence",{}))])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="findings.csv")


@app.route("/export/evaluation.csv")
def export_evaluation_csv():
    auth = require_admin_key()
    if auth:
        return auth
    metrics = load_evaluation_metrics()
    summary = metrics.get("summary", {})
    fixture = metrics.get("fixture_validation", {})

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["metric", "value"])
    for k, v in summary.items():
        w.writerow([k, v])

    w.writerow([])
    w.writerow(["fixture_metric", "value"])
    for k, v in fixture.items():
        w.writerow([k, v])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="evaluation_metrics.csv")


@app.route("/export/report.pdf")
def export_report_pdf():
    auth = require_admin_key()
    if auth:
        return auth
    devices, findings, _, _, _, summary, analytics = build_view()
    lines = build_print_lines(devices, findings, summary, analytics)
    pdf_bytes = _build_simple_pdf(lines)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=iot-security-report.pdf"},
    )

@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == "__main__":
    host = os.environ.get("IOT_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port_raw = os.environ.get("PORT", os.environ.get("IOT_PORT", "5000")).strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 5000
    app.run(host=host, port=port, debug=False)
