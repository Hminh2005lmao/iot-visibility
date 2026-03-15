from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

FINDINGS_FILE = DATA_DIR / "findings.json"
REPORT_FILE = DATA_DIR / "devices_report.json"
OUT_FILE = DATA_DIR / "threat_intel.json"

SEVERITY_BASE = {"H": 70, "M": 45, "L": 25, "I": 8}

ISSUE_INTEL = {
    "no_auth_endpoint": {
        "exploitability": 0.92,
        "impact": 0.9,
        "kev_like": True,
        "epss_like": 0.78,
        "rationale": "Admin endpoint reachable without auth can allow immediate unauthorized control.",
    },
    "default_login_like": {
        "exploitability": 0.88,
        "impact": 0.82,
        "kev_like": True,
        "epss_like": 0.71,
        "rationale": "Default-style login surfaces are frequently targeted in opportunistic attacks.",
    },
    "telnet_exposed": {
        "exploitability": 0.9,
        "impact": 0.84,
        "kev_like": True,
        "epss_like": 0.74,
        "rationale": "Telnet is plaintext and commonly abused in IoT botnet propagation.",
    },
    "smb_exposed": {
        "exploitability": 0.76,
        "impact": 0.78,
        "kev_like": True,
        "epss_like": 0.64,
        "rationale": "SMB exposure is a known lateral movement path in internal networks.",
    },
    "ftp_plaintext_exposed": {
        "exploitability": 0.66,
        "impact": 0.62,
        "kev_like": False,
        "epss_like": 0.46,
        "rationale": "FTP may expose credentials in plaintext and weakens management security.",
    },
    "http_only": {
        "exploitability": 0.58,
        "impact": 0.54,
        "kev_like": False,
        "epss_like": 0.35,
        "rationale": "HTTP-only management enables credential interception on shared networks.",
    },
    "rtsp_exposed": {
        "exploitability": 0.57,
        "impact": 0.6,
        "kev_like": False,
        "epss_like": 0.34,
        "rationale": "Exposed RTSP streams can leak video feeds and device metadata.",
    },
    "upnp_exposed": {
        "exploitability": 0.45,
        "impact": 0.45,
        "kev_like": False,
        "epss_like": 0.22,
        "rationale": "UPnP exposure increases unintended service reachability risk.",
    },
    "self_signed_tls": {
        "exploitability": 0.28,
        "impact": 0.35,
        "kev_like": False,
        "epss_like": 0.12,
        "rationale": "Self-signed TLS reduces trust and can hide man-in-the-middle risk.",
    },
    "headers_missing": {
        "exploitability": 0.2,
        "impact": 0.3,
        "kev_like": False,
        "epss_like": 0.09,
        "rationale": "Missing security headers increases web hardening gaps.",
    },
    "https_available": {
        "exploitability": 0.05,
        "impact": 0.08,
        "kev_like": False,
        "epss_like": 0.03,
        "rationale": "Informational signal that encrypted admin path exists.",
    },
}

INTEL_REFERENCES = [
    "https://nvd.nist.gov/developers/vulnerabilities",
    "https://api.first.org/epss/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich findings with KEV/EPSS-style threat prioritization.")
    parser.add_argument("--findings", type=Path, default=FINDINGS_FILE, help="Input findings.json")
    parser.add_argument("--report", type=Path, default=REPORT_FILE, help="Input devices_report.json")
    parser.add_argument("--output", type=Path, default=OUT_FILE, help="Output threat_intel.json")
    return parser.parse_args()


def clamp_score(value: float) -> int:
    return max(0, min(100, int(round(value))))


def priority_for_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def enrich_finding(item: dict, device: dict | None) -> dict:
    issue_type = str(item.get("issue_type", "unknown"))
    severity = str(item.get("severity", "I"))
    intel = ISSUE_INTEL.get(
        issue_type,
        {
            "exploitability": 0.35,
            "impact": 0.35,
            "kev_like": False,
            "epss_like": 0.15,
            "rationale": "Generic heuristic used; no specific issue intelligence profile defined.",
        },
    )

    base = SEVERITY_BASE.get(severity, 20)
    exploitability = float(intel["exploitability"])
    impact = float(intel["impact"])
    kev_like = bool(intel["kev_like"])
    epss_like = float(intel["epss_like"])
    device_risk = int((device or {}).get("risk_score", 0))

    threat_score = base + (exploitability * 20.0) + (impact * 15.0) + (8.0 if kev_like else 0.0) + (device_risk * 0.1)
    threat_score = clamp_score(threat_score)
    priority = priority_for_score(threat_score)

    return {
        "ip": item.get("ip", ""),
        "issue_type": issue_type,
        "severity": severity,
        "timestamp": item.get("timestamp"),
        "evidence": item.get("evidence", {}),
        "device_type": (device or {}).get("device_type", "unknown"),
        "device_risk_score": device_risk,
        "device_risk_grade": (device or {}).get("risk_grade", "N/A"),
        "threat_score": threat_score,
        "priority": priority,
        "exploitability_percent": int(round(exploitability * 100)),
        "impact_percent": int(round(impact * 100)),
        "kev_like": kev_like,
        "epss_like_percent": int(round(epss_like * 100)),
        "rationale": intel["rationale"],
        "references": INTEL_REFERENCES,
    }


def main():
    args = parse_args()
    findings = load_json(args.findings, [])
    report = load_json(args.report, {})
    devices = report.get("devices", []) if isinstance(report, dict) else []
    devices_by_ip = {str(d.get("ip", "")): d for d in devices if d.get("ip")}

    enriched = [enrich_finding(item, devices_by_ip.get(str(item.get("ip", "")))) for item in findings]
    enriched.sort(key=lambda x: (x.get("threat_score", 0), x.get("priority", "")), reverse=True)

    priority_counts = Counter(x.get("priority", "low") for x in enriched)
    issue_scores = defaultdict(list)
    for item in enriched:
        issue_scores[item["issue_type"]].append(item["threat_score"])

    issue_priority = sorted(
        (
            {
                "issue_type": issue,
                "avg_threat_score": round(sum(scores) / len(scores), 1),
                "count": len(scores),
            }
            for issue, scores in issue_scores.items()
        ),
        key=lambda x: x["avg_threat_score"],
        reverse=True,
    )

    out = {
        "generated_at_utc": now_iso(),
        "source_findings_count": len(findings),
        "summary": {
            "priority_counts": dict(priority_counts),
            "top_priorities": enriched[:10],
            "issue_priority": issue_priority[:12],
        },
        "enriched_findings": enriched,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[+] Wrote threat intelligence enrichment to {args.output}")
    print(f"[+] Enriched findings: {len(enriched)}")


if __name__ == "__main__":
    main()
