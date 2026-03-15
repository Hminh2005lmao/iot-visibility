# run_pipeline.py
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
SCAN_META_FILE = DATA_DIR / "scan_meta.json"

def run(cmd):
    print("\n>>", " ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=str(ROOT))
    except FileNotFoundError as exc:
        print(f"[!] Executable not found: {cmd[0]}")
        print(f"[!] Details: {exc}")
        sys.exit(1)
    if r.returncode != 0:
        print("[!] Command failed:", r.returncode)
        sys.exit(r.returncode)


def resolve_python_exe() -> str:
    """
    Resolve a Python interpreter that works on both local Windows and Linux containers.
    Priority:
    1) active interpreter (sys.executable)
    2) project venv Windows path
    3) project venv Linux path
    """
    candidates = [
        Path(sys.executable),
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(candidate)
    return "python"


def update_scan_meta(scan_mode: str, discovery_profile: str, check_profile: str):
    if not SCAN_META_FILE.exists():
        return
    try:
        meta = json.loads(SCAN_META_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(meta, dict):
        return
    meta["scan_mode"] = scan_mode
    meta["discovery_profile"] = discovery_profile
    meta["check_profile"] = check_profile
    SCAN_META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run IoT visibility pipeline end-to-end.")
    parser.add_argument("cidr", help="Target CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("note", nargs="?", default="", help="Optional archive note")
    parser.add_argument(
        "--scan-mode",
        choices=["active", "hybrid", "passive"],
        default="hybrid",
        help="Scan mode: active probes only, passive cache observation only, or hybrid.",
    )
    parser.add_argument(
        "--discovery-profile",
        choices=["standard", "balanced", "aggressive"],
        default="balanced",
        help="Discovery profile passed to scanner/discover.py",
    )
    parser.add_argument(
        "--check-profile",
        choices=["safe", "audit", "research"],
        default="safe",
        help="Web and management check depth profile.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    cidr = args.cidr
    note = args.note
    scan_mode = args.scan_mode
    discovery_profile = args.discovery_profile
    check_profile = args.check_profile

    py = resolve_python_exe()

    run(
        [
            py,
            str(ROOT / "scanner" / "discover.py"),
            cidr,
            "--scan-mode",
            scan_mode,
            "--discovery-profile",
            discovery_profile,
        ]
    )
    update_scan_meta(scan_mode=scan_mode, discovery_profile=discovery_profile, check_profile=check_profile)
    # optional classification if script exists
    classify = ROOT / "checks" / "classify_devices.py"
    if classify.exists():
        run([py, str(classify)])

    if scan_mode == "passive":
        print("\n>> Skipping active web checks in passive mode")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        (DATA_DIR / "findings.json").write_text("[]\n", encoding="utf-8")
        print(">> Wrote empty findings.json for passive mode")
    else:
        run([py, str(ROOT / "checks" / "web_checks_v4.py"), "--check-profile", check_profile])
    # policy-based security scoring report
    scorer = ROOT / "checks" / "score_devices.py"
    if scorer.exists():
        run([py, str(scorer)])

    # threat-intel style enrichment (KEV/EPSS heuristic priority)
    intel_builder = ROOT / "checks" / "enrich_threat_intel.py"
    if intel_builder.exists():
        run([py, str(intel_builder)])

    # evaluation metrics report
    eval_builder = ROOT / "checks" / "build_evaluation_metrics.py"
    if eval_builder.exists():
        run([py, str(eval_builder)])

    # persistent asset state + run-to-run drift summary
    asset_builder = ROOT / "checks" / "build_asset_history.py"
    if asset_builder.exists():
        run([py, str(asset_builder)])

    # archive after scan
    run([py, str(ROOT / "api" / "run_manager.py")])

    print("\n[+] Pipeline complete. Latest run saved in data/latest_run.json")

if __name__ == "__main__":
    main()
