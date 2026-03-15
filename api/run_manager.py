# api/run_manager.py
from pathlib import Path
import json
import shutil
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RUNS_DIR = DATA / "runs"
INDEX_FILE = RUNS_DIR / "index.json"
LATEST_FILE = DATA / "latest_run.json"

FILES_TO_ARCHIVE = [
    DATA / "inventory.json",
    DATA / "inventory_labeled.json",
    DATA / "findings.json",
    DATA / "devices_report.json",
    DATA / "threat_intel.json",
    DATA / "scan_meta.json",
    DATA / "evaluation_metrics.json",
    DATA / "asset_state.json",
    DATA / "asset_changes.json",
]

def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")

def load_index():
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return {"runs": []}

def save_index(idx):
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps(idx, indent=2), encoding="utf-8")

def archive_run(note: str = "") -> dict:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = utc_stamp()
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    archived = []
    missing = []

    for f in FILES_TO_ARCHIVE:
        if f.exists():
            dest = run_dir / f.name
            shutil.copy2(f, dest)
            archived.append(f.name)
        else:
            missing.append(f.name)

    meta = {
        "run_id": run_id,
        "created_utc": run_id,
        "note": note,
        "run_dir": str(run_dir),
        "files_archived": archived,
        "files_missing": missing,
    }

    # update index
    idx = load_index()
    idx["runs"].insert(0, meta)  # newest first
    save_index(idx)

    # update latest pointer
    LATEST_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return meta

if __name__ == "__main__":
    # manual test: archive current run
    m = archive_run(note="manual archive")
    print("[+] Archived run:", m["run_id"])
    print("[+] Files archived:", m["files_archived"])
    if m["files_missing"]:
        print("[!] Missing:", m["files_missing"])
