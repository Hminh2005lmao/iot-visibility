# checks/summarize_findings.py
from pathlib import Path
import json
from collections import Counter, defaultdict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FINDINGS_PATH = PROJECT_ROOT / "data" / "findings.json"

if not FINDINGS_PATH.exists():
    raise FileNotFoundError(f"Cannot find {FINDINGS_PATH}. Run web_checks_v4.py first.")

findings = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))

print("Findings file:", FINDINGS_PATH)
print("Total findings:", len(findings))

if not findings:
    print("No findings to summarize.")
    raise SystemExit(0)

print("\nIssue type counts:")
print(Counter(f["issue_type"] for f in findings))

score_map = {"H": 3, "M": 2, "L": 1, "I": 0}
by_ip = defaultdict(int)

for f in findings:
    by_ip[f["ip"]] += score_map.get(f.get("severity", "I"), 0)

print("\nTop 10 worst devices by score:")
for ip, s in sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"{ip}  score={s}")
