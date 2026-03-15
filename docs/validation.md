# Validation Workflow

Use this workflow to verify that classifier and scoring logic still behave as expected after changes.

## Run baseline validation

```powershell
.\.venv\Scripts\python.exe .\checks\validate_calibration.py --write-output
```

## What it checks

- Device type classification against expected labels.
- IoT/non-IoT flag correctness.
- Score ranges for each fixture device.
- Minimum confidence thresholds.
- Summary checks (`device_count`, `iot_count` range).

## Fixture files

- `tests/fixtures/lab_baseline/inventory.json`
- `tests/fixtures/lab_baseline/findings.json`
- `tests/fixtures/lab_baseline/expected.json`

Generated outputs (optional) are written to:

- `tests/output/lab_baseline/inventory_labeled.json`
- `tests/output/lab_baseline/devices_report.json`
