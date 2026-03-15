# Device Report Contract

The file `data/devices_report.json` is the canonical output for per-device security scoring.

## Top-level fields

- `generated_at_utc`: UTC timestamp for report generation.
- `policy_version`: Policy version from `docs/policy.json`.
- `secure_threshold_max_score`: Maximum score still considered secure.
- `device_count`: Number of devices in the report.
- `devices`: Array of per-device objects.

## Per-device fields

- `ip`: Device IP.
- `mac`: Device MAC address (if available).
- `vendor_guess`: Vendor hint from scan.
- `open_tcp_ports`: Observed open TCP ports.
- `is_iot`: Boolean IoT detection flag.
- `device_type`: Friendly normalized type (`camera`, `iot_or_router`, `printer`, `pc`, `phone_or_laptop`, `unknown`).
- `device_type_raw`: Raw classifier output.
- `device_type_reason`: Why type was assigned.
- `device_type_confidence`: Confidence in device type (`low`, `medium`, `high`).
- `device_type_signals`: Passive signals that influenced classification (ports, vendor, web hints).
- `risk_score`: Integer risk score `0..100` (higher is less secure).
- `risk_score_raw`: Raw risk score before optional tuning caps.
- `risk_grade`: Letter grade `A/B/C/D/F`.
- `is_secure`: `true` when `risk_score <= secure_threshold_max_score`.
- `hard_fail_triggered`: `true` when a policy guardrail forced insecure posture or score floor.
- `hard_fail_rules`: List of guardrail rule IDs applied to this device.
- `why_this_score`: Human-readable score explanation list.
- `score_breakdown`: Structured scoring components with `rule_id`, `points`, `reason`, `source`.
- `issues`: Raw findings linked to that device.

## Notes

- Scoring is policy-based and explainable, not exploit confirmation.
- Findings are passive only.
- Findings may include profile-driven management exposure issues such as:
  - `telnet_exposed`
  - `ftp_plaintext_exposed`
  - `smb_exposed`
  - `rtsp_exposed`
  - `upnp_exposed`
- Threat prioritization output is available in `data/threat_intel.json` with KEV/EPSS-style heuristic fields:
  - `threat_score`
  - `priority`
  - `exploitability_percent`
  - `impact_percent`
  - `kev_like`
  - `epss_like_percent`
- UI/API response enrichment maps findings to standards references via `standards_refs` (ETSI EN 303 645, NISTIR 8259A, RFC 8520 MUD, NIST SP 1800-15) to support compliance explanation.
