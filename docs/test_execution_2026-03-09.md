# IoT Visibility Test Execution Report

Date: 2026-03-09

## Summary
- Overall result: PASS
- Critical criteria result: PASS
- Latest archived run: `20260309_155214Z`
- Latest scan meta: cidr=`10.10.7.0/30`, scan_mode=`hybrid`, discovery_profile=`standard`, check_profile=`safe`

## Test Case Results
| Test Case | Status | Evidence |
|---|---|---|
| TC-01 | PASS | install.ps1 executed; imports for flask/requests/nmap/waitress all succeeded after installing waitress. |
| TC-02 | PASS | validate_calibration.py --write-output passed (Devices checked: 5, IoT detected: 3). |
| TC-03 | PASS | {'latest_run_id': '20260309_155214Z', 'run_dir': 'C:\\Final Year Project\\iot-visibility\\data\\runs\\20260309_155214Z', 'files_present': ['inventory.json', 'inventory_labeled.json', 'findings.json', 'devices_report.json', 'threat_intel.json', 'scan_meta.json', 'evaluation_metrics.json', 'asset_state.json', 'asset_changes.json']} |
| TC-04 | PASS | {'scan_meta_keys': ['check_profile', 'cidr', 'discovery_phases', 'discovery_profile', 'discovery_rate_percent', 'live_host_count', 'passive_arp_entries_seen', 'passive_arp_hosts_in_cidr', 'ports_scanned', 'runtime_seconds', 'scan_finished_utc', 'scan_mode', 'scan_started_utc', 'target_host_count'], 'inventory_count': 0} |
| TC-05 | PASS | {'run_dir': 'C:\\Final Year Project\\iot-visibility\\data\\runs\\20260309_154107Z', 'scan_mode': 'passive', 'findings_count': 0} |
| TC-06 | PASS | {'run_dir': 'C:\\Final Year Project\\iot-visibility\\data\\runs\\20260309_154114Z', 'scan_meta_check_profile': 'audit', 'evidence_items_checked': 0, 'findings_count': 0} |
| TC-07 | PASS | {'status': 400, 'body': {'error': 'invalid_cidr', 'ok': False}} |
| TC-08 | PASS | {'mode': {'status': 400, 'body': {'allowed_modes': ['active', 'hybrid', 'passive'], 'error': 'invalid_scan_mode', 'ok': False}}, 'discovery': {'status': 400, 'body': {'allowed_profiles': ['aggressive', 'balanced', 'standard'], 'error': 'invalid_discovery_profile', 'ok': False}}, 'check': {'status': 400, 'body': {'allowed_check_profiles': ['audit', 'research', 'safe'], 'error': 'invalid_check_profile', 'ok': False}}} |
| TC-09 | PASS | {'first': {'status': 200, 'body': {'check_profile': 'safe', 'cidr': '10.10.7.0/24', 'discovery_profile': 'balanced', 'message': 'scan_started', 'note': 'tc09-lock', 'ok': True, 'scan_mode': 'hybrid'}}, 'second': {'status': 409, 'body': {'error': 'scan_already_running', 'ok': False, 'status': {'check_profile': 'safe', 'cidr': '10.10.7.0/24', 'discovery_profile': 'balanced', 'finished_utc': None, 'last_status': 'running', 'note': 'tc09-lock', 'pid': 15456, 'returncode': None, 'running': True, 'scan_mode': 'hybrid', 'started_utc': '2026-03-09T15:49:24.097160Z'}}}} |
| TC-10 | PASS | {'status': 200, 'keys': ['check_profile', 'cidr', 'discovery_profile', 'finished_utc', 'last_status', 'log_tail', 'note', 'pid', 'returncode', 'running', 'scan_mode', 'started_utc'], 'running': True} |
| TC-11 | PASS | {'status': 200, 'keys': ['analytics', 'asset_changes', 'devices', 'evaluation_metrics', 'findings', 'grade_counts', 'issue_counts', 'severity_counts', 'standards_map', 'summary', 'threat_intel']} |
| TC-12 | PASS | {'status': 200, 'keys': ['based_on_scan_finished_utc', 'check_profile_comparison', 'fixture_validation', 'generated_at_utc', 'issue_counts', 'summary']} |
| TC-13 | PASS | {'status': 200, 'keys': ['enriched_findings', 'generated_at_utc', 'source_findings_count', 'summary']} |
| TC-14 | PASS | {'status': 200, 'content_type': 'text/csv; charset=utf-8', 'line1': 'ip,issue_type,severity,timestamp,evidence'} |
| TC-15 | PASS | {'status': 200, 'content_type': 'text/csv; charset=utf-8', 'line1': 'metric,value'} |
| TC-16 | PASS | {'status': 200, 'content_type': 'application/pdf', 'bytes': 901} |
| TC-17 | PASS | {'/': 200, '/dashboard': 200, '/visibility': 200, '/evaluation': 200, '/report': 200} |
| TC-18 | PASS | {'/api/devices': 200, '/api/findings': 200, '/api/report': 200, '/api/evaluation': 200, '/export/findings.csv': 200, '/export/evaluation.csv': 200, '/export/report.pdf': 200, '/report/print': 200} |
| TC-19 | PASS | {'unauthorized': {'/api/devices': 401, '/api/findings': 401, '/api/report': 401, '/api/evaluation': 401, '/export/findings.csv': 401, '/export/evaluation.csv': 401, '/export/report.pdf': 401, '/report/print': 401}, 'authorized_header': {'/api/devices': 200, '/api/findings': 200, '/api/report': 200, '/api/evaluation': 200, '/export/findings.csv': 200, '/export/evaluation.csv': 200, '/export/report.pdf': 200, '/report/print': 200}, 'authorized_query': {'/api/devices': 200, '/api/findings': 200, '/api/report': 200, '/api/evaluation': 200, '/export/findings.csv': 200, '/export/evaluation.csv': 200, '/export/report.pdf': 200, '/report/print': 200}} |
| TC-20 | PASS | {'latest_run_id': '20260309_155214Z', 'presence': {'inventory.json': True, 'inventory_labeled.json': True, 'findings.json': True, 'devices_report.json': True, 'threat_intel.json': True, 'scan_meta.json': True, 'evaluation_metrics.json': True, 'asset_state.json': True, 'asset_changes.json': True}, 'json_parse_ok': {'inventory.json': True, 'inventory_labeled.json': True, 'findings.json': True, 'devices_report.json': True, 'threat_intel.json': True, 'scan_meta.json': True, 'evaluation_metrics.json': True, 'asset_state.json': True, 'asset_changes.json': True}, 'matches_active_data': {'inventory.json': True, 'inventory_labeled.json': True, 'findings.json': True, 'devices_report.json': True, 'threat_intel.json': True, 'scan_meta.json': True, 'evaluation_metrics.json': True, 'asset_state.json': True, 'asset_changes.json': True}} |

## Evidence Files
- `data/test_results_pipeline.json`
- `data/test_results_auth_off.json`
- `data/test_results_auth_on.json`
- `data/scan_meta.json`
- `data/latest_run.json`
