# scanner/discover.py
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import re
import subprocess
from pathlib import Path

import nmap

# Expanded set of common ports (safe: only detection, no login)
# Web/admin: 80/443 + common alternates
# IoT: 554 (RTSP), 1900 (SSDP)
# Endpoint signals: 22/23 (SSH/Telnet), 139/445 (SMB)
COMMON_PORTS = "80,443,8080,8443,8000,8888,10000,10443,554,1900,22,23,139,445"
DISCOVERY_PROBE_PORTS = "80,443,22,23,139,445,554,1900"

DISCOVERY_PROFILES = {
    "standard": [
        {"name": "default_ping_sweep", "args": "-sn"},
    ],
    "balanced": [
        {"name": "default_ping_sweep", "args": "-sn"},
        {"name": "arp_sweep", "args": "-sn -PR"},
        {"name": "tcp_icmp_ping", "args": f"-sn -PE -PS{DISCOVERY_PROBE_PORTS} -PA{DISCOVERY_PROBE_PORTS}"},
    ],
    "aggressive": [
        {"name": "default_ping_sweep", "args": "-sn"},
        {"name": "arp_sweep", "args": "-sn -PR"},
        {"name": "tcp_icmp_ping", "args": f"-sn -PE -PS{DISCOVERY_PROBE_PORTS} -PA{DISCOVERY_PROBE_PORTS}"},
        # Last-resort host discovery for devices that ignore ping probes.
        {"name": "open_port_presence", "args": f"-Pn -n --open --max-retries 1 -T3 -p {DISCOVERY_PROBE_PORTS}"},
    ],
}


def utc_now_iso() -> str:
    """Timezone-aware UTC timestamp (avoids utcnow() deprecation warning)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover hosts and build passive-friendly inventory.json")
    parser.add_argument("cidr", nargs="?", default="192.168.1.0/24", help="Target CIDR, e.g. 192.168.1.0/24")
    parser.add_argument(
        "--scan-mode",
        choices=["active", "hybrid", "passive"],
        default="hybrid",
        help="Discovery mode: active probes only, passive ARP observation only, or hybrid.",
    )
    parser.add_argument(
        "--discovery-profile",
        choices=sorted(DISCOVERY_PROFILES.keys()),
        default="balanced",
        help="Host discovery profile: standard, balanced, or aggressive.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="Batch size for the follow-up common-port scan.",
    )
    parser.add_argument(
        "--max-target-hosts",
        type=int,
        default=4096,
        help="Safety limit: refuse very large target ranges by default.",
    )
    return parser.parse_args()


def get_scanner() -> "nmap.PortScanner":
    """Create an Nmap PortScanner, with Windows fallback paths."""
    try:
        return nmap.PortScanner()
    except nmap.PortScannerError:
        return nmap.PortScanner(
            nmap_search_path=[
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe",
            ]
        )


def fingerprint_hint(open_tcp: set[int]) -> str:
    """Very lightweight heuristic: label by observed open ports."""
    if 554 in open_tcp:
        return "camera_or_nvr"
    if open_tcp & {80, 443, 8080, 8443, 8000, 8888, 10000, 10443}:
        return "web_managed_device"
    if open_tcp & {139, 445}:
        return "likely_windows_or_smb_host"
    if open_tcp & {22, 23}:
        return "ssh_or_telnet_device"
    return "host_up_no_common_ports"


def network_target_count(cidr: str) -> int:
    net = ipaddress.ip_network(cidr, strict=False)
    # Count usable hosts for IPv4 subnets where network/broadcast are reserved.
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
        return int(net.num_addresses - 2)
    return int(net.num_addresses)


def chunked(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def normalize_mac(raw_mac: str) -> str:
    mac = raw_mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6:
        return ""
    if not all(re.fullmatch(r"[0-9a-f]{2}", p or "") for p in parts):
        return ""
    return ":".join(parts)


def discover_from_arp_cache(cidr: str) -> tuple[list[str], dict[str, dict[str, str]], dict[str, int]]:
    """
    Passive-ish discovery using local ARP cache.
    This does not send packets from this script; results depend on existing cache entries.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
        output = f"{result.stdout}\n{result.stderr}"
    except OSError:
        return [], {}, {"entries_seen": 0, "matched_in_cidr": 0}

    host_meta: dict[str, dict[str, str]] = {}
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_pattern = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")

    entries_seen = 0
    for line in output.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if not ip_match:
            continue
        entries_seen += 1

        ip_str = ip_match.group(1)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_obj not in network:
            continue

        mac = normalize_mac(mac_match.group(1)) if mac_match else ""
        host_meta[ip_str] = {
            "mac": mac,
            "vendor_guess": "",
        }

    hosts = sorted(host_meta.keys(), key=lambda x: ipaddress.ip_address(x))
    return hosts, host_meta, {"entries_seen": entries_seen, "matched_in_cidr": len(hosts)}


def collect_host_metadata(nm: "nmap.PortScanner", host: str, host_meta: dict[str, dict[str, str]]):
    entry = host_meta.setdefault(host, {"mac": "", "vendor_guess": ""})
    host_obj = nm[host]
    mac = host_obj.get("addresses", {}).get("mac", "")
    if mac and not entry["mac"]:
        entry["mac"] = mac

    vendor_guess = ""
    vendor_map = host_obj.get("vendor", {})
    if vendor_map:
        vendor_guess = next(iter(vendor_map.values()))
    if vendor_guess and not entry["vendor_guess"]:
        entry["vendor_guess"] = vendor_guess


def run_discovery_phases(
    nm: "nmap.PortScanner",
    cidr: str,
    profile_name: str,
) -> tuple[list[str], dict[str, dict[str, str]], list[dict]]:
    phases = DISCOVERY_PROFILES[profile_name]
    discovered_hosts: set[str] = set()
    host_meta: dict[str, dict[str, str]] = {}
    phase_stats: list[dict] = []

    for phase in phases:
        phase_name = phase["name"]
        phase_args = phase["args"]
        phase_start = datetime.datetime.now(datetime.timezone.utc)

        print(f"[+] Host discovery phase '{phase_name}' on {cidr} ({phase_args})")
        nm.scan(hosts=cidr, arguments=phase_args)
        phase_hosts = {h for h in nm.all_hosts() if nm[h].state() == "up"}

        for host in phase_hosts:
            collect_host_metadata(nm, host, host_meta)

        new_hosts = phase_hosts - discovered_hosts
        discovered_hosts.update(phase_hosts)
        phase_elapsed = (datetime.datetime.now(datetime.timezone.utc) - phase_start).total_seconds()

        print(
            f"[+]   phase result: {len(phase_hosts)} up, {len(new_hosts)} new, "
            f"{len(discovered_hosts)} total so far"
        )
        phase_stats.append(
            {
                "name": phase_name,
                "args": phase_args,
                "phase_live_hosts": len(phase_hosts),
                "new_hosts": len(new_hosts),
                "cumulative_live_hosts": len(discovered_hosts),
                "duration_seconds": round(phase_elapsed, 2),
            }
        )

    ordered_hosts = sorted(discovered_hosts, key=lambda x: ipaddress.ip_address(x))
    return ordered_hosts, host_meta, phase_stats


def main():
    args = parse_args()
    cidr = args.cidr
    scan_mode = args.scan_mode

    target_count = network_target_count(cidr)
    if target_count > args.max_target_hosts:
        raise ValueError(
            f"Target {cidr} has {target_count} hosts, above safety limit {args.max_target_hosts}. "
            "Use a smaller subnet or raise --max-target-hosts."
        )

    start = datetime.datetime.now(datetime.timezone.utc)
    phase_stats: list[dict] = []
    host_meta: dict[str, dict[str, str]] = {}
    host_sources: dict[str, set[str]] = {}
    active_hosts: list[str] = []
    nm = None

    if scan_mode in {"active", "hybrid"}:
        nm = get_scanner()
        active_hosts, active_meta, phase_stats = run_discovery_phases(nm, cidr, args.discovery_profile)
        host_meta.update(active_meta)
        for host in active_hosts:
            host_sources.setdefault(host, set()).add("active_nmap")

    passive_hosts: list[str] = []
    passive_stats = {"entries_seen": 0, "matched_in_cidr": 0}
    if scan_mode in {"passive", "hybrid"}:
        print(f"[+] Passive observation from ARP cache for {cidr} ...")
        passive_hosts, passive_meta, passive_stats = discover_from_arp_cache(cidr)
        for host, meta in passive_meta.items():
            current = host_meta.setdefault(host, {"mac": "", "vendor_guess": ""})
            if meta.get("mac") and not current.get("mac"):
                current["mac"] = meta["mac"]
            if meta.get("vendor_guess") and not current.get("vendor_guess"):
                current["vendor_guess"] = meta["vendor_guess"]
            host_sources.setdefault(host, set()).add("arp_cache")
        phase_stats.append(
            {
                "name": "passive_arp_cache",
                "args": "arp -a (local cache read)",
                "phase_live_hosts": len(passive_hosts),
                "new_hosts": len(set(passive_hosts) - set(active_hosts)),
                "cumulative_live_hosts": len(set(active_hosts).union(passive_hosts)),
                "duration_seconds": 0.0,
            }
        )

    hosts = sorted(set(active_hosts).union(passive_hosts), key=lambda x: ipaddress.ip_address(x))

    # Always create an entry for every discovered host.
    inventory = []
    for host in hosts:
        meta = host_meta.get(host, {})
        inventory.append(
            {
                "device_id": host,
                "ip": host,
                "mac": meta.get("mac", ""),
                "vendor_guess": meta.get("vendor_guess", ""),
                "open_tcp_ports": [],
                "fingerprint_hint": "passive_cache_observed" if scan_mode == "passive" else "unknown",
                "discovery_sources": sorted(host_sources.get(host, [])),
                "last_seen": utc_now_iso(),
            }
        )

    if hosts and scan_mode != "passive":
        print(f"[+] Target port scan ({COMMON_PORTS}) across {len(hosts)} discovered hosts ...")
        inv_by_ip = {d["ip"]: d for d in inventory}
        batches = chunked(hosts, max(1, int(args.batch_size)))
        for idx, batch in enumerate(batches, start=1):
            print(f"[+]   port-scan batch {idx}/{len(batches)} ({len(batch)} hosts)")
            nm.scan(hosts=" ".join(batch), arguments=f"-Pn -T4 -p {COMMON_PORTS}")
            for host in nm.all_hosts():
                collect_host_metadata(nm, host, host_meta)
                tcp = nm[host].get("tcp", {})
                open_tcp = {p for p, info in tcp.items() if info.get("state") == "open"}
                if host in inv_by_ip:
                    inv_by_ip[host]["open_tcp_ports"] = sorted(open_tcp)
                    inv_by_ip[host]["fingerprint_hint"] = fingerprint_hint(open_tcp)
                    # Refresh with metadata from whichever phase had the best information.
                    inv_by_ip[host]["mac"] = host_meta.get(host, {}).get("mac", inv_by_ip[host]["mac"])
                    inv_by_ip[host]["vendor_guess"] = host_meta.get(host, {}).get(
                        "vendor_guess", inv_by_ip[host]["vendor_guess"]
                    )
        inventory = list(inv_by_ip.values())
    elif scan_mode == "passive":
        print("[+] Passive mode enabled: skipped active port scan stage.")

    # Save relative to project root.
    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    out_file = data_dir / "inventory.json"
    meta_file = data_dir / "scan_meta.json"

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)

    elapsed = (datetime.datetime.now(datetime.timezone.utc) - start).total_seconds()
    meta = {
        "cidr": cidr,
        "scan_mode": scan_mode,
        "discovery_profile": args.discovery_profile,
        "target_host_count": target_count,
        "live_host_count": len(inventory),
        "discovery_rate_percent": round((len(inventory) * 100.0 / target_count), 2) if target_count else None,
        "scan_started_utc": start.isoformat().replace("+00:00", "Z"),
        "scan_finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "runtime_seconds": round(elapsed, 2),
        "ports_scanned": COMMON_PORTS if scan_mode != "passive" else "",
        "passive_arp_entries_seen": passive_stats["entries_seen"],
        "passive_arp_hosts_in_cidr": passive_stats["matched_in_cidr"],
        "discovery_phases": phase_stats,
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"[+] Saved {len(inventory)} hosts to {out_file}")
    print(f"[+] Saved scan metadata to {meta_file}")
    print(f"[+] Runtime: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
