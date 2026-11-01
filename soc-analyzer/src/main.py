from __future__ import annotations

import argparse
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None

# === SSH log regex patterns for parsing ===
SSH_FAILED_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>sshd)\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\S+)"
)

SSH_ACCEPTED_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>sshd)\[\d+\]:\s+"
    r"Accepted password for (?P<username>\S+) from (?P<ip>\S+)"
)

# === Supported Windows Security Event IDs ===
WINDOWS_FAILED_EVENT_ID = 4625
WINDOWS_SUCCESS_EVENT_ID = 4624

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SOC Authentication Anomaly Detector"
    )
    parser.add_argument(
        "-l", "--log",
        required=True,
        help="Path to authentication log file"
    )
    parser.add_argument(
        "-i", "--ioc",
        help="Path to IOC IP list file"
    )
    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        help="Failed login threshold for brute force detection within the time window (default: 5)",
    )
    parser.add_argument(
        "--spray-threshold",
        type=int,
        default=3,
        help="Unique username threshold for password spraying detection (default: 3)",
    )
    parser.add_argument(
        "--success-after-fail-threshold",
        type=int,
        default=3,
        help="Failed login threshold before a success is considered suspicious (default: 3)",
    )
    parser.add_argument(
        "--time-window-minutes",
        type=int,
        default=5,
        help="Time window in minutes for bursty brute force, spraying and success-after-fail correlation (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report in JSON format"
    )
    parser.add_argument(
        "--output",
        help="Path to save JSON report (optional)"
    )
    return parser.parse_args()


def load_lines(file_path: Path) -> list[str]:
    try:
        with file_path.open("r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File Not Found: {file_path}")
        raise SystemExit(1)


def load_iocs(file_path: Path) -> set[str]:
    raw_lines = load_lines(file_path)
    valid_ips = set()

    for line in raw_lines:
        try:
            ip_obj = ipaddress.ip_address(line)
            valid_ips.add(str(ip_obj))
        except ValueError:
            print(f"Skipping invalid IOC entry: {line}")
    return valid_ips


def parse_event_timestamp(raw_timestamp: str, log_type: str) -> datetime | None:
    """Parse supported timestamp formats into datetime objects for correlation."""
    if not raw_timestamp:
        return None

    try:
        if log_type == "ssh":
            current_year = datetime.now().year
            return datetime.strptime(
                f"{current_year} {raw_timestamp}",
                "%Y %b %d %H:%M:%S",
            )

        normalized = raw_timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


def classify_ip_context(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"

    if ip_obj.is_loopback:
        return "loopback"

    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    if any(ip_obj in net for net in private_networks):
        return "internal"

    return "external"


def within_minutes(start: datetime, end: datetime, minutes: int) -> bool:
    delta_seconds = (end - start).total_seconds()
    return 0 <= delta_seconds <= minutes * 60


def parse_logs(lines: list[str]) -> list[dict]:
    """
    Parse supported authentication logs and normalize them into structured events.

    Currently supported formats:

    1. SSH authentication logs
       Example:
       Jul 10 22:11:03 server sshd[1234]: Failed password for admin from 185.10.10.10 port 49200 ssh2
       Jul 10 22:11:08 server sshd[1239]: Accepted password for admin from 185.10.10.10 port 49201 ssh2

    2. Windows Security Event logs in JSON-lines format
       Example:
       {"EventID": 4625, "TimeCreated": "2026-07-10T22:11:03", "Computer": "DC01", "IpAddress": "185.10.10.10", "TargetUserName": "Administrator"}
       {"EventID": 4624, "TimeCreated": "2026-07-10T22:11:08", "Computer": "DC01", "IpAddress": "185.10.10.10", "TargetUserName": "Administrator"}
    """
    events = []

    for line in lines:
        failed_match = SSH_FAILED_RE.match(line)
        accepted_match = SSH_ACCEPTED_RE.match(line)

        if failed_match:
            data = failed_match.groupdict()
            events.append(
                {
                    "timestamp": data["timestamp"],
                    "parsed_time": parse_event_timestamp(data["timestamp"], "ssh"),
                    "status": "FAIL",
                    "ip": data["ip"],
                    "username": data["username"],
                    "service": data["service"],
                    "host": data["host"],
                    "log_type": "ssh",
                    "ip_context": classify_ip_context(data["ip"]),
                }
            )
            continue

        if accepted_match:
            data = accepted_match.groupdict()
            events.append(
                {
                    "timestamp": data["timestamp"],
                    "parsed_time": parse_event_timestamp(data["timestamp"], "ssh"),
                    "status": "SUCCESS",
                    "ip": data["ip"],
                    "username": data["username"],
                    "service": data["service"],
                    "host": data["host"],
                    "log_type": "ssh",
                    "ip_context": classify_ip_context(data["ip"]),
                }
            )
            continue

        try:
            win_event = json.loads(line)
        except json.JSONDecodeError:
            win_event = None

        if isinstance(win_event, dict):
            event_id = win_event.get("EventID")
            ip = str(win_event.get("IpAddress", "")).strip()
            username = str(win_event.get("TargetUserName", "")).strip()
            timestamp = str(win_event.get("TimeCreated", "")).strip()
            host = str(win_event.get("Computer", win_event.get(
                "host", "windows-host"))).strip()

            if event_id in {WINDOWS_FAILED_EVENT_ID, WINDOWS_SUCCESS_EVENT_ID} and ip and username:
                status = "FAIL" if event_id == WINDOWS_FAILED_EVENT_ID else "SUCCESS"
                events.append(
                    {
                        "timestamp": timestamp,
                        "parsed_time": parse_event_timestamp(timestamp, "windows"),
                        "status": status,
                        "ip": ip,
                        "username": username,
                        "service": "winlogon",
                        "host": host,
                        "log_type": "windows",
                        "ip_context": classify_ip_context(ip),
                    }
                )
                continue

        print(f"[!] Unsupported log line skipped: {line}")

    return events


# === Raw .evtx parsing support ===
def parse_evtx(file_path: Path) -> list[dict]:
    """
    Parse raw Windows .evtx Security logs and normalize supported authentication
    events into the same event structure used by the detection engine.

    Currently supported Event IDs:
    - 4625: Failed logon
    - 4624: Successful logon
    """

    if Evtx is None:
        print("[!] Raw .evtx parsing requires the python-evtx package.")
        print("[!] Install it with: pip install python-evtx")
        raise SystemExit(1)

    events = []
    namespace = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

    try:
        with Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                except ET.ParseError:
                    continue

                event_id_text = root.findtext(
                    "./ev:System/ev:EventID", namespaces=namespace)
                if event_id_text is None:
                    continue

                try:
                    event_id = int(event_id_text)
                except ValueError:
                    continue

                if event_id not in {WINDOWS_FAILED_EVENT_ID, WINDOWS_SUCCESS_EVENT_ID}:
                    continue

                time_node = root.find(
                    "./ev:System/ev:TimeCreated", namespaces=namespace)
                timestamp = ""
                if time_node is not None:
                    timestamp = time_node.attrib.get("SystemTime", "")

                host = root.findtext(
                    "./ev:System/ev:Computer", default="windows-host", namespaces=namespace)

                event_data = {}
                for data_node in root.findall("./ev:EventData/ev:Data", namespaces=namespace):
                    name = data_node.attrib.get("Name")
                    if name:
                        event_data[name] = (data_node.text or "").strip()

                ip = event_data.get("IpAddress", "").strip()
                username = event_data.get("TargetUserName", "").strip()

                if not ip or ip in {"-", "::1", "127.0.0.1"} or not username:
                    continue

                status = "FAIL" if event_id == WINDOWS_FAILED_EVENT_ID else "SUCCESS"
                events.append(
                    {
                        "timestamp": timestamp,
                        "parsed_time": parse_event_timestamp(timestamp, "windows"),
                        "status": status,
                        "ip": ip,
                        "username": username,
                        "service": "winlogon",
                        "host": host,
                        "log_type": "windows_evtx",
                        "ip_context": classify_ip_context(ip),
                    }
                )

    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        raise SystemExit(1)
    except Exception as exc:
        print(f"[!] Failed to parse .evtx file: {exc}")
        raise SystemExit(1)

    return events


def add_finding(findings_by_ip: dict, ip: str, severity: str, finding_type: str, details: str) -> None:
    findings_by_ip[ip]["findings"].append(
        {
            "type": finding_type,
            "severity": severity,
            "details": details,
        }
    )

    current = findings_by_ip[ip]["max_severity"]
    if SEVERITY_ORDER[severity] > SEVERITY_ORDER[current]:
        findings_by_ip[ip]["max_severity"] = severity


def detect_anomalies(
    events: list[dict],
    bad_ips: set[str],
    bf_threshold: int,
    spray_threshold: int,
    success_after_fail_threshold: int,
    time_window_minutes: int,
) -> dict:
    findings_by_ip = defaultdict(
        lambda: {"findings": [], "max_severity": "LOW"}
    )

    events_by_ip = defaultdict(list)
    failed_events_by_ip_host_user = defaultdict(list)
    failed_events_by_ip_host = defaultdict(list)
    success_events_by_ip_host_user = defaultdict(list)
    ip_context_by_ip = {}

    for event in events:
        ip = event["ip"]
        host = event["host"]
        status = event["status"]
        username = event["username"]
        parsed_time = event.get("parsed_time")

        events_by_ip[ip].append(event)
        ip_context_by_ip[ip] = event.get("ip_context", classify_ip_context(ip))

        if status == "FAIL":
            failed_events_by_ip_host_user[(
                ip, host, username)].append(parsed_time)
            failed_events_by_ip_host[(ip, host)].append(
                (parsed_time, username))
        elif status == "SUCCESS":
            success_events_by_ip_host_user[(
                ip, host, username)].append(parsed_time)

    for ip, ip_events in events_by_ip.items():
        ip_context = ip_context_by_ip.get(ip, "unknown")
        touched_hosts = sorted({event["host"] for event in ip_events})

        if ip in bad_ips:
            add_finding(
                findings_by_ip,
                ip,
                "CRITICAL",
                "IOC Match",
                f"IP {ip} is present in the IOC list ({ip_context} source); hosts involved: {', '.join(touched_hosts)}"
            )

        # Brute force: same IP + same host + same username, many failures within time window
        for (candidate_ip, host, username), fail_times in failed_events_by_ip_host_user.items():
            if candidate_ip != ip:
                continue

            valid_fail_times = sorted(
                time for time in fail_times if time is not None)
            if not valid_fail_times:
                continue

            left = 0
            max_fail_count = 0
            for right in range(len(valid_fail_times)):
                while left <= right and not within_minutes(valid_fail_times[left], valid_fail_times[right], time_window_minutes):
                    left += 1
                max_fail_count = max(max_fail_count, right - left + 1)

            if max_fail_count >= bf_threshold:
                severity = "HIGH"
                add_finding(
                    findings_by_ip,
                    ip,
                    severity,
                    "Brute Force",
                    f"{max_fail_count} failed logins against user '{username}' on host '{host}' within {time_window_minutes} minutes ({ip_context} source)",
                )

        # === Password spraying: same IP + same host, many different usernames within time window ===
        for (candidate_ip, host), failed_entries in failed_events_by_ip_host.items():
            if candidate_ip != ip:
                continue

            valid_entries = sorted(
                (time, username)
                for time, username in failed_entries
                if time is not None
            )
            if not valid_entries:
                continue

            left = 0
            max_unique_users = 0
            best_users: set[str] = set()
            user_window_counts = defaultdict(int)

            for right, (right_time, right_username) in enumerate(valid_entries):
                user_window_counts[right_username] += 1

                while left <= right and not within_minutes(valid_entries[left][0], right_time, time_window_minutes):
                    left_username = valid_entries[left][1]
                    user_window_counts[left_username] -= 1
                    if user_window_counts[left_username] == 0:
                        del user_window_counts[left_username]
                    left += 1

                current_user = set(user_window_counts.keys())
                if len(current_user) > max_unique_users:
                    max_unique_users = len(current_user)
                    best_users = current_user.copy()

            if max_unique_users >= spray_threshold:
                severity = "MEDIUM" if ip_context == "external" else "HIGH"
                add_finding(
                    findings_by_ip,
                    ip,
                    severity,
                    "Password Spraying",
                    f"Targeted {max_unique_users} usernames on host '{host}' within {time_window_minutes} minutes ({ip_context} source): {', '.join(sorted(best_users))}",
                )

        # === Suspicious success: same IP + same host + same username, success shortly after failures ===
        for (candidate_ip, host, username), success_times in success_events_by_ip_host_user.items():
            if candidate_ip != ip:
                continue

            fail_times = sorted(
                time for time in failed_events_by_ip_host_user.get((ip, host, username), [])
                if time is not None
            )
            valid_success_times = sorted(
                time for time in success_times if time is not None)

            if not fail_times or not valid_success_times:
                continue

            suspicious = False
            max_fail_before_success = 0

            for success_time in valid_success_times:
                fail_count = sum(
                    1
                    for fail_time in fail_times
                    if fail_time <= success_time and within_minutes(fail_time, success_time, time_window_minutes)
                )
                max_fail_before_success = max(
                    max_fail_before_success, fail_count)
                if fail_count >= success_after_fail_threshold:
                    suspicious = True
                    break

            if suspicious:
                severity = "HIGH" if ip_context == "external" else "CRITICAL"
                add_finding(
                    findings_by_ip,
                    ip,
                    severity,
                    "Suspicious Login Success",
                    f"Successful login for user '{username}' on host '{host}' after {max_fail_before_success} failures within {time_window_minutes} minutes ({ip_context} source)",
                )

        if len(touched_hosts) > 1:
            has_failures = any(
                event["status"] == "FAIL"
                for event in ip_events
            )

            if ip_context == "internal":
                severity = "CRITICAL" if has_failures else "MEDIUM"
            else:
                severity = "HIGH" if has_failures else "MEDIUM"

            add_finding(
                findings_by_ip,
                ip,
                severity,
                "Multi-Host Targeting",
                f"{ip_context.capitalize()} IP {ip} generated authentication activity across multiple hosts: {', '.join(touched_hosts)}",
            )

    return findings_by_ip


# === Reporting and Main Entrypoint ===
def print_report(findings_by_ip: dict) -> None:
    if not findings_by_ip:
        print("[+] No suspicious activity detected.")
        return

    print("\n=== SOC ANALYSIS REPORT ===\n")

    sorted_findings = sorted(
        findings_by_ip.items(),
        key=lambda item: (SEVERITY_ORDER[item[1]["max_severity"]], item[0]),
        reverse=True,
    )

    for ip, data in sorted_findings:
        print(f"IP: {ip}")
        print(f"Max Severity: {data['max_severity']}")

        for finding in data["findings"]:
            print(
                f"  - [{finding['severity']}] {finding['type']}: {finding['details']}")

        print("-" * 40)


def generate_json_report(findings_by_ip: dict) -> dict:
    return {
        "summary": {
            "total_flagged_ips": len(findings_by_ip),
        },
        "results": {
            ip: {
                "max_severity": data["max_severity"],
                "findings": data["findings"],
            }
            for ip, data in findings_by_ip.items()
        },
    }


def main() -> None:
    args = parse_args()

    log_path = Path(args.log)
    ioc_ips = load_iocs(Path(args.ioc)) if args.ioc else set()

    if log_path.suffix.lower() == ".evtx":
        events = parse_evtx(log_path)
    else:
        log_lines = load_lines(log_path)
        events = parse_logs(log_lines)

    findings = detect_anomalies(
        events,
        ioc_ips,
        args.bf_threshold,
        args.spray_threshold,
        args.success_after_fail_threshold,
        args.time_window_minutes,
    )

    if args.json:
        json_report = generate_json_report(findings)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(json_report, f, indent=4)
            print(f"[+] JSON report saved to {args.output}")
        else:
            print(json.dumps(json_report, indent=4))
    else:
        print_report(findings)


if __name__ == "__main__":
    main()
