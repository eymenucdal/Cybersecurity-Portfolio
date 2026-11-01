# SOC Log Analyzer

A Python-based SOC detection tool that simulates real-world SIEM behavior by analyzing authentication logs across multiple platforms (SSH and Windows) and identifying attack patterns such as brute forcing, password spraying, and lateral movement techniques.

This project focuses on detection engineering principles, including log normalization, time-based correlation, and context-aware alerting, inspired by real SOC workflows.

---

## Features

- IOC (Indicator of Compromise) matching
- Brute force detection using time-based thresholds
- Password spraying detection based on multi-user targeting
- Suspicious login success detection (fail → success correlation)
- Multi-host targeting detection
- Context-aware severity classification (internal vs external IPs)
- Structured per-IP reporting
- Support for multiple log formats:
  - SSH logs (`auth.log`)
  - Windows logs (JSONL)
  - EVTX (Windows Event Logs)
- Optional JSON output for integration with other tools

---

## Detection Logic

The tool analyzes authentication logs and applies the following detection rules:

| Detection Type           | Description                                                     |
|--------------------------|-----------------------------------------------------------------|
| IOC Match                | Flags IPs found in the provided IOC list                        |
| Brute Force              | Multiple failed login attempts within a defined time window     |
| Password Spraying        | Multiple usernames targeted by the same IP within a time window |
| Suspicious Login Success | Successful login following repeated failed attempts             |
| Multi-Host Targeting     | Same IP targeting multiple hosts                                |

Each IP is assigned a maximum severity level based on detected activity.

---

## Project Structure

```
soc-analyzer/
├── README.md
├── src/
│   └── main.py
├── sample_logs/
│   ├── auth.log
│   └── windows_auth.jsonl
└── iocs/
    └── bad_ips.txt
```

---

## Requirements

- Python 3.10 or newer (uses `X | Y` type unions)
- No third-party packages for SSH and JSONL input
- Raw `.evtx` input additionally requires `python-evtx`:

```bash
pip install python-evtx
```

---

## Usage

Run the tool from the `soc-analyzer/` directory:

```bash
python3 src/main.py -l sample_logs/auth.log
```

```bash
# With IOC enrichment (optional)
python3 src/main.py -l sample_logs/auth.log -i iocs/bad_ips.txt
```

```bash
# Windows JSONL sample
python3 src/main.py -l sample_logs/windows_auth.jsonl -i iocs/bad_ips.txt
```

### JSON output

```bash
python3 src/main.py -l sample_logs/auth.log -i iocs/bad_ips.txt --json
```

### Save JSON output to a file

```bash
python3 src/main.py -l sample_logs/auth.log -i iocs/bad_ips.txt --json --output results.json
```

---

## Arguments

| Argument                         | Description                                        |
|----------------------------------|----------------------------------------------------|
| `-l`, `--log`                    | Path to log file (SSH / JSONL / EVTX)              |
| `-i`, `--ioc`                    | (Optional) Path to IOC list (one IP per line)      |
| `--bf-threshold`                 | Threshold for brute force detection                |
| `--spray-threshold`              | Threshold for password spraying detection          |
| `--success-after-fail-threshold` | Fail count before success is considered suspicious |
| `--time-window-minutes`          | Time window used for correlation                   |
| `--json`                         | Output results in JSON format                      |
| `--output`                       | Save JSON output to file                           |

---

## Sample Data

The repository includes sample data demonstrating various attack scenarios:

### SSH Logs (`auth.log`)
- Brute force attempts
- Password spraying
- Suspicious login success patterns
- Multi-host targeting
- Normal internal activity

### Windows Logs (`windows_auth.jsonl`)
- Simulated Windows authentication events
- Event IDs:
  - `4625` — Failed login
  - `4624` — Successful login

### IOC List (`bad_ips.txt`)
- Optional list of known malicious IP addresses used for IOC enrichment

---

## Example Output

```
=== SOC ANALYSIS REPORT ===

IP: 185.10.10.10
Max Severity: CRITICAL
  - [HIGH] Brute Force: 5 failed login attempts detected
  - [CRITICAL] Suspicious Login Success: Successful login after multiple failures
----------------------------------------
```

---

## Technologies Used

- Python 3
- Standard libraries:
  - argparse
  - ipaddress
  - collections
  - pathlib
  - json
  - re

---

## Future Improvements

- MITRE ATT&CK mapping for detections
- Real-time log monitoring
- Integration with SIEM platforms (e.g., Splunk, Microsoft Sentinel)
- Web-based dashboard for visualization
- Risk scoring and alert prioritization

---

## Notes

This project demonstrates:

- Log parsing and normalization across different platforms
- Detection engineering principles
- Time-based correlation logic
- Security-focused Python development

---

## Author

Eymen Ucdal  
MSc Cybersecurity Engineering student, Riga Technical University (RTU); BSc Computer Systems (RTU, 2026)  
HTB Certified Penetration Testing Specialist (CPTS), October 2026
