# Cybersecurity Portfolio

This repository contains my cybersecurity projects, including detection tools, machine learning-based attack analysis, and hands-on penetration testing write-ups.

## About Me

Eymen Ucdal
MSc student in Cybersecurity Engineering – Riga Technical University (RTU)

I am building my career in cybersecurity with a strong interest in penetration testing and red teaming, while also developing skills on the defensive side such as detection engineering and SOC analysis. My goal is to keep improving from both the attacker and defender perspective and apply that knowledge in real-world environments.

## Projects

Each project in this portfolio is built with a focus on practical application, real-world scenarios, and clear technical reasoning.

### 1. SOC Authentication Anomaly Detector

A Python-based tool designed to analyze authentication logs and detect suspicious behavior.

**Features:**
- Brute force detection
- Password spraying detection
- Suspicious login success correlation
- Multi-host targeting detection
- IOC (Indicator of Compromise) matching
- Support for SSH `auth.log`, Windows JSONL, and raw `.evtx` authentication logs

**Location:**
`soc-analyzer/`

---

### 2. Credential Stuffing Detection (Machine Learning)

Code and results from my bachelor's thesis at RTU (2026), "Optimization of Machine Learning-Based Detection of Credential Stuffing Attacks in Payment Gateways", using the IEEE-CIS Fraud Detection dataset as a proxy for credential-stuffing abuse.

**Key Components:**
- Data preprocessing and feature engineering
- Random Forest model (baseline + optimized)
- Hyperparameter tuning
- Evaluation metrics (Precision, Recall, F1, ROC-AUC)
- SHAP-based model explainability
- Threshold tuning and operational policy simulation

**Location:**
`credential-stuffing-detection/`

---

### 3. Penetration Testing Write-Ups (Hack The Box)

Report-style write-ups of retired Hack The Box machines, written from my own lab work.

**Currently included:**
- `cap-writeup/` – Cap (Linux): IDOR leading to credential disclosure, privilege escalation via a misconfigured Linux capability
- `support-writeup/` – Support (Windows Domain Controller): credential recovery from a client binary, LDAP enumeration, BloodHound analysis, escalation to SYSTEM via a delegation misconfiguration

Each write-up covers enumeration, exploitation, privilege escalation, and remediation notes, with screenshots.

**Location:**
`htb-writeups/`

---

## Technical Focus

**Offensive Security:**
- Penetration testing (HTB Certified Penetration Testing Specialist, CPTS, October 2026)
- Active Directory attacks and lateral movement
- Privilege escalation (Windows & Linux)
- Web application testing (enumeration, authentication, injection)

**Defensive Security:**
- Authentication log parsing and normalization (SSH, Windows)
- Rule-based detection logic (brute force, spraying, fail-to-success correlation)
- Supervised ML classification for abuse detection (Random Forest, SHAP, calibration)

**Programming & Systems:**
- Python (automation, data analysis, detection logic)
- Bash (scripting and enumeration workflows)
- Linux / Windows environments

## Current Focus

- HTB Certified Web Exploitation Specialist (CWES) path, exam planned for December 2026
- Python and backend fundamentals refresh
- Cloud and Kubernetes security fundamentals
- Looking for a first security role or internship alongside the MSc

## Future Improvements

- Expand detection logic in the SOC tool (behavior-based detection, correlation improvements)
- Add more write-ups from retired machines and lab environments
- Improve the ML model with additional features and datasets
- Develop additional security tools

## Notes

This portfolio is continuously evolving as I learn and build new projects.

## Contact

- GitHub: https://github.com/eymenucdal
- LinkedIn: https://www.linkedin.com/in/eymenucdal
- Email: eymen.ucdal@outlook.com
