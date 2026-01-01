# SSH Log Analyzer (Python)

## Overview
This project is a SOC-style SSH log analysis tool written in Python.  
It analyzes authentication logs to detect suspicious activity such as
brute-force login attempts and repeated failed authentications.

The project demonstrates practical defensive security skills including
log analysis, pattern detection, and alert reporting.

---

## What This Tool Detects
- Multiple failed SSH login attempts from the same IP address
- Possible brute-force authentication behavior
- Successful logins following repeated failures
- High-risk source IPs based on failed attempts

---

## How It Works
1. Reads an SSH authentication log file
2. Parses failed and successful login events
3. Applies detection thresholds
4. Generates a SOC-style alert report

---

## Technologies Used
- Python
- Regular Expressions (Regex)
- Linux log analysis concepts
- SOC / defensive security fundamentals

---

## Project Structure
ssh-log-analyzer-python/
├── logs/
│   └── ssh_auth.log
├── analyzer/
│   └── ssh_log_analyzer.py
├── reports/
│   └── alerts_report.txt
└── README.md

---

## Why This Project Matters
SSH brute-force attacks are one of the most common threats monitored
by Security Operations Centers (SOC). This project shows how defenders
can identify attack patterns using log data and transform them into
actionable security alerts.

