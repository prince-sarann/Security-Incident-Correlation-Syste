# Security Incident Correlation System

A beginner-friendly **C++17 cybersecurity simulator** that processes simulated security events, groups activity by source IP, applies simple correlation rules, and prioritizes suspicious incidents.

> Educational project only. It does not monitor networks, scan devices, or connect to real security systems.

## Features

- Process events in FIFO order using a **Queue**
- Group events by source IP using an **unordered map (hash table)**
- Count failed logins and distinct usernames targeted
- Score suspicious activity with explainable correlation rules
- Prioritize incidents with a **Priority Queue**
- Display recent event IDs with a **Stack**
- Search an event by ID using a **Binary Search Tree (BST)**
- Run a built-in demo or add custom simulated events

## Data Structures and Complexity

| Data structure | Purpose | Typical complexity |
|---|---|---|
| Queue | FIFO event processing | O(1) per push/pop |
| Unordered map | Group events and count failed logins by IP | Average O(1) lookup/update |
| Set | Count distinct usernames | O(log n) insertion |
| Priority queue | Show highest-scoring incident first | O(log k) push/pop |
| Stack | Keep recent event IDs | O(1) push/pop |
| Binary Search Tree | Search event by ID | Average O(log n), worst O(n) |

Here, n is the number of events and k is the number of flagged IP addresses. Actual performance depends on input and implementation.

## Correlation Rules

For events sharing the same source IP:

| Condition | Risk points |
|---|---:|
| 3 or more failed login events | +3 |
| Failed logins targeting 3 or more distinct usernames | +2 |
| A critical event: malware_detected, privilege_escalation, or ransomware_alert | +4 |

Severity levels:
- **CRITICAL:** score 6 or higher
- **HIGH:** score 4–5
- **MEDIUM:** score 2–3
- **LOW:** score below 2

Only IP groups with a positive score are reported. These thresholds are illustrative, not real-world security policy. This version groups the loaded dataset by IP; it does not implement a sliding time window.

## Requirements

- A C++ compiler supporting **C++17** (G++, Clang, or a recent Visual C++ toolchain)

## Run Locally

### 1. Clone the repository

    git clone https://github.com/prince-sarann/Security-Incident-Correlation-Syste.git
    cd Security-Incident-Correlation-Syste

### 2. Compile

Linux, macOS, or Windows with MinGW:

    g++ -std=c++17 -Wall -Wextra -pedantic src/main.cpp -o incident-correlation

### 3. Run

Linux/macOS:

    ./incident-correlation

Windows (MinGW):

    incident-correlation.exe

Choose **1** for the built-in demo or **2** to add up to 50 custom simulated events. To trigger the failed-login rules, use the same source IP for at least three failed_login events and use three distinct usernames.

## Expected Demo Findings

- **192.168.1.20:** repeated failed logins and multiple usernames targeted
- **172.16.0.9:** critical event types detected

Exact formatting may vary by terminal/compiler.

## Screenshots

After running the program, upload your real terminal screenshots to a folder named screenshots, then uncomment and update the Markdown image paths below.

<!--
![Program menu](screenshots/menu.png)
![Correlated incident report](screenshots/incident-report.png)
-->

## Project Structure

    Security-Incident-Correlation-Syste/
    ├── src/
    │   └── main.cpp
    ├── screenshots/
    │   └── (add screenshots here)
    ├── .gitignore
    └── README.md

## Limitations and Future Improvements

- Uses simulated input; it does not ingest real operating-system or network logs.
- No authentication, persistent database, or external alerting.
- Correlation is performed across the loaded dataset, not a real-time time window.
- Future improvements: CSV import, configurable rules, unit tests, and time-window correlation.

## Author

**Prince Kumar Saran** · [GitHub](https://github.com/prince-sarann)

---

Built as a student project to practice data structures and cybersecurity fundamentals.
