IoT Network Visibility & Security Scanner

A lightweight IoT security visibility tool designed to discover devices on local networks, identify potential IoT assets, and detect common security risks through non-intrusive analysis.

Overview

Modern networks contain a growing number of IoT devices such as cameras, smart plugs, and home automation systems. However, many of these devices are poorly secured and difficult to monitor.

This project provides a lightweight and practical solution to:

Discover devices on a local network
Identify likely IoT devices
Detect common security misconfigurations
Present risk insights through a simple dashboard

The system is designed for small-scale environments such as homes and small offices, without requiring complex enterprise tools.

Key Features

1 Network Discovery
Scan local networks to identify active devices using Nmap

2 Device Classification
Identify likely IoT devices using MAC vendor lookup, open ports, and service fingerprints

3 Security Checks
Detect common vulnerabilities such as:
HTTP without HTTPS
Default-style login pages
Missing or weak security headers
Open or unauthenticated endpoints

4 Risk Scoring System
Assign risk levels (High / Medium / Low) based on detected issues

5 Interactive Dashboard
Visualize device information, findings, and risk levels

6 Report Export
Generate structured reports (JSON / Excel) for further analysis

7 System Architecture
User
  ↓
Desktop IoT Scanner App
  ↓
Discovery Module → Classification Module → Security Check Module
  ↓
Scoring Engine
  ↓
Dashboard & Export

8 Tech Stack
Python – Core backend logic
Flask – Web-based dashboard
Nmap – Network scanning and discovery
HTML/CSS/JS – Frontend interface
Pandas – Data processing and report generation

9 Demo

🔹 Dashboard Interface
Displays detected devices
Shows risk levels and findings
Provides actionable insights

<img width="1312" height="338" alt="image (3)" src="https://github.com/user-attachments/assets/9e204410-62ab-4dde-9287-3c20ccfc1613" />

<img width="1379" height="957" alt="image" src="https://github.com/user-attachments/assets/9451797c-9241-4d21-a8a3-c2a64c5d36fb" />


⚙️ How It Works
Scan the local network to detect active devices
Collect network data (IP, MAC, open ports, services)
Identify likely IoT devices using heuristics
Perform lightweight security checks
Assign risk scores based on findings
Display results via dashboard and export reports
📈 Results

The system successfully:

Discovered devices within a local network environment
Identified potential IoT assets
Detected common security issues (e.g., exposed services, weak configurations)
Provided a clear visualization of network security posture
🚧 Limitations
Uses heuristic-based IoT detection (not 100% accurate)
Limited to local network scanning
Does not perform deep vulnerability exploitation (non-intrusive by design)
🔮 Future Work
Integrate machine learning for improved device classification
Add real-time monitoring capabilities
Support IoT-specific policies (e.g., MUD – Manufacturer Usage Description)
Develop a mobile-friendly version
📚 References
NIST SP 1800-15 – Securing Small-Business and Home IoT Devices
ETSI EN 303 645 – Cyber Security for Consumer IoT
RFC 8520 – Manufacturer Usage Description (MUD)
👤 Author

Tran Hoang Minh
BSc (Hons) Computer Science (Cyber Security)
British University Vietnam

🔗 Project Link

👉 (https://github.com/Hminh2005-cyber/iot-visibility)
