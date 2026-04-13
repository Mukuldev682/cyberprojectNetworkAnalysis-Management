A Network Investigation & Management Toolkit designed to simplify packet capture, filtering, traffic analysis, and anomaly detection using automation scripts built on top of Wireshark utilities.

This project helps students, security analysts, and networking professionals analyze network traffic efficiently and generate clear reports.

📌 Table of Contents
Project Overview
Features
Technology Stack
System Architecture
Folder Structure
Installation
Usage
Screenshots
Project Timeline
Team Members
Future Improvements
License
📖 Project Overview

NetScope simplifies network traffic analysis by integrating Wireshark utilities with automation scripts.

It allows users to:

Capture network packets
Filter specific traffic
Analyze protocols
Detect suspicious patterns
Generate easy-to-read reports

The goal is to make network investigation easier and faster while also serving as an educational tool for learning networking concepts.

🚀 Features

✅ Automated network packet capture
✅ Advanced filtering using scripts
✅ Protocol-level traffic inspection
✅ Anomaly detection in network traffic
✅ CSV/Text report generation
✅ Beginner-friendly network learning tool

🛠 Technology Stack
Category	Tools Used
Packet Analysis	Wireshark, Tshark
Programming	Python, Bash
Platform	Linux
Interface	CLI / Basic GUI
Reporting	CSV, Text Files
🏗 System Architecture
Network Traffic
       │
       ▼
Packet Capture (Wireshark / Tshark)
       │
       ▼
Automation Scripts (Python / Bash)
       │
       ▼
Traffic Filtering & Analysis
       │
       ▼
Anomaly Detection
       │
       ▼
Report Generation (CSV / TXT)
📂 Project Folder Structure
NetScope
│
├── scripts
│   ├── capture.sh
│   ├── filter_packets.py
│   └── anomaly_detection.py
│
├── reports
│   ├── traffic_summary.csv
│   └── anomaly_report.txt
│
├── data
│   └── captured_packets.pcap
│
├── docs
│   └── project_documentation.pdf
│
├── screenshots
│   ├── capture.png
│   ├── filtering.png
│   └── report.png
│
└── README.md
⚙️ Installation
1️⃣ Clone the Repository
git clone https://github.com/yourusername/netscope.git
cd netscope
2️⃣ Install Dependencies

Install Wireshark and Tshark:

sudo apt install wireshark tshark

Install Python dependencies:

pip install pandas scapy
▶️ Usage
1️⃣ Capture Network Traffic
bash scripts/capture.sh
2️⃣ Filter Packets
python scripts/filter_packets.py
3️⃣ Detect Network Anomalies
python scripts/anomaly_detection.py
4️⃣ Generate Reports

Reports will be saved in the reports folder.

🖼 Screenshots
Packet Capture
<img src="screenshots/capture.png" width="700">
Traffic Filtering
<img src="screenshots/filtering.png" width="700">
Generated Report
<img src="screenshots/report.png" width="700">


🔮 Future Improvements
Real-time network monitoring dashboard
AI-based anomaly detection
Web-based visual analytics interface
Support for large-scale enterprise networks
📜 License

This project is developed for educational and academic purposes.
