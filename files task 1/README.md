# 🛰️ NetSentinel — Basic Network Sniffer & Traffic Analyzer

**CodeAlpha Cyber Security Internship — Task 1**

> A Python-based packet sniffer that captures and analyzes live network traffic, flags suspicious activity in real time, and exports clean session reports — built to go beyond the basic brief with a threat-heuristics layer and a zero-setup demo mode.

![Mode](https://img.shields.io/badge/mode-LIVE%20%7C%20DEMO-blue)
![Language](https://img.shields.io/badge/language-Python%203-yellow)
![Status](https://img.shields.io/badge/status-Completed-success)

---

## 📸 Screenshot — Tool in Action

![NetSentinel terminal output](screenshots/screenshot_task1_sniffer.png)

*Live demo run capturing 20 packets — color-coded by protocol, with one suspicious FTP packet auto-flagged in red.*

---

## 📌 Task Brief (from CodeAlpha)

> Build a Python program to capture network traffic packets, analyze captured packets to understand structure/content, and display source/destination IPs, protocols, and payload info using `scapy` or `socket`.

This project fulfills that brief **and adds extra engineering** described below.

---

## ✨ What Makes This Implementation Stand Out

Most basic sniffers just print raw packets. NetSentinel goes a step further:

| # | Feature | Why it matters |
|---|---------|-----------------|
| 1 | **Color-coded live terminal dashboard** | Instantly distinguish TCP/UDP/ICMP traffic at a glance — zero extra dependencies, pure ANSI. |
| 2 | **Threat Heuristics Engine** | Auto-flags traffic on known risky ports (FTP 21, Telnet 23, SMB 445, RDP 3389, Metasploit 4444, etc.) — turns a "sniffer" into a lightweight **intrusion-awareness tool**. |
| 3 | **Protocol statistics + visual bar chart** | A live session summary shows protocol distribution as ASCII bar graphs — no extra plotting libraries needed. |
| 4 | **Dual export (CSV + JSON)** | Every session auto-saves to both formats so the captured data can be opened in Excel/Wireshark-style tools or fed into other scripts. |
| 5 | **Built-in DEMO MODE** | Generates realistic, statistically-varied synthetic traffic so the tool can be **graded, screen-recorded, or demoed on any machine** — no root access, no live NIC, no firewall hassles. This is the mode used for the screenshot above. |
| 6 | **Graceful interrupt handling** | `Ctrl+C` during a live capture still produces a complete summary report instead of crashing. |

---

## 🧠 How It Works

```
                ┌────────────────────┐
                │   Packet Source    │
                │ (scapy live NIC OR │
                │   demo generator)  │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │   analyze_packet() │  → parses proto / IP / port / length
                └─────────┬──────────┘
                          │
              ┌───────────┼────────────┐
              ▼           ▼            ▼
        Terminal log   Threat check   Stats counter
        (color print)  (risky ports)  (Counter())
              │           │            │
              └─────┬─────┴─────┬──────┘
                    ▼            ▼
              Session Summary  CSV/JSON Export
```

---

## ⚙️ Setup

```bash
git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

> `scapy` is only required for **live** capture mode. Demo mode needs nothing beyond the Python standard library.

---

## ▶️ Usage

### Option A — Demo Mode (recommended for quick testing / grading, no root needed)
```bash
python3 sniffer.py --demo --count 25
```

### Option B — Live Capture (real traffic, requires admin/root privileges)
```bash
# Linux / macOS
sudo python3 sniffer.py --iface eth0 --count 50

# Windows (run terminal as Administrator)
python sniffer.py --iface "Wi-Fi" --count 50
```

### All CLI options
| Flag | Description | Default |
|------|--------------|---------|
| `--demo` | Run with synthetic traffic, no NIC/root required | off |
| `--iface` | Network interface to sniff on (live mode) | none |
| `--count` | Number of packets to capture before stopping | 25 |
| `--out` | Base filename for exported CSV/JSON logs | `capture` |

---

## 📂 Sample Output

A real session log produced by the program is included in [`sample_output/`](sample_output):
- [`capture.csv`](sample_output/capture.csv)
- [`capture.json`](sample_output/capture.json)

Example terminal line:
```
[07:14:22] UDP   192.168.1.254   :29626 -> :21 -> 182.162.158.173 len=224   ⚠ SUSPICIOUS (FTP (unencrypted))
```

End-of-session summary:
```
============================================================
 SESSION SUMMARY
============================================================
 Duration        : 0.61s
 Packets captured: 20
 Total bytes     : 15420
 Suspicious hits : 1
 Protocol breakdown:
   TCP    9     █████████████
   ICMP   8     ████████████
   UDP    3     ████
============================================================
```

---

## 🧩 Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py              # Main program (live + demo modes)
├── requirements.txt        # Python dependencies
├── README.md                # This report
├── screenshots/
│   └── screenshot_task1_sniffer.png
└── sample_output/
    ├── capture.csv
    └── capture.json
```

---

## 🔐 Concepts Demonstrated

- Network protocol structure (Ethernet → IP → TCP/UDP/ICMP)
- Source/destination addressing & port-based service identification
- Basic threat-intelligence heuristics (risky port detection)
- Packet statistics and traffic-pattern analysis
- Secure-by-design CLI tooling (no hardcoded secrets, no destructive actions)

## ⚖️ Ethical & Legal Disclaimer

This tool is built strictly for **educational purposes** as part of the CodeAlpha internship.
Only run packet capture on networks/devices you **own or are explicitly authorized** to monitor.
Unauthorized interception of network traffic is illegal in most jurisdictions (e.g., under wiretapping
and computer-misuse laws). The author and CodeAlpha are not responsible for any misuse of this tool.

---

## 🙋 About This Submission

- **Internship**: Cyber Security, CodeAlpha
- **Task**: Task 1 — Basic Network Sniffer
- **Tech stack**: Python 3, `scapy` (optional, for live capture), standard library only for demo mode

If you found this useful, feel free to ⭐ the repo!
