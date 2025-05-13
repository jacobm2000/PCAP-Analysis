# Basic PCAP Analyzer

A lightweight, GUI-based Python application for performing basic analysis of `.pcap` (packet capture) files. This tool summarizes protocol usage, top IPs, ports, and common application-layer traffic like HTTP, DNS, SSH, and more.

---

## Features

- Analyze `.pcap` files using Scapy
- Summarizes:
  - Top 5 Protocols (e.g., TCP, UDP, ICMP, ARP)
  - Top Source IPs
  - Top Destination IPs
  - Top Source Ports
  - Top Destination Ports
  - Top Application-Layer Services (e.g., HTTP, SSH, DNS)
- Simple GUI built with `tkinter`
- Tabbed output for clean formatting

---

## Requirements

- Python 3.7 or higher
- Required Python packages:
  ```bash
  pip install scapy
  ```

Note: `tkinter` is typically included with Python. If it's missing, install it using your OS's package manager.

---

## How to Run

1. Save the script (e.g., `pcap_analyzer.py`).
2. Open a terminal and run:
   ```bash
   python pcap_analyzer.py
   ```
3. Click the **Open PCAP File** button and choose a `.pcap` file to analyze.

---

## Sample Output

```
Total packets: 1221

Top Protocols
    TCP: 980
    UDP: 150
    ICMP: 60
    ARP: 31

Top Source IPs
    192.168.1.1: 420
    10.0.0.5: 300

Top Destination IPs
    192.168.1.100: 390
    8.8.8.8: 210

Top Source Ports
    443: 512
    22: 330

Top Destination Ports
    80: 512
    443: 330

Top Application Ports
    HTTP: 512
    HTTPS: 330
    SSH: 100
```



## License

This project is licensed under the MIT License. You are free to use, modify, and distribute it.
