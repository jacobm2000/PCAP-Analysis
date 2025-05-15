# PCAP Summary

A lightweight, GUI-based Python application for performing basic analysis of `.pcap` (packet capture) files. This tool summarizes protocol usage, top IPs, ports, and common application-layer traffic like HTTP, DNS, SSH, and more.

---

## Features
- Can Take 1 or multiple .pcap files as input
- Analyze `.pcap` files using Scapy
- Summarizes:
  - Top 5 Protocols (e.g., TCP, UDP, ICMP, ARP)
  - Top Source IPs
  - Top Destination IPs
  - Top Source Ports
  - Top Destination Ports
  - Top Application-Layer Services (e.g., HTTP, SSH, DNS)
- Save summaries to text file
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
Total packets: 327

Top Protocols
    TCP: 215 (65.75%)
    UDP: 68 (20.8%)
    ARP: 24 (7.34%)
    ICMP: 15 (4.59%)
    Unknown(89): 5 (1.53%)

Top Source IPs
    192.168.1.10: 120 (36.7%)
    192.168.1.1: 58 (17.74%)
    8.8.8.8: 45 (13.76%)
    10.0.0.5: 30 (9.17%)
    172.16.0.2: 22 (6.73%)

Top Destination IPs
    192.168.1.1: 112 (34.26%)
    192.168.1.10: 89 (27.22%)
    8.8.4.4: 50 (15.29%)
    10.0.0.1: 40 (12.23%)
    172.16.0.1: 25 (7.65%)

Top Source Ports
    443: 98 (29.97%)
    80: 62 (18.96%)
    53: 50 (15.29%)
    22: 35 (10.7%)
    12345: 20 (6.12%)

Top Destination Ports
    443: 105 (32.11%)
    80: 59 (18.04%)
    53: 48 (14.68%)
    22: 33 (10.09%)
    3389: 21 (6.42%)

Top Application Ports
    HTTPS: 203 (62.39%)
    HTTP: 121 (37.01%)
    DNS: 98 (29.97%)
    SSH: 68 (20.8%)
    RDP: 21 (6.42%)

```



## License

This project is licensed under the MIT License. You are free to use, modify, and distribute it.
