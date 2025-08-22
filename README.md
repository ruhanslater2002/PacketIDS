Intrusion Detection System (IDS)

This Python-based Intrusion Detection System (IDS) is designed to monitor network traffic and detect potential scanning activities, including port scans and ICMP (ping) scans, in real time. The system analyzes packets on a specified network interface and identifies suspicious behaviors based on customizable thresholds.

Monitors TCP and ICMP traffic on a specified network interface using Scapy.
Identifies and logs suspicious network activity, such as:

    Port Scans (detects multiple ports being accessed by the same source IP).
    ICMP Scans (detects excessive ping requests).

Installation:

    pip install -r requirements.txt

Usage:

    python main.py -st <scan_threshold> -tw <time_window> -if <interface>

Example:

    python main.py -st 30 -tw 15 -if "Ethernet"

<img width="517" height="169" alt="{BFF98B30-99F5-432E-BF79-7B5627FD9CA3}" src="https://github.com/user-attachments/assets/934d0359-686c-48a3-8179-94838e062f2f" />
<img width="1048" height="231" alt="{AE738BEF-411B-403B-A8BD-8EDD650684BB}" src="https://github.com/user-attachments/assets/3377efce-22d8-4929-b3e9-046b443d548c" />
