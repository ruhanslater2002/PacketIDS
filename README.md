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
