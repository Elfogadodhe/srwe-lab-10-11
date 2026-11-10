#!/usr/bin/env python3
"""DTP-keretek figyelése: ha a port 'dynamic' módban van, trunkolható.

Futtatás: sudo python3 vlan_hop_recon.py eth0
"""
import sys
from scapy.all import sniff, Ether

def show(pkt):
    if Ether in pkt:
        etype = pkt[Ether].type
        if etype == 0x2004:
            print("[!] DTP-keret látva — a port valószínűleg dynamic módban van!")
            print(pkt.summary())
        elif etype == 0x8100:
            print("[!] Tagged 802.1Q-forgalom érkezik az access porton:")
            print(pkt.summary())

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    print(f"[*] DTP- és 802.1Q-megfigyelés a(z) {iface}-n...")
    sniff(iface=iface, prn=show, store=0,
          filter="ether proto 0x2004 or ether proto 0x8100")

if __name__ == "__main__":
    main()
