#!/usr/bin/env python3
"""CDP-üzenetek passzív lehallgatása (platform, port, IOS-verzió) + Telnet-próba.

Futtatás: sudo python3 cdp_telnet_recon.py eth0 10.0.99.1
"""
import socket, sys
from scapy.all import sniff, Ether

def parse_cdp(pkt):
    print(f"[+] CDP-keret: {pkt.src} -> {pkt.dst}, {len(pkt)} bájt")
    print(pkt.summary())

def telnet_probe(ip):
    print(f"[*] Telnet-próba: {ip}:23 ...")
    try:
        s = socket.create_connection((ip, 23), timeout=3)
        print(f"[!] NYITOTT TELNET: {s.recv(100)!r}")
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        print("[+] Telnet zárva/elutasítva — jó.")

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    mgmt_ip = sys.argv[2] if len(sys.argv) > 2 else None
    if mgmt_ip:
        telnet_probe(mgmt_ip)
    print(f"[*] CDP-figyelés a(z) {iface}-n (30 mp)...")
    sniff(iface=iface, lfilter=lambda p: Ether in p and p[Ether].type == 0x2000,
          prn=parse_cdp, store=0, timeout=30)

if __name__ == "__main__":
    main()
