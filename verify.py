#!/usr/bin/env python3
"""verify.py — Automatizált védelem-ellenőrző a SRWE 10–11 laborhoz.

27 ellenőrzés mind a 12 támadás ellen, pontszámmal és jegykalkulációval.

Használat:
    python3 verify.py inventory.yml                # ellenőrzés + pontszám
    python3 verify.py inventory.yml --verbose     # nyers kimenetekkel
    python3 verify.py inventory.yml --json out.json
    python3 verify.py inventory.yml --only S1     # csak egy eszköz

Függőségek: pip install netmiko pyyaml
Kilépési kód: 0 ha >= 60%, 1 ha alatta (CI-barát)
"""
import argparse
import json
import re
import sys
from datetime import datetime

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


# ============================================================================
# ELLENŐRZÉSI DEFINÍCIÓK
# ============================================================================
# expect: (regex, kell_illeszkedni) lista
#   (pattern, True)  -> a kimenetben KELL szerepelnie
#   (pattern, False) -> a kimenetben NEM SZABAD szerepelnie
# alt_cmd / alt_expect: tartalék parancs, ha az elsődleges nem támogatott

CHECKS = [
    # ---------- 1-2. MAC flooding / MAC spoofing -> PORT SECURITY ----------
    {
        "id": "s1-portsec-status",
        "device": "S1",
        "cmd": "show port-security",
        "expect": [(r"SecurePort\s+MaxSecureAddr\s+CurrentAddr", True),
                   (r"Fa0/1", True), (r"Fa0/3", True)],
        "points": 8,
        "attack": "1-2. MAC flooding / MAC spoofing",
    },
    {
        "id": "s1-portsec-attacker-shutdown",
        "device": "S1",
        "cmd": "show port-security interface fa0/3",
        "expect": [(r"Port Security\s*:\s*Enabled", True),
                   (r"Violation Mode\s*:\s*Shutdown", True),
                   (r"Maximum MAC Addresses\s*:\s*1", True)],
        "points": 8,
        "attack": "1-2. MAC flooding / MAC spoofing",
    },
    {
        "id": "s1-portsec-sticky",
        "device": "S1",
        "cmd": "show port-security interface fa0/1",
        "expect": [(r"Port Security\s*:\s*Enabled", True),
                   (r"Sticky MAC Addresses\s*:\s*[1-9]", True)],
        "points": 5,
        "attack": "2. MAC spoofing",
    },
    {
        "id": "s2-portsec-status",
        "device": "S2",
        "cmd": "show port-security",
        "expect": [(r"SecurePort\s+MaxSecureAddr\s+CurrentAddr", True), (r"Fa0/1", True)],
        "points": 4,
        "attack": "1-2. MAC flooding / MAC spoofing",
    },

    # ---------- 3-4. DHCP starvation / spoofing -> DHCP SNOOPING ----------
    {
        "id": "s1-dhcp-snooping-enabled",
        "device": "S1",
        "cmd": "show ip dhcp snooping",
        "expect": [(r"Switch DHCP snooping is Enabled", True),
                   (r"(?s)configured on following VLANs:\s*\n?\s*[\d,\-\s]*\b10\b", True)],
        "points": 8,
        "attack": "3-4. DHCP starvation / spoofing",
    },
    {
        "id": "s1-dhcp-trust-ports",
        "device": "S1",
        "cmd": "show ip dhcp snooping",
        "expect": [(r"Gi0/1\s+trust", True), (r"Fa0/24\s+trust", True)],
        "points": 6,
        "attack": "4. DHCP spoofing",
    },
    {
        "id": "s1-dhcp-rate-limit",
        "device": "S1",
        "cmd": "show ip dhcp snooping",
        "expect": [(r"Fa0/3\s+\S+\s+\d+", True)],   # rate limit, nem 'unlimited'
        "points": 6,
        "attack": "3. DHCP starvation",
    },
    {
        "id": "s2-dhcp-snooping",
        "device": "S2",
        "cmd": "show ip dhcp snooping",
        "expect": [(r"Switch DHCP snooping is Enabled", True), (r"Fa0/24\s+trust", True)],
        "points": 4,
        "attack": "3-4. DHCP starvation / spoofing",
    },

    # ---------- 5. ARP poisoning -> DAI ------------------------------------
    {
        "id": "s1-dai-vlan10",
        "device": "S1",
        "cmd": "show ip arp inspection vlan 10",
        "expect": [(r"^\s*10\s+Yes", True)],
        "points": 8,
        "attack": "5. ARP poisoning",
    },
    {
        "id": "s1-dai-trust",
        "device": "S1",
        "cmd": "show ip arp inspection",
        "expect": [(r"Fa0/24\s+Trust", True)],
        "points": 5,
        "attack": "5. ARP poisoning",
    },
    {
        "id": "s1-dai-statistics",
        "device": "S1",
        "cmd": "show ip arp inspection statistics vlan 10",
        "expect": [(r"Packets Received", True), (r"Dropped", True)],
        "points": 4,
        "attack": "5. ARP poisoning",
    },

    # ---------- 6. STP manipuláció -> BPDU/ROOT GUARD ----------------------
    {
        "id": "s1-bpduguard",
        "device": "S1",
        "cmd": "show spanning-tree summary totals",
        "expect": [(r"Portfast", True), (r"BPDU Guard", True)],
        "points": 6,
        "attack": "6. STP manipuláció",
    },
    {
        "id": "s1-root-primary",
        "device": "S1",
        "cmd": "show spanning-tree vlan 10 root",
        "expect": [(r"This bridge is the root", True)],
        "alt_cmd": "show spanning-tree vlan 10",
        "alt_expect": [(r"This bridge is the root", True)],
        "points": 5,
        "attack": "6. STP manipuláció",
    },

    # ---------- 7. VLAN hopping (DTP) --------------------------------------
    {
        "id": "s1-no-dtp-access",
        "device": "S1",
        "cmd": "show interfaces fa0/3 switchport",
        "expect": [(r"Operational Mode:\s*static access", True),
                   (r"Negotiation of Trunking:\s*Off", True)],
        "points": 8,
        "attack": "7. VLAN hopping (DTP)",
    },
    {
        "id": "s1-unused-ports-down",
        "device": "S1",
        "cmd": "show interfaces status | include Fa0/(4|5|6|7)",
        "expect": [(r"disabled", True)],
        "points": 4,
        "attack": "7. VLAN hopping (DTP)",
    },

    # ---------- 8. CDP felderítés + Telnet -> HARDENING ---------------------
    {
        "id": "s1-cdp-off",
        "device": "S1",
        "cmd": "show cdp",
        "expect": [(r"CDP is not enabled", True)],
        "points": 5,
        "attack": "8. CDP felderítés",
    },
    {
        "id": "s1-ssh2-only",
        "device": "S1",
        "cmd": "show ip ssh",
        "expect": [(r"version 2", True), (r"version 1", False)],
        "points": 4,
        "attack": "8. Telnet / gyenge elérés",
    },
    {
        "id": "s1-vty-ssh-only",
        "device": "S1",
        "cmd": "show running-config | section line vty",
        "expect": [(r"transport input ssh", True),
                   (r"transport input telnet", False)],
        "points": 4,
        "attack": "8. Telnet / gyenge elérés",
    },
    {
        "id": "s2-cdp-off",
        "device": "S2",
        "cmd": "show cdp",
        "expect": [(r"CDP is not enabled", True)],
        "points": 3,
        "attack": "8. CDP felderítés",
    },
    {
        "id": "s2-vty-ssh-only",
        "device": "S2",
        "cmd": "show running-config | section line vty",
        "expect": [(r"transport input ssh", True), (r"transport input .*telnet", False)],
        "points": 3,
        "attack": "8. Telnet / gyenge elérés",
    },

    # ---------- 9. Double-tagging -> NATÍV VLAN HARDENING ------------------
    {
        "id": "s1-native-vlan-not-default",
        "device": "S1",
        "cmd": "show interfaces trunk",
        "expect": [(r"Fa0/24\s+\S+\s+\S+\s+\S+\s+999\b", True)],
        "points": 8,
        "attack": "9. 802.1Q double-tagging",
    },
    {
        "id": "s1-trunk-pruned",
        "device": "S1",
        "cmd": "show interfaces trunk",
        "expect": [(r"10,20,99", True)],
        "points": 4,
        "attack": "9. 802.1Q double-tagging",
    },

    # ---------- 10. IP spoofing -> IP SOURCE GUARD --------------------------
    {
        "id": "s1-ipsg-enabled",
        "device": "S1",
        "cmd": "show ip verify source",
        "expect": [(r"Interface\s+Filter-type\s+Filter-mode", True),
                   (r"Fa0/(1|3)\s+ip\s+active", True)],
        "points": 8,
        "attack": "10. IP spoofing",
    },
    {
        "id": "s1-source-binding",
        "device": "S1",
        "cmd": "show ip source binding",
        "expect": [(r"Fa0/1\s+dhcp\s+snooping", True)],
        "points": 4,
        "attack": "10. IP spoofing",
    },

    # ---------- 11. LLDP felderítés -----------------------------------------
    {
        "id": "s1-lldp-access-off",
        "device": "S1",
        "cmd": "show lldp interface FastEthernet0/1",
        "expect": [(r"(Tx|Rx):\s*disabled", True)],
        "alt_cmd": "show lldp",
        "alt_expect": [(r"LLDP is not enabled", True)],
        "points": 6,
        "attack": "11. LLDP felderítés",
    },

    # ---------- 12. ICMP redirect MITM --------------------------------------
    {
        "id": "r1-no-redirects",
        "device": "R1",
        "cmd": "show ip interface GigabitEthernet0/1.10 | include redirects",
        "expect": [(r"ICMP redirects are never sent", True)],
        "points": 8,
        "attack": "12. ICMP-redirect gateway MITM",
    },
    {
        "id": "r1-no-redirects-vlan20",
        "device": "R1",
        "cmd": "show ip interface GigabitEthernet0/1.20 | include redirects",
        "expect": [(r"ICMP redirects are never sent", True)],
        "points": 4,
        "attack": "12. ICMP-redirect gateway MITM",
    },
]

MAX_POINTS = sum(c["points"] for c in CHECKS)


# ============================================================================
# MOTOR
# ============================================================================

def connect(params):
    try:
        return ConnectHandler(**params), None
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        return None, str(e)


def run_check(conn, check):
    """Egy ellenőrzés futtatása. Visszatér: (passed, details, output)"""
    output = ""
    try:
        output = conn.send_command(check["cmd"], read_timeout=20)
    except Exception as e:
        if check.get("alt_cmd"):
            try:
                output = conn.send_command(check["alt_cmd"], read_timeout=20)
            except Exception:
                return False, f"parancshiba: {e}", output
        else:
            return False, f"parancshiba: {e}", output

    expects = check.get("expect", [])
    if not output.strip() and check.get("alt_cmd"):
        expects = check.get("alt_expect", expects)

    failed = []
    for pattern, should_match in expects:
        found = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
        if should_match and not found:
            failed.append(f"HIÁNYZIK: '{pattern}'")
        if not should_match and found:
            failed.append(f"TILTOTT MINTA: '{pattern}'")

    return (not failed), (" | ".join(failed) if failed else "OK"), output


def main():
    ap = argparse.ArgumentParser(description="SRWE labor védelem-ellenőrző")
    ap.add_argument("inventory", help="inventory.yml útvonala")
    ap.add_argument("--verbose", "-v", action="store_true", help="nyers kimenetek")
    ap.add_argument("--json", metavar="FILE", help="eredmény JSON fájlba")
    ap.add_argument("--only", metavar="ESZKÖZ", help="csak egy eszköz ellenőrzése")
    args = ap.parse_args()

    with open(args.inventory) as f:
        inventory = yaml.safe_load(f)

    devices = inventory["devices"]
    print("=" * 78)
    print(" SRWE 10-11 LABOR — AUTOMATIZÁLT VÉDELEM-ELLENŐRZÉS")
    print(f" Időpont: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
          f" | Elérhető pont: {MAX_POINTS}")
    print("=" * 78)

    conns = {}
    for name, params in devices.items():
        if args.only and name != args.only:
            continue
        conn, err = connect(params)
        if conn:
            conns[name] = conn
            print(f"[+] {name}: kapcsolat OK ({params['host']})")
        else:
            print(f"[!] {name}: NEM ELÉRHETŐ — {err}")

    results, earned = [], 0
    print("-" * 78)
    print(f"{'ID':<32}{'Pont':>5}  {'Eredmény':<8} Részletek")
    print("-" * 78)

    for check in CHECKS:
        dev = check["device"]
        if dev not in conns:
            print(f"{check['id']:<32}{check['points']:>5}  {'SKIP':<8} eszköz nem elérhető")
            results.append({**check, "passed": None, "details": "eszköz nem elérhető"})
            continue
        passed, details, output = run_check(conns[dev], check)
        print(f"{check['id']:<32}{check['points']:>5}  "
              f"{'Pipa' if passed else 'Hiba':<8} {details}")
        if passed:
            earned += check["points"]
        if args.verbose:
            print(f"--- {check['cmd']} ---\n{output}\n")
        results.append({**check, "passed": passed, "details": details})

    for conn in conns.values():
        conn.disconnect()

    # ------------------------------ ÖSSZESÍTÉS ------------------------------
    total = len([r for r in results if r["passed"] is not None])
    ok_cnt = len([r for r in results if r["passed"] is True])
    pct = 100.0 * earned / MAX_POINTS if MAX_POINTS else 0
    grade = (5 if pct >= 90 else 4 if pct >= 80 else 3 if pct >= 70
             else 2 if pct >= 60 else 1)
    print("-" * 78)
    print(f" Elért pont: {earned} / {MAX_POINTS}  ({pct:.1f}%)")
    print(f" Átment ellenőrzések: {ok_cnt} / {total}")
    print(f" Vélhető jegy: {grade}")
    print("=" * 78)

    print("\n Támadásonkénti fedettség:")
    by_attack = {}
    for r in results:
        by_attack.setdefault(r["attack"], []).append(r)
    for attack, checks in sorted(by_attack.items()):
        ok = sum(1 for c in checks if c["passed"] is True)
        print(f"   {attack:<48} {ok}/{len(checks)}")
        for c in checks:
            if c["passed"] is not True:
                print(f"     -> [!] {c['id']}: {c['details']}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "score": {"earned": earned, "max": MAX_POINTS,
                          "percent": round(pct, 1), "grade": grade},
                "results": [{"id": r["id"], "device": r["device"], "cmd": r["cmd"],
                             "attack": r["attack"], "points": r["points"],
                             "passed": r["passed"], "details": r["details"]}
                            for r in results],
            }, f, indent=2, ensure_ascii=False)
        print(f"\n[+] JSON mentve: {args.json}")

    sys.exit(0 if pct >= 60 else 1)


if __name__ == "__main__":
    main()
