# SRWE Modul 10–11 Labor — Teljes csomag indexe
## Összes dokumentum, script és telepítési útmutató

---

## Tartalomjegyzék

| Sorszám | Dokumentum | Célközönség | Helye a repóban |
|---|---|---|---|
| 1 | **Összevont labor könyv** (teljes labor egy könyvben, 12 támadás + védelem) | Oktató, hallgató | `docs/srwe-labor-konyv.md` |
| 2 | **Hallgatói feladatlap** (12 fázis kitöltendő) | Hallgató | `docs/hallgatoi-feladatlap.md` |
| 3 | **Reflexiós és adatvédelmi lap** (MITM/HTTP/HTTPS/DNS elemzés) | Hallgató | `docs/reflexios-lap.md` |
| 4 | **verify.py** (27 ellenőrzés, Pipa/Hiba — nem ad jegyet) | Oktató, hallgató | `verify.py` (repó gyökér) |
| 5 | **Baseline** (Telnet nyitva, sebezhető állapot) | Oktató | `configs/baseline.yml` |
| 6 | **Deployment checklist + oktatói útmutató** (ez a fájl) | Oktató | **Ebben a fájlban** |

---

## 1. Gyorsstart — 15 perces előkészület

### 1.1 A repó beszerzése

A repó **minden fájlt tartalmaz** — kézzel semmit nem kell létrehozni vagy bemásolni. Klónozd:

```bash
git clone <repó-URL> srwe-lab-full
cd srwe-lab-full
```

### 1.2 A repóban lévő fájlok

Már a repóban vannak, a helyükön:
- `inventory.yml`
- `configs/baseline.yml`
- `configs/mitigations.yml`
- `push_config.py`
- `attacker/` mappa 12 scriptje (mac_flood.py, mac_spoof.py, dhcp_starve.py, rogue_dhcp.py, arp_spoof.py, stp_takeover.py, vlan_hop_recon.py, cdp_telnet_recon.py, vlan_double_tag.py, ip_spoof.py, lldp_recon.py, icmp_redirect.py)
- `verify.py` (a repó gyökerében)

**Fontos:** A `configs/baseline.yml` VTY szekciójában a következő soroknak kell szerepelniük (sebezhető, de elérhető kiinduló állapot):
```yaml
- line vty 0 4
- transport input telnet ssh
- password ciscotelnet
- login
```

### 1.3 Függőségek telepítése

```bash
pip install netmiko pyyaml scapy
```

### 1.4 Gyors teszt (baseline feltöltése)

```bash
# Először csak egy eszközre (S1)
python3 push_config.py inventory.yml configs/baseline.yml S1-only
# Ellenőrzés
ssh admin@10.0.99.1
# show running-config | section line vty
# "transport input telnet ssh" kell látszódjon
```

---

## 2. Oktatói megoldókulcs — Reflexiós lap kulcskérdései

### 2.1 (Reflexiós lap 2.2) Kitöltendő: mit láttál a tcpdumpban?

**Várható válasz (laborban HTTP/HTTPS forgalom esetén):**

| Protokoll | Titkosítva látszott-e? | Mit lehetett volna kiolvasni? |
|---|---|---|
| HTTP | ✗ | Jelszavas űrlapok, cookie-k, teljes URL-path, POST-adatok |
| HTTPS/TLS 1.3 | ✓ (adatrészen) | Csak SNI (domén), IP, méret, idő; tartalom NEM |
| DNS | ✗ | Minden lekérdezés (domain-nevek teljes listája) |
| DHCP | ✗ | Kliens-MAC, ajánlott IP, gateway, DNS |
| ARP | ✗ | IP↔MAC mappingek |
| Telnet | ✗ | **Jelszavak plaintextben** |

### 2.2 (Reflexiós lap 3.1) HTTPS: miért sérti az SNI a magánszférát, de nem a tartalomtitkosságot?

**Elvárt válasz (mintaadat):**

> Az **SNI** (Server Name Indication) a TLS handshake kezdetekor **plaintext-ben** kerül át a klienstől a szervernek — ez szükséges, hogy a szerver tudja, melyik tanúsítványt használja. Egy MITM pozícióban lévő megfigyelő látja ezt, tehát **tudja, hová mész** (pl. facebook.com, banking.hu), de nem látja a **tartalmat** (pl. melyik üzenetedet nézed, milyen adatokat küldesz). Ezért sérti a magánszférát (böngészési profilozás), de nem a tartalomtitkosságot. Megoldás: **ECH (Encrypted Client Hello)**.

**Fogalmazási variációk elfogadhatók**, ha a lényeg benne van: SNI = domain-leak → profilalkotás, nem = tartalom-leak.

### 2.3 (Reflexiós lap 3.3) DoH: a rogue DHCP ki tudja játszani?

**A) Ha a kliens rendszer-DNS-t használ DoH-val:**

> **Igen.** A rogue DHCP saját DNS szervert ad ki. Ha a kliens (pl. Windows, Linux) ezt fogadja el és **DoH-t használ** arra a resolver-re, akkor a MITM **látja a DNS lekérdezéseket** (mert a DoH resolver a saját szervere, amit ő kontrollál). Tehát a DoH titkossága **a resolver birtoklásától függ**. A labor 4. fázisa (rogue DHCP) ezt demonstrálja: a támadó DNS-t adj ki → a DoH sem véd, ha a resolver a támadó.

**B) Ha a kliens fix DoH-endpointot használ:**

> A MITM **blokkolhatja** a DoH lekérdezéseket (IP-level drop, DNS sinkhole), vagy **SSL-strippinget** próbálhat (ha a kliens HTTP-re engedélyezi a downgrade). **Nem tudja látni a tartalmat**, mert a böngésző a valódi resolver-rel (pl. cloudflare-dns.com) TLS alatt kommunikál. Viszont **az SNI-ből látja a domént** (pl. cloudflare-dns.com), és **blokkolhatja a hozzáférést**.

**C) Hálózatüzemeltetői oldal:**

> A DoH **centralizálja** a DNS-lekérdezéseket kevés nagy resolver-re (Google, Cloudflare, Quad9). Ez **nehezíti** a tűzfalak számára a domain-alapú szűrést (mert DoH port 443-on megy, mint sima HTTPS). A megoldás: **DoH-policy enforcement** (céges proxy + saját CA), vagy **DoH whitelist/blacklist** a klienseken. Az adatvédelmi dilemma: **felhasználói magánszféra vs. hálózatellenőrzés**.

### 2.4 (Reflexiós lap 4.2) GDPR-elvpárosítás — mintapéldák

| Elv | Hálózati vonatkozás | Laborbeli példa |
|---|---|---|
| **Adatminimalizálás** | Csak a szükséges protokolladatok rögzítése | tcpdump filter: `port 80 or port 443`, ne minden csomag |
| **Célhoz kötöttség** | A rögzített adat csak oktatási célra használható | MITM-pozícióból nyert adat nem másolható ki USB-n |
| **Tárolási korlátozás** | Naplók csak a szükséges ideig | tcpdump .pcap törlése a labor végén; syslog/show-kimenetek törlése legkésőbb 1 héten belül |
| **Átláthatóság** | A demonstrációt meg kell előznie tájékoztatásnak | A hallgatók előre tudták, hogy MITM-demonstráció folyik (informed consent) |
| **Feldolgozás biztonsága** | Pszeudonimizálás, ahol lehetséges | Dokumentált MAC-címeknél csak a gyártói rész (OUI) marad, a többi maszkolva: `00:1A:2B:xx:xx:xx` |

---

## 3. Hibaelhárítási útmutató (oktatónak)

### 3.1 Gyakori problémák és megoldások

| Hiba | Ok | Megoldás |
|---|---|---|
| **`push_config.py` nem csatlakozik SSH-n** | Baseline-ban nincs SSH kulcs generálva | Futtasd: `crypto key generate rsa modulus 1024` manuálisan |
| **Telnet próba nem működik** | Baseline VTY még SSH-only | **Javítsd** a baseline-t a `transport input telnet ssh` sorral |
| **IP Source Guard minden forgalmat blokkol** | DHCP snooping még nincs bekapcsolva | Pusheld előbb a `dhcp-snooping` szekciót |
| **DAI statistics 0 dropped** | ARP forgalom nincs szimulálva | Futass `arp_spoof.py`-t újra a támadó gépen |
| **`verify.py` hibát jelez LLDP-nél** | Platformspecifikus LLDP szintaxis | Írj át a `no lldp transmit/receive` parancsokra |
| **STP port nem megy err-disabled-be** | BPDU Guard nincs aktiválva | Ellenőrizd: `spanning-tree bpduguard enable` a porton |
| **Double-tagging nem működik** | Natív VLAN még mindig 1 | Pusheld a `native-vlan-hardening` szekciót (VLAN 999) |
| **ICMP redirect nem települ route-t** | Kernel rejecteli | VC-V-n: `sysctl -w net.ipv4.conf.eth0.accept_redirects=1` |

### 3.2 Platformspecifikus szintaxisok (ellenőrizd a saját IOS-eddel)

| Funkció | Cisco IOS változat | Parancs |
|---|---|---|
| **LLDP TX/RX tiltása** | Régi (pre-15.x) | `no lldp run` (globális) |
| | Új (15.x+) | `no lldp transmit` / `no lldp receive` (interfészen) |
| **IP Source Guard** | 12.2(50)SE+ | `ip verify source` (access porton) |
| **DAI rate limit** | 15.x | `ip arp inspection limit rate 15` |
| **STP BPDU Guard** | Minden | `spanning-tree bpduguard enable` |
| **Native VLAN hardening** | Minden | `switchport trunk native vlan 999` |

---

## 4. Deployment checklist (oktató számára)

### 4.1 Labor előkészítés (2–3 órával előtte)

- [ ] Fizikai eszközök összeállítása (2× switch, 1× router, 3× PC)
- [ ] Topológia bekötve (S1–S2 trunk, PC-V, PC-A, ATTACKER)
- [ ] R1-en DHCP pool konfigurálva (VLAN 10, 10.10.10.0/24)
- [ ] PC-A (admin) IP-cím: 10.0.99.10/24, SSH elérhető
- [ ] ATTACKER (Kali/Debian) root jog, scapy telepítve
- [ ] **baseline.yml** feltöltve (Telnet nyitva — sebezhető kiinduló állapot)
- [ ] `verify.py` futási teszt (legalább S1-en)

### 4.2 Labor előtt 15 perc (hallgatók érkezése előtt)

- [ ] Baseline visszaállítása (ha előző csoport használta)
- [ ] SSH kulcsok frissítése (ha szükséges)
- [ ] `clear mac address-table dynamic` (S1, S2)
- [ ] `clear ip dhcp snooping binding` (S1)
- [ ] `clear ip arp inspection statistics` (S1)
- [ ] Baseline konfiguráció mentése (`write memory`)

### 4.3 Labor végén (csoport átkötés előtt)

- [ ] `clear ip dhcp binding *` (R1)
- [ ] `clear ip dhcp snooping binding` (S1)
- [ ] `clear ip arp inspection statistics` (S1)
- [ ] `clear spanning-tree detected-protocols` (S1, S2)
- [ ] Baseline újbóli feltöltése (vagy manuális reset)
- [ ] **tcpdump .pcap fájlok törlése** (adatvédelem!)
- [ ] Hallgatók reflexiós lapjainak begyűjtése

### 4.4 Adatvédelmi checklist

- [ ] Hallgatók tájékoztatva a MITM demonstrációról (informed consent)
- [ ] Valódi felhasználói adatok NEM vannak a laborban
- [ ] Tcpdump fájlok **nem** kerülnek ki a laborból
- [ ] MAC-címek (ha dokumentálva) pszeudonimizálva (csak az OUI marad, pl. `00:1A:2B:xx:xx:xx`)
- [ ] Naplók (syslog, show-kimenetek) törlése legkésőbb 1 héten belül (a .pcap fájlok már a labor végén törlendők)

---

## 5. Fejlesztési lehetőségek (haladóknak)

### 5.1 Automatizált labor értékelés (CI/CD)

```bash
#!/bin/bash
# CI pipeline példány
echo "=== SRWE Labor Automatizált Értékelés ==="
python3 push_config.py inventory.yml configs/baseline.yml
sleep 30
./run_attacks.sh          # automatikus támadás-futtatás
sleep 30
python3 verify.py inventory.yml --json eredmeny.json
cat eredmeny.json | jq '.score.percent'
```

### 5.2 Ansible playbook – alternatív megközelítés

```yaml
# ansible/srwe_baseline.yml
- hosts: switches
  become: yes
  tasks:
    - name: Apply baseline config
      ios_config:
        src: baseline.yml
    - name: Save config
      ios_save:
```

### 5.3 Grafikus monitoring dashboard

- **Grafana + Prometheus + snmp_exporter** → valós idejű port statisztikák
- **Wireshark dissector plugin** → L2 támadások vizualizálása

---

## 6. Kapcsolódó anyagok

| Téma | Forrás |
|---|---|
| Cisco SRWE v7.0 Curriculum | [netacad.com](https://www.netacad.com/courses/ccna-switching-routing-wireless-essentials) |
| DHCP Snooping Deep Dive | [cisco.com/security/dhcp-snooping](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/85770-configure-dhcp-guard.html) |
| DAI & ARP Inspection | [cisco.com/dai-guide](https://www.cisco.com/c/en/us/support/docs/security/52299-configure-inspection.html) |
| DoH & Privacy Debate | [ietf.org/rfc8484](https://tools.ietf.org/html/rfc8484) + [cloudflare.com/learning/dns/doe-vs-doh](https://www.cloudflare.com/learning/dns/what-is-doh/) |
| ECH (Encrypted Client Hello) | [rfc8484bis](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni) |

---

## 7. Kontakt és visszajelzés

Ha hibát találsz a dokumentumban, vagy fejlesztést javasolsz:

- **GitHub Issues** (ha a labor repo-ban van)
- **Email**: [oktatas@intezetet.hu](mailto:oktatas@intezetet.hu)
- **Verziókezelés**: Ez a dokumentum `v2.0 FINAL` — a változtatási napló a GitHub commit message-ekben


