# SRWE Modul 10–11 — Hallgatói Feladatlap (VÉGLEGES, 12 fázis)
## 12 Layer 2 támadás és védelem | Python automatizálással

**Kitöltendő a labor során | A fázisszámok megegyeznek a mester dokumentum fázistáblájával**

---

## 0. Alapadatok

| Elem | Kitöltendő |
|---|---|
| Hallgató neve | _________________________ |
| Neptun/azonosító | _________________________ |
| Laborvezető | _________________________ |
| Labor dátuma | _________________________ |
| Partner neve (ha van) | _________________________ |

---

## Fázis 0 — Alapkonfiguráció (baseline) feltöltése

**Parancs:**
```bash
python3 push_config.py inventory.yml configs/baseline.yml
```

| Eszköz | IP-cím | SSH-elérés (I/N) | Telnet-elérés (I/N) | Megjegyzés |
|---|---|---|---|---|
| S1 | 10.0.99.1 | _____ | _____ | ________ |
| S2 | 10.0.99.2 | _____ | _____ | ________ |
| R1 | 10.0.99.254 | _____ | _____ | ________ |

**Kérdés:** Miért nem kapcsolunk be a baseline-ban egyetlen védelmet sem?

```
_________________________________________________________________________
```

---

## Fázis 1 – MAC address table overflow (MAC flooding)

**Támadás:** `sudo python3 attacker/mac_flood.py eth0 10000`

**Megfigyelés (S1):** `show mac address-table count`

| Metrika | Támadás előtt | Támadás után |
|---|---|---|
| Bejegyzések száma | ______ | ______ |
| Szabad bejegyzések | ______ | ______ |
| Teljes kapacitás | ______ | ______ |

**Kérdés 1:** Mit tapasztalsz a CAM-tábla szabad kapacitásában a támadás után?

```
_________________________________________________________________________
```

**Kérdés 2:** Mi történik a switchsel, ha a CAM-tábla megtelik? Hogyan érinti ez a biztonságot?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml port-security`

**Ellenőrzés (S1):** `show port-security` és `show port-security interface fa0/3`

| Paraméter | Fa0/1 (áldozat) | Fa0/3 (támadó) |
|---|---|---|
| Port Security állapot | __________ | __________ |
| Maximum MAC-cím | __________ | __________ |
| Violation mód | __________ | __________ |
| Sticky MAC | __________ | __________ |

**Újratámadás:** `sudo python3 attacker/mac_flood.py eth0 10000`

**Kérdés:** Miért hiúsult meg most a támadás?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 2 – MAC spoofing

**Támadás:** `sudo python3 attacker/mac_spoof.py eth0 <PC-V-MAC>`

**Megfigyelés (S1):** `show port-security` + syslog üzenet.

**Kérdés:** Milyen violation-lépést váltott ki a spoofolt MAC, és melyik porton?

```
_________________________________________________________________________
```

**Visszaállítás:** hogyan engeded újra az err-disabled portot? Írd ki a parancsokat!

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 3 – DHCP starvation

**Támadás:** `sudo python3 attacker/dhcp_starve.py eth0 250`

**Megfigyelés (R1):** `show ip dhcp binding`

**Kérdés:** Hány DHCP-kötés keletkezett? Valódi vagy hamis többségben?

```
_________________________________________________________________________
```

**Megfigyelés (PC-V):** `dhclient -v eth0` — Sikeres? _____ Miért nem?

```
_________________________________________________________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml dhcp-snooping`

**Ellenőrzés (S1):** `show ip dhcp snooping` és `show ip dhcp snooping binding`

| Interfész | Trust? | Rate limit? | Állapot |
|---|---|---|---|
| Gi0/1 (R1/DHCP) | _____ | _____ | _____ |
| Fa0/24 (S2 trunk) | _____ | _____ | _____ |
| Fa0/3 (támadó) | _____ | _____ | _____ |
| Fa0/1 (PC-V) | _____ | _____ | _____ |

**Újratámadás + kérdés:** Mi változott a támadó porton a DHCP-üzenetek sorsában?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 4 – DHCP spoofing (rogue DHCP)

**Támadás:** `sudo python3 attacker/rogue_dhcp.py eth0` — majd PC-V-n: `dhclient -r eth0 && dhclient -v eth0`

**Megfigyelés (PC-V):** `ip route` és `cat /etc/resolv.conf`

**Kérdés:** Ki a kiosztott gateway és DNS? Egyezik-e a legitim 10.10.10.1-gyel? _____

**Mit jelent ez a pozícióból adódóan (hova kerül a PC-V forgalma)?**

```
_________________________________________________________________________
_________________________________________________________________________
```

**Védelem:** a `dhcp-snooping` szekció már aktív a 3. fázisból.

**Ellenőrzés (S1):** `show ip dhcp snooping binding` — csak legitim lease van?

**Kérdés:** A rogue OFFER-eket miért dobta el a switch, és milyen porton?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 5 – ARP poisoning (kétirányú MITM)

**Támadás:** `sudo python3 attacker/arp_spoof.py eth0 10.10.10.20 10.10.10.1`

**Megfigyelés (PC-V):** `arp -a | grep 10.10.10.1`

**Kérdés:** Milyen MAC-cím tartozik a gateway-hez? Egyezik-e a támadó MAC-jével? _____

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml dai`

**Ellenőrzés (S1):** `show ip arp inspection statistics vlan 10`

**Kérdés:** Nő-e az eldobott (dropped) ARP-csomagok száma? Mennyivel?

```
_________________________________________________________________________
```

**Újratámadás + kérdés:** Megváltozott-e a PC-V ARP-táblája? Miért / miért nem?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 6 – STP manipuláció

**Támadás:** `sudo python3 attacker/stp_takeover.py eth0`
(Alternatíva a megbízhatóság kedvéért: `sudo brctl addbr br0 && sudo brctl setbridgeprio br0 0 && sudo ip link set br0 up`)

**Megfigyelés (S1):** `show spanning-tree root`

**Kérdés:** Ki a root bridge a támadás alatt? MAC-cím?

```
_________________________________________________________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml stp-guard`

**Ellenőrzés (S1):** `show spanning-tree summary` és `show interfaces status err-disabled`

**Kérdés:** Melyik port került err-disabled állapotba, és melyik védelem lépett működésbe (BPDU Guard / Root Guard)?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Port helyreállítása — írd ki a parancsokat:**

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 7 – VLAN hopping és DTP

**Felderítés:** `sudo python3 attacker/vlan_hop_recon.py eth0`

**Kérdés:** Láttál DTP-keretet? Mit jelent ez a port működési módjára nézve?

```
_________________________________________________________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml vlan-hop`

**Ellenőrzés (S1):** `show interfaces fa0/3 switchport` és `show interfaces status`

**Kérdések:** A Fa0/3 üzemmódja? ___________ | DTP-egyeztetés? ___________
A nem használt portok (pl. Fa0/4) állapota? Miért fontos ez?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 8 – CDP felderítés és Telnet

**Felderítés:** `sudo python3 attacker/cdp_telnet_recon.py eth0 10.0.99.1`

**Kérdés:** Milyen információkat árult el a CDP a switchről? (Sorolj fel hármat!)

```
1. ______________________________  2. ______________________________  3. ______________________________
```

**Telnet próba eredménye (baseline-ban):** _______________________

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml hardening`

**Ellenőrzés (S1):** `show cdp`, `show ip ssh`, `show running-config | section line vty`

| Paraméter | Baseline | Hardening után |
|---|---|---|
| CDP fut? | _____ | _____ |
| SSH-verzió | _____ | _____ |
| VTY-átvitel | _____ | _____ |

**Telnet próba újra:** `telnet 10.0.99.1` — Sikerül-e csatlakozni? Miért?

```
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 9 – 802.1Q double-tagging

**Támadás:** `sudo python3 attacker/vlan_double_tag.py eth0 10.20.20.10`

**Megfigyelés (PC-W, VLAN 20):** `tcpdump -i eth0 icmp`

**Kérdés:** Megérkezett-e az ICMP echo request a VLAN 10-es támadótól? _____

**Magyarázd el a double-tagging elvét:** mit tesz a külső tag a trunkon, és mit értelmez a második switch?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml native-vlan-hardening`

**Ellenőrzés (S1):** `show interfaces trunk` — Natív VLAN előtte / utána: ______ / ______

**Újratámadás + kérdés:** Eljutott-e a keret a VLAN 20-ba? Miért nem?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Kérdés:** Miért csak egyirányú ez a támadás?

```
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 10 – IP spoofing

**Támadás:** `sudo python3 attacker/ip_spoof.py eth0 10.10.10.50`

**Kérdés:** A hamis 10.10.10.50 szerepel-e a DHCP snooping binding táblában? _____

**Miért nem fogja meg a DHCP snooping önmagában ezt a forgalmat?**

```
_________________________________________________________________________
_________________________________________________________________________
```

**Védelem (csak a dhcp-snooping után!):** `python3 push_config.py inventory.yml configs/mitigations.yml ip-source-guard`

**Ellenőrzés (S1):** `show ip verify source` és `show ip source binding`

| Interfész | Filter-type | Filter-mode | Állapot |
|---|---|---|---|
| Fa0/1 | __________ | __________ | _____ |
| Fa0/3 | __________ | __________ | _____ |

**Újratámadás + kérdés:** Elfordul-e a hamis forrású csomag? Melyik táblát ellenőrzi a switch hozzá?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 11 – LLDP felderítés

**Felderítés:** `sudo python3 attacker/lldp_recon.py eth0 --inject`

**Kérdés:** Láttál LLDPDU-t? Mit árul el az LLDP a hálózatról? (Három elem!)

```
1. ______________________________  2. ______________________________  3. ______________________________
```

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml lldp-hardening`

**Ellenőrzés (S1):** `show lldp interface FastEthernet0/1` — Tx: _____ Rx: _____

**Kérdés:** Sorolj fel két különbséget a CDP és az LLDP között! (tulajdonos, szabvány, hatókör)

```
1. ______________________________________________  2. ______________________________________________
```

**Önértékelés (1–5):** ______

---

## Fázis 12 – ICMP redirect (gateway MITM)

**Előkészület (PC-V):** `sysctl -w net.ipv4.conf.eth0.accept_redirects=1`

**Kérdés:** Miért tiltja ezt alapértelmezetten a modern Linux-kernel? Miről árulkodik ez a beállítás?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Támadás:** `sudo python3 attacker/icmp_redirect.py eth0 10.10.10.20 10.10.10.1`

**Megfigyelés (PC-V):** `ip route get 8.8.8.8` — Települt-e a támadón át vezető route? _____

**Védelem:** `python3 push_config.py inventory.yml configs/mitigations.yml icmp-redirect`

**Ellenőrzés (R1):** `show ip interface GigabitEthernet0/1.10 | include redirects` — Kimenet: _______________

**Újratámadás + kérdés:** Települ-e most a redirect-route? Miért nem?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Kérdés:** Hasonlítsd össze az ARP-poisoning-MITM-t (5. fázis) és az ICMP-redirect-MITM-t: milyen extra feltétele van az utóbbinak a kliens oldalon?

```
_________________________________________________________________________
_________________________________________________________________________
```

**Önértékelés (1–5):** ______

---

## Automatikus ellenőrzés (a labor végén)

```bash
python3 verify.py inventory.yml
```

**Eredmények átmásolása** (a `verify.py` 27 ellenőrzést futtat mind a 12 támadás ellen; az alábbi sorok ezek csoportjai):

| Ellenőrzés | Várt | Tényleges | OK (I/N) |
|---|---|---|---|
| Port Security aktív, sticky MAC (S1, S2) | Igen | _____ | ___ |
| DHCP Snooping aktív, trust-ok megfelelőek | Igen | _____ | ___ |
| DAI aktív VLAN 10-en | Igen | _____ | ___ |
| BPDU Guard / Root Guard aktív | Igen | _____ | ___ |
| DTP tiltva, natív VLAN = 999 | Igen | _____ | ___ |
| CDP letiltva, SSHv2-only, VTY csak SSH (S1, S2) | Igen | _____ | ___ |
| IP Source Guard aktív | Igen | _____ | ___ |
| LLDP TX/RX letiltva user-portokon | Igen | _____ | ___ |
| ICMP redirect letiltva (R1, VLAN 10 és 20 alinterfész) | Igen | _____ | ___ |

**Átment ellenőrzések:** ___ / 27  |  **Elért pontszám:** ______ %  |  **Vélhető jegy:** ______

**Teljesített fázisok száma:** ___ / 12

**Laborvezető aláírása:** ____________________ **Dátum:** ______________

---

## Záró reflexiós kérdések

**1. Melyik támadás volt a legmeglepőbb számodra, és miért?**

```
_________________________________________________________________________
_________________________________________________________________________
```

**2. Miért nem elég egyetlen védelem? Nevezz meg három támadást, amit a port security egymagában NEM véd ki!**

```
1. ______________  2. ______________  3. ______________
```

**3. Hogyan kapcsolódnak ezek a Layer 2-védelmek a magasabb rétegek adatvédelméhez (HTTP, HTTPS, DNS, DoH)?**

```
_________________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________
```

**4. Adatvédelmi dilemma: ha a laborban valós felhasználói forgalmat fogtunk volna, hogyan kellett volna eljárni?**

```
_________________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________
```

*A protokoll- és adatvédelmi mélyelemzés a külön reflexiós és adatvédelmi lapon folytatódik.*
