# Végigvezetés: mit mire használunk, hogyan állítsuk fel és csináljuk végig a labort

*SRWE Modul 10–11 — Layer 2 támadás/védelem labor | gyakorlati kézikönyv oktatóknak és hallgatóknak*

Ez a dokumentum összeköti a csomag többi fájlját egyetlen, lineárisan követhető menetbe: előbb **mit mire használunk**, majd **hogyan állítjuk fel** a labort, végül **hogyan csináljuk végig** fázisról fázisra. A részletes parancsok, YAML-ek és szkriptek a `docs/mester-labor-dokumentacio.md`-ben vannak — ez a lap a karmester.

---

## 0. Egyperces áttekintés

A labor egy fizikai (vagy emulált) kis Cisco-hálózaton **12 Layer 2 támadást** mutat be, mindegyiknél ugyanazzal a ritmussal:

> **támadás → megfigyelés → védelem felkonfigurálása → újratámadás (most már elhiúsul)**

Három szerepkör van:
- **Támadó (ATTACKER)** — Python/scapy szkripteket futtat root-ként (a `attacker/` mappából).
- **Üzemeltető (PC-A / admin)** — YAML-ben leírt Cisco-konfigurációt tölt fel netmikóval (`push_config.py`), majd pontoz (`verify.py`).
- **Áldozat/megfigyelő (PC-V, PC-W)** — `tcpdump`-pal nézi, mi történik a dróton.

A tanulság a végén: **a magasabb rétegek védelme (TLS, DoH, DNSSEC) is összeomlik, ha a Layer 2 alap nincs megerősítve** — ezt a `docs/reflexios-lap.md` dolgozza fel.

---

## 1. Mit mire használunk? — a csomag elemei

### 1.1 Dokumentumok (`docs/`)

| Fájl | Mire való | Ki használja |
|---|---|---|
| `mester-labor-dokumentacio.md` | A teljes forrás: topológia, `inventory.yml`, `baseline.yml`, `mitigations.yml`, `push_config.py`, mind a 12 scapy-szkript, és a fázisonkénti menet. Innen másolható ki minden fájl. | Oktató (felállítás), hallgató (referencia) |
| `vegigvezetes-labor-felallitas.md` | **Ez a lap** — a felállítás és a végigjátszás lineáris forgatókönyve. | Mindenki |
| `hallgatoi-feladatlap.md` | A 12 fázis kitöltendő munkalapja (megfigyelések, kérdések, „Átment ellenőrzések: ___/27"). | Hallgató |
| `reflexios-lap.md` | MITM-adatvédelmi elemzés (HTTP/HTTPS/SNI/DNS/DoH/DNSSEC) + GDPR-elvpárosítás + dilemmakérdések. A 12. fázis után töltendő. | Hallgató |
| `index-es-deploy-checklist.md` | 15 perces gyorsstart + **oktatói megoldókulcs** a reflexiós lap kérdéseihez. | Oktató |
| `AI-instrukcio-es-vegso-audit.md` | A csomag „source of truth"-ja: reprodukciós protokoll, audit-szempontok, és a **bővítési roadmap** (13–16. fázis: HSRP, IPv6 RA, DHCPv6, VTP). | Oktató / fejlesztő |

### 1.2 Kód / konfiguráció

| Elem | Mire való |
|---|---|
| `inventory.yml` | A három eszköz (S1, S2, R1) menedzsment-IP-je és SSH-hitelesítése netmikóhoz. **Minden** push/verify ebből dolgozik. |
| `configs/baseline.yml` | A **sebezhető kiinduló állapot**: minden védelem KI, de az eszközök elérhetők, és a vty-sorokon **Telnet is nyitva** (hogy a 8. fázis demózható legyen). |
| `configs/mitigations.yml` | A **12 védelmi szekció** (pl. `port-security`, `dhcp-snooping`, `dai`, `stp-guard` …). Szekciónként push-olható, mindegyik `post:` blokkja egy ellenőrző `show`-t futtat. |
| `push_config.py` | YAML → Cisco feltöltő (netmiko). Felismeri a `global`, `dhcp_pool`, `interfaces`, `range …` kulcsokat; **nem** szúr be automatikus `exit`-et (ezért a YAML-ben explicit `exit` zárja a blokkokat). |
| `verify.py` | **27 regex-ellenőrzés / 150 pont.** Lefuttatja a `show`-kat, pozitív (KELL) és negatív (NEM SZABAD) mintákkal pontoz, jegyet számol, JSON-t exportál. |
| `attacker/*.py` | 12 scapy-szkript, egy-egy támadáshoz. Mind **root-ot** igényel (raw socket). |

### 1.3 A 12 támadás → védelem párosítás

| # | Támadás | scapy-szkript | Védelem (`mitigations.yml` szekció) |
|---|---|---|---|
| 1 | MAC flood (CAM overflow) | `mac_flood.py` | `port-security` |
| 2 | MAC spoofing | `mac_spoof.py` | `port-security` (sticky) |
| 3 | DHCP starvation | `dhcp_starve.py` | `dhcp-snooping` (+ rate limit) |
| 4 | DHCP spoofing (rogue DHCP) | `rogue_dhcp.py` | `dhcp-snooping` (trust) |
| 5 | ARP poisoning (MITM) | `arp_spoof.py` | `dai` |
| 6 | STP root takeover | `stp_takeover.py` | `stp-guard` (BPDU + Root Guard) |
| 7 | VLAN hopping (DTP) | `vlan_hop_recon.py` | `vlan-hop` |
| 8 | CDP recon + nyílt Telnet | `cdp_telnet_recon.py` | `hardening` |
| 9 | 802.1Q double-tagging | `vlan_double_tag.py` | `native-vlan-hardening` |
| 10 | IP spoofing | `ip_spoof.py` | `ip-source-guard` |
| 11 | LLDP recon | `lldp_recon.py` | `lldp-hardening` |
| 12 | ICMP redirect (gateway MITM) | `icmp_redirect.py` | `icmp-redirect` |

---

## 2. Felállítás

### 2.1 Hardver / eszközök

A topológia (részletesen: `mester-labor-dokumentacio.md`, 2. szakasz):

```
R1 (router, DHCP + GW)  ──trunk──  S1 (switch)  ──trunk (Fa0/24)──  S2 (switch)
                                   ├ Fa0/1  PC-V   (áldozat,  VLAN 10)
                                   ├ Fa0/2  PC-A   (admin,    VLAN 99) ← netmiko innen
                                   └ Fa0/3  ATTACKER (támadó, VLAN 10)
                                              S2 Fa0/1: PC-W (VLAN 20 — csak a 9. fázis)
```

**Címzés:**
- Menedzsment **VLAN 99**: S1 `10.0.99.1`, S2 `10.0.99.2`, R1 `10.0.99.254`, PC-A `10.0.99.10`
- User **VLAN 10**: `10.10.10.0/24` (PC-V, ATTACKER; DHCP-pool az R1-en, GW `10.10.10.1`)
- Teszt **VLAN 20**: `10.20.20.0/24` (PC-W, csak a double-tagginghez)

> **Emuláció is jó:** GNS3 / EVE-NG / CML a switchekhez és R1-hez, a PC-khez Linux VM-ek. A scapy Layer 2-támadásokhoz a virtuális switch portoknak **promiscuous / trunk-áteresztő** módban kell lenniük, különben a keretek nem jutnak át.

### 2.2 Szoftverkövetelmények

| Gép | Telepítendő |
|---|---|
| PC-A (admin) | `python3`, `pip install netmiko pyyaml` |
| ATTACKER | `python3`, `pip install scapy`, **root** (raw socket) |
| PC-V / PC-W | Linux, `tcpdump` |

### 2.3 Fájlok a helyükre

Klónozd a repót a PC-A gépre, vagy hozd létre a `mester-labor-dokumentacio.md` alapján a következő szerkezetet:

```
srwe-lab/
├── inventory.yml
├── configs/baseline.yml
├── configs/mitigations.yml
├── push_config.py
├── verify.py
└── attacker/   (12 .py szkript)
```

- `inventory.yml`, `baseline.yml`, `mitigations.yml`, `push_config.py` és a 12 `attacker/*.py` szövege a **mester dokumentáció** megfelelő szakaszaiból másolható (4–9. szakasz).
- `verify.py` már kész a repó gyökerében.
- **Ellenőrizd** az `inventory.yml` IP-jeit/jelszavait a saját eszközeidhez, és a `baseline.yml` vty-blokkjában maradjon benne a `transport input telnet ssh` (enélkül a 8. fázis félresül).

### 2.4 Előkészítő kézi lépés az eszközökön

A netmiko SSH-val jelentkezik be, ezért az eszközöknek **elérhetőnek kell lenniük már az első push előtt**. Konzolról állítsd be a menedzsment-VLAN-t és az SSH-t minimálisan (IP a VLAN 99-en + `crypto key generate rsa` + `username`), vagy ha a `baseline.yml`-t konzolról/első kézi feltöltéssel viszed fel, utána már SSH-n mehet minden. A `baseline.yml` global-blokkja tartalmazza ezeket a sorokat — egyszer kézzel felvéve a láncban onnan automatizálható.

### 2.5 Baseline feltöltése (0. fázis)

```bash
# először érdemes egyetlen eszközre próbálni:
python3 push_config.py inventory.yml configs/baseline.yml S1-only   # ha használsz szűrőt
# majd a teljes baseline:
python3 push_config.py inventory.yml configs/baseline.yml
```

**Elvárt eredmény:** S1, S2, R1 elérhető SSH-n ÉS Telneten; egyetlen védelem sincs aktív. Gyors ellenőrzés:

```bash
ssh admin@10.0.99.1
S1# show running-config | section line vty    # "transport input telnet ssh" kell
```

Ezzel a labor **készen áll** — innen jön a 12 fázis.

---

## 3. Végigcsinálás — a 12 fázis menete

**Minden fázis azonos ritmusú:** (1) futtasd a támadást, (2) figyeld meg a hatást PC-V/PC-W tcpdumppal vagy az eszköz `show`-jaival és írd be a `hallgatoi-feladatlap.md`-be, (3) töltsd fel a védelmet, (4) futtasd újra a támadást — most el kell hiúsulnia.

A támadó szkriptek a `eth0` interfészt és néhány argumentumot várnak (lásd a docstringeket). Alább a menet (teljes táblázat: `mester-labor-dokumentacio.md`, 10. szakasz):

| Fázis | Támadás | Védelem feltöltése | Mit figyelj |
|---|---|---|---|
| 1 | `sudo python3 attacker/mac_flood.py eth0 10000` | `push_config.py … port-security` | CAM megtelik → PC-V idegen forgalmat lát; védelem után Fa0/3 err-disabled |
| 2 | `sudo python3 attacker/mac_spoof.py eth0 <PC-V-MAC>` | (már aktív) | Syslog: port-security violation |
| 3 | `sudo python3 attacker/dhcp_starve.py eth0 250` | `push_config.py … dhcp-snooping` | PC-V nem kap címet; védelem után rate-limit dob |
| 4 | `sudo python3 attacker/rogue_dhcp.py eth0` + PC-V renew | (snooping már aktív) | PC-V GW-je a támadó lesz; védelem után csak legit lease |
| 5 | `sudo python3 attacker/arp_spoof.py eth0 <PC-V-IP> 10.10.10.1` | `push_config.py … dai` | PC-V `arp -a`: GW-MAC = támadó MAC; DAI után drop nő |
| 6 | `sudo python3 attacker/stp_takeover.py eth0` | `push_config.py … stp-guard` | `show spanning-tree root` = támadó; védelem → Fa0/3 err-disabled |
| 7 | `sudo python3 attacker/vlan_hop_recon.py eth0` | `push_config.py … vlan-hop` | DTP-keret látszik; védelem után nincs DTP, fix access |
| 8 | `sudo python3 attacker/cdp_telnet_recon.py eth0 10.0.99.1` | `push_config.py … hardening` | CDP-ben IOS-verzió + nyílt Telnet; védelem után SSHv2-only |
| 9 | `sudo python3 attacker/vlan_double_tag.py eth0 10.20.20.10` | `push_config.py … native-vlan-hardening` | PC-W (VLAN 20) ICMP-t kap; védelem után nem jut át |
| 10 | `sudo python3 attacker/ip_spoof.py eth0 10.10.10.50` | `push_config.py … ip-source-guard` | Hamis forrás látszik; IPSG után hardware-drop |
| 11 | `sudo python3 attacker/lldp_recon.py eth0 --inject` | `push_config.py … lldp-hardening` | LLDPDU: rendszernév/portok; védelem után nincs LLDP user-porton |
| 12 | `sudo python3 attacker/icmp_redirect.py eth0 <PC-V-IP> 10.10.10.1` | `push_config.py … icmp-redirect` | PC-V route a támadón át; védelem után a router sosem küld redirectet |

### 3.1 Kritikus sorrend- és fázisközi figyelmeztetések

1. **IPSG csak DHCP snooping UTÁN** (10. fázis a 3–4. után): az IP Source Guard a snooping binding-táblájából dolgozik — enélkül **minden** user-forgalmat eldob. (Ezt érdemes szándékos hibakeresési gyakorlatként is megmutatni.)
2. **Double-tagging (9v) után** futtasd újra a 9. támadást, hogy lásd a natív-VLAN hardening hatását.
3. **12. fázishoz** a PC-V-n `sysctl net.ipv4.conf.all.accept_redirects=1` kell — ezt a hallgató állítja be; a lecke épp az, hogy éles rendszeren ez miért van tiltva.
4. **err-disabled portok:** a 2. (`violation shutdown`) és a 6. fázis (BPDU Guard) után a Fa0/3 err-disabled állapotba kerülhet. A **következő támadás előtt** állítsd helyre:
   ```
   S1(config)# interface fa0/3
   S1(config-if)# shutdown
   S1(config-if)# no shutdown
   ```

---

## 4. Pontozás és zárás

### 4.1 Ellenőrzés (Z fázis)

A 12 védelem feltöltése után:

```bash
python3 verify.py inventory.yml                 # 27 ellenőrzés + pontszám + jegy
python3 verify.py inventory.yml --verbose       # a nyers show-kimenetekkel (hibakereséshez)
python3 verify.py inventory.yml --json eredmeny.json   # gépi kiértékeléshez
python3 verify.py inventory.yml --only S1       # csak egy eszköz
```

**Pontozás:** 27 ellenőrzés, összesen **150 pont**. Százalék → jegy:

| Százalék | Jegy |
|---|---|
| ≥ 90% | 5 |
| ≥ 80% | 4 |
| ≥ 70% | 3 |
| ≥ 60% | 2 |
| < 60% | 1 |

A kilépési kód 0, ha ≥ 60% (CI-barát). A hallgató a feladatlap „Átment ellenőrzések: ___/27" mezőjébe írja be az eredményt.

### 4.2 Reflexió

A 12. fázis után a hallgató kitölti a `reflexios-lap.md`-et (MITM-adatvédelem, HTTPS/SNI, DNS vs DoH vs DNSSEC, GDPR-elvpárosítás, dilemmakérdések). Az oktatói megoldókulcs az `index-es-deploy-checklist.md` 2. szakaszában van.

### 4.3 Visszaállítás a következő csoportnak

```bash
python3 push_config.py inventory.yml configs/baseline.yml   # védtelen állapot vissza
```

Majd takarítsd a maradékokat az eszközökön:
- sticky MAC-ek és snooping binding-ek: `clear` parancsokkal
- err-disabled portok: `shutdown` / `no shutdown`, vagy `errdisable recovery cause …`

---

## 5. Hibakeresési gyorslista

| Tünet | Valószínű ok / teendő |
|---|---|
| netmiko timeout/auth hiba | Rossz IP/jelszó az `inventory.yml`-ben; az eszköz nem elérhető VLAN 99-en; SSH nincs felhozva (`crypto key generate rsa`) |
| Push után „parancs nem ismert" | A YAML-blokkból hiányzik az explicit `exit` (a pusher nem teszi be automatikusan) |
| A támadás „nem csinál semmit" | ATTACKER nem root; rossz `eth0` interfésznév; virtuális switch nem promiscuous/trunk |
| Minden user-forgalom elesik a 10. fázisban | IPSG-t a DHCP snooping ELŐTT push-oltad — előbb `dhcp-snooping`, utána `ip-source-guard` |
| A 8. fázisban nincs Telnet-próba | A baseline vty-ból kimaradt a `transport input telnet ssh` |
| 12. fázis nem működik | PC-V-n nincs `accept_redirects=1`, vagy az `rp_filter` eldobja — ideiglenesen kapcsold ki |
| `verify.py` egy védelemnél buktat, pedig beállítottad | Platform-/IOS-függő `show`-kimenet; nézd `--verbose`-zal és igazítsd a YAML/regex párost |

---

## 6. Hova tovább (bővítés)

A következő iterációk 4 új fázist adhatnak hozzá (teljes értékelő táblázat + scapy-vázak: `AI-instrukcio-es-vegso-audit.md`, RÉSZ 0):

1. **13. HSRP/VRRP/GLBP eltérítés** — gateway-MITM FHRP-n át → `standby … authentication md5`
2. **14. IPv6 RA spoofing** (rogue RA) → `ipv6 nd raguard`
3. **15. DHCPv6 starvation/spoofing** → `ipv6 dhcp guard` (a 14. UTÁN)
4. **16. VTP injection** (VLAN-adatbázis felülírás) → `vtp mode transparent` / VTPv3

> **Biztonsági megkötés mindvégig:** a labor kizárólag izolált, oktatási szegmensen futtatható. A scapy-szkriptek valódi L2/L3 támadásokat szimulálnak — éles vagy intézményi hálózaton tilos futtatni őket.
