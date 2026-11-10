# SRWE Modul 10–11 — Reflexiós, értékelő és összefoglaló lap
## Adatvédelmi és sebezhetőségi elemzés: MITM hatása a HTTP, HTTPS, DNS, DoH és további protokollokra

**A labor 12. fázisa után kitöltendő | Anonim beadásra is van lehetőség**

> Ez a lap a Layer 2 támadásoknak azt a kérdését vizsgálja, ami a konfiguráción túlmutat: **ha valaki MITM pozícióba kerül, mit lát és mit tud módosítani a rajta futó protokollokból — és mit jelent ez az adataid védelméből?** A labor fizikai támadásai nem öncélúak: mindegyik egy valós pozíciót hoz létre, amiből a magasabb rétegek támadhatók.

---

## 1. A labor támadásai által szerzett pozíciók

Töltsd ki a labor tapasztalataid alapján — mindegyik támadás milyen **megfigyelési/manipulációs pozíciót** ad:

| # | Támadás | Szerzett pozíció | Passzív sniffing? (I/N) | Aktív forgalom-átirányítás? (I/N) |
|---|---|---|---|---|
| 1 | MAC flood | A switch hub-módba vált → idegen forgalom látszik | _____ | _____ |
| 2 | MAC spoof | Identitás-lopás a porton | _____ | _____ |
| 3 | DHCP starvation | DoS — mások nem kapnak szolgáltatást | _____ | _____ |
| 4 | Rogue DHCP | **Kliens oldali GW/DNS kontroll** — a támadó dönt a DNS-ről | _____ | _____ |
| 5 | ARP poisoning | **Kétirányú MITM** a kliens és a GW között | _____ | _____ |
| 6 | STP takeover | Forgalom átirányítása a támadón át | _____ | _____ |
| 7 | VLAN hopping (DTP) | Trunkként megnyíló access port | _____ | _____ |
| 8 | CDP/Telnet recon | Eszközinformáció-gyűjtés, nyílt vty | _____ | _____ |
| 9 | Double-tagging | Bejutás idegen VLAN-ba (egyirányú) | _____ | _____ |
| 10 | IP spoofing | Hamis forrásidentitás | _____ | _____ |
| 11 | LLDP recon | Topológia- és eszközinformáció-szerzés | _____ | _____ |
| 12 | ICMP redirect | Route-injektálás a GW-nek kiadva magunkat | _____ | _____ |

**Kulcskérdés:** A 4, 5, 6 és 12-es támadás mind ugyanahhoz a célpozícióhoz vezetett különböző utakon. **Miért van szüksége a magasabb rétegbeli protokollvédelemnek a Layer 2 hardeningre?** (3–5 mondat)

```
_________________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________
```

---

## 2. Protokoll-sebezhetőségi mátrix MITM pozícióból

Minden protokoll esetén elemezd: **mit lát a támadó**, **mit tud módosítani**, **mi véd**, és **mi az adatvédelmi vonatkozás**.

### 2.1 Áttekintő mátrix (kész váz)

| Protokoll | Titkosítás? | MITM **lát** (passzív) | MITM **módosít** (aktív) | Védelem | Adatvédelmi kockázat |
|---|---|---|---|---|---|
| **HTTP** | nincs | Teljes tartalom: sütik, URL-ek, űrlapadatok | Minden | HTTPS-re váltás, HSTS | Sütilopás → munkamenet-eltérítés; jelszavas űrlapok kilesése |
| **HTTPS (TLS 1.2/1.3)** | van (csatorna) | SNI a ClientHello-ban, cél-IP, időzítés, méret | SSL-stripping (lásd 3.2), rogue CA (lásd 3.2) | Tanúsítványvalidáció, HSTS, pinning, CT-naplók | **Az SNI és a DNS még elárulja, hová mész** |
| **DNS (UDP/53)** | nincs | Minden lekérdezés → profilrajzolás | Hamis válasz (cache-mérgezés) | DNSSEC (hitelesség!), DoT/DoH (titkosság!) | A lekérdezett domének önmagukban érzékeny adatok |
| **DoH (RFC 8484, 443)** | van | Csak az, hogy valaki DoH-t használ | Resolver-blokkolás | — | **Kettős természet**: adatvédelmet ad a felhasználónak, de elveszi a hálózatüzemeltetőtől a szabályozhatóságot |
| **DoT (RFC 7858, 853)** | van | A port alapján látszik, hogy DoT megy | Resolver-blokkolás | — | Ugyanaz, mint a DoH, de port alapján szűrhető |
| **Telnet** | nincs | Minden, **a jelszó is** | Munkamenet-eltérítés | SSHv2 | Jelszólopás — a 8. fázisban saját szemeddel láttad |
| **FTP** | nincs | Hitelesítő adatok, fájltartalom | Fájlcserék módosítása | SFTP/FTPS | A jelszó plaintextben utazik |
| **SMTP/POP3/IMAP (plaintext)** | nincs | Levelek, jelszavak | Levéltartalom | STARTTLS kényszerítés, MTA-STS | A levelezés tartalma személyes adat (GDPR) |
| **SNMPv1/v2c** | nincs | Community string plaintextben | Konfiguráció-módosítás | SNMPv3 (auth + priv) | Eszközleltár-szivárgás → belső topológiatérkép |
| **NTP** | nincs | — | Idő-eltolás → gyengíti az autentikációt | NTP-hitelesítés, több forrás | Nem adatvédelmi, de integritási támadási lánc |
| **LLDP/CDP** | nincs | Rendszernév, port, IOS-verzió, menedzsment-IP | Hamis szomszéd injektálása | LLDP TX/RX tiltása user-portokon (a 11. fázisban bekapcsoltad) | Passzív eszközfelderítés → célzottabb támadás |
| **ARP, DHCP, STP** | nincs | — | Maga a pozíciónyérés eszközei | DAI, snooping, BPDU/Root Guard (az 1–6. védelmek) | A rajtuk átfutó forgalom lesz az áldozat |

### 2.2 Kitöltendő: saját megfigyeléseid a laborból

A MITM-pozíció megszerzése után (5. fázis, ARP poisoning) a PC-V tcpdumpjában milyen protokollokat láttál?

```
Megfigyelt protokoll     Titkosítva látszott?     Mit tudtál volna kiolvasni belőle?
______________________   _______________________   ________________________________
______________________   _______________________   ________________________________
______________________   _______________________   ________________________________
______________________   _______________________   ________________________________
```

**Kérdés:** Ha a labori forgalomban HTTP is lett volna, mit láttál volna a tcpdumpban, amit HTTPS esetén nem?

```
_________________________________________________________________________
_________________________________________________________________________
```

---

## 3. Mélyelemzés: MITM az egyes protokollokban

### 3.1 HTTPS: mennyire véd valójában a TLS?

A TLS **a csatornát** titkosítja, de a MITM-pozícióból ezt **még mindig látja valaki**:

1. **Céldomén (SNI):** a TLS ClientHello-ban az SNI-mező alapból plaintext — a megfigyelő látja, *hová* mész, csak a tartalmat nem. (Megoldási irány: **ECH, Encrypted Client Hello** — 2024-es állapot szerint még nem volt általánosan bekapcsolva.)
2. **DNS:** ha a lekérdezés UDP/53-on ment (nem DoH), a MITM a domént **már a TLS-kezetelés előtt** látja.
3. **Metaadatok:** csomagméret, időzítés, cél-IP → forgalomelemzési lehetőségek.

**Kérdés:** Miért nem sérti az SNI-szivárgás a tartalom titkosságát, de miért sérti a magánszférát? (4–6 mondat)

```
_________________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________
```

### 3.2 A „trükkös" eset: amikor a TLS mégis feltörhető

Sorolj fel három mechanizmust, amivel **HTTPS mellett is** MITM lehetséges — mindegyiknél jelöld az adatvédelmi tanulságot:

| Mechanizmus | Elve (töltsd ki!) | Adatvédelmi tanulság |
|---|---|---|
| **Rogue CA / kényszerített root-tanúsítvány** (pl. céges TLS-interception proxy) | _______________________ | A „titkosított" forgalom valakinek tudatosan látható — a kérdés: kinek, milyen jogalapon, milyen tájékoztatással? |
| **SSL-stripping (lefokozás)** | A támadó levágja a HTTP→HTTPS átirányítást, a kliens sima HTTP-ben marad | Miért véd ez ellen a HSTS, és miért nem elég az átirányítás? |
| **Tanúsítvány-validáció átugratása (social engineering)** | _______________ | A böngésző figyelmeztetésének átléptetése = emberi tényező sebezhetősége |

**Dilemmakérdés:** Egy iskolai/céges hálózat TLS-interceptiót alkalmaz (a saját root CA-jával fejti vissza a HTTPS-t) „biztonsági okból". Sorolj fel két legitim okot és két kockázatot, majd írd le: milyen feltételek mellett elfogadható (pl. tájékoztatás, kilépési lehetőség, auditálhatóság, adatminimalizálás)?

```
Legitim okok:    1. ______________________  2. ______________________
Kockázatok:      1. ______________________  2. ______________________

Elfogadhatóság feltételei:
_________________________________________________________________________
_________________________________________________________________________
```

### 3.3 DNS → DoH: a titkosság árnyoldala

A **DNSSEC és a DoH/DoT egymást nem helyettesítő dolgot véd:**

| Technológia | Mit véd | Mit NEM véd |
|---|---|---|
| **DNSSEC** | **Hitelesség + integritás** (a válasz nem hamis) | **Titkosságot nem** — a lekérdezés plaintext marad |
| **DoH/DoT** | **Titkosság** (a megfigyelő nem látja a domént) | Önmagában nem hitelesíti a választ (a resolverbe kell bíznod) |

**Kérdés A:** Ha a támadó a DHCP-ben (4. fázis) saját DNS-szervert oszt ki, és a kliensed **rendszer-DNS-t** használ a DoH-ban — elveszíted a DoH védelmét? Indokold!

```
_________________________________________________________________________
_________________________________________________________________________
```

**Kérdés B:** Ha a kliens **fix DoH-végpontot** használ (pl. böngészőbe égetett URL), mit tud tenni a MITM? (Tipp: mit lát, mit tud blokkolni, tud-e információt nyerni az SNI-ből?)

```
_________________________________________________________________________
_________________________________________________________________________
```

**Kérdés C (hálózatüzemeltetői oldal):** Miért nehezíti meg a DoH a domain-alapú szűrést (pl. rosszindulatú domének blokkolása)? Mi a lehetséges egyensúly (DoH-központosítás kritikája, házirend-alapú resolver)?

```
_________________________________________________________________________
_________________________________________________________________________
```

### 3.4 Más protokollok: rangsorold!

Melyik a legsebezhetőbb MITM-mel szemben? Rangsorold 1-től (legsebezhetőbb) 5-ig, és indokold:

- FTP-fájlátvitel
- SSHv2
- SNMPv3 authPriv
- HTTP-alapú REST API (token-autentikációval)
- Plaintext SMTP-levelezés

```
1. ______________   mert: _________________________________________________
2. ______________   mert: _________________________________________________
3. ______________   mert: _________________________________________________
4. ______________   mert: _________________________________________________
5. ______________   mert: _________________________________________________
```

---

## 4. Adatvédelmi szempontok a labor során

A labor maga is **személyes adatokat érinthet** (a lehallgatott forgalom mások kommunikációja lehet). Gondolkodj el az alábbiakon:

### 4.1 Ellenőrzőlista

| Kérdés | I/N | Megjegyzés |
|---|---|---|
| Csak szintetikus/tesztforgalmat figyeltünk, nem valós felhasználói adatot | __ | ______ |
| A fogadott csomagokról nem készült mentés vagy archiválás a laboron kívülre | __ | ______ |
| A tcpdump-kimenetek a labor végén törölve lettek | __ | ______ |
| Ha véletlenül láttunk valódi nevet/jelszót, azt nem dokumentáltuk | __ | ______ |
| A MITM-eszköz a labor végén le lett választva | __ | ______ |

### 4.2 GDPR-elvek párosítása a hálózati gyakorlathoz

| GDPR-elv | Hálózati vonatkozás | Laborbeli példa (töltsd ki!) |
|---|---|---|
| **Adatminimalizálás** | Csak a szükséges protokolladatok rögzítése | _______________________ |
| **Célhoz kötöttség** | A rögzített adat csak oktatási célra használható | _______________________ |
| **Tárolási korlátozás** | Naplók csak a szükséges ideig | _______________________ |
| **Átláthatóság** | A demonstrációt meg kell előznie tájékoztatásnak | _______________________ |
| **Feldolgozás biztonsága** | Pszeudonimizálás, ahol lehetséges | _______________________ |

**Kérdés:** Miért feszül a hálózati naplózásnál az adatvédelmi és az IT-biztonsági szemlélet („mindent naplózunk a védelem érdekében" vs. „minimalizáljunk")? Adj egy konkrét példát (pl. csomagtartalom-ellenőrzés vs. metaadat-naplózás)!

```
_________________________________________________________________________
_________________________________________________________________________
```

---

## 5. Összefoglaló és önreflexió

### 5.1 A legfontosabb tanulságok (a diák írja)

```
1. _____________________________________________________________________
2. _____________________________________________________________________
3. _____________________________________________________________________
```

### 5.2 Önreflexiós kérdéssor

| Kérdés | 1–5 skála | Indoklás |
|---|---|---|
| Megértem, hogyan szerez MITM-pozíciót egy L2-támadás | __ | ______ |
| Meg tudom mondani, hogy HTTP vs. HTTPS esetén mit lát egy megfigyelő | __ | ______ |
| Értem, hogy a DNSSEC ≠ DoH — más-mást véd | __ | ______ |
| Felismerem, mikor van létjogosultsága a TLS-interceptiónak, és milyen feltételekkel | __ | ______ |
| Az adatvédelmi elveket át tudom ültetni a hálózati naplózásra | __ | ______ |
| Tudom, melyik protokoll lecserélése melyik sebezhetőséget szünteti meg | __ | ______ |

### 5.3 Továbbgondolás (haladóknak, házi feladatként)

Válassz egyet, és adj be 1 oldalas elemzést:

1. **ECH (Encrypted Client Hello):** hogyan változtatja meg az SNI-alapú forgalomelemzést, és milyen új vitát hoz a hálózatüzemeltető–felhasználó viszonyába?
2. **802.1X:** miért ez a szabványos megoldás az „ismeretlen eszköz" problémára (végponti biztonság, Modul 10.1), és hogyan viszonyul a Layer 2-védelmekhez? (EAP-TLS vs. PEAP)
3. **Zero Trust:** hova kerül a Layer 2 hardening egy zero trust modellben? Kiegészíti-e vagy helyettesíthető-e mikroszegmentációval?
4. **DoH-központosítás:** a nagy DoH-szolgáltatók miért lettek a DNS-adatvédelem központi pontjai — összeegyeztethető ez a decentralizációval?

---

## 6. Értékelés

### 6.1 A reflexiós lap értékelési rácsa

| Kritérium | 5 pont (kiváló) | 4 pont | 3 pont | 2 pont |
|---|---|---|---|---|
| **Protokollismeret** | Minden protokollnál pontos: mit véd és mit nem, és miért | Kisebb pontatlanságok | Félreértések (pl. DNSSEC = titkosítás) | Súlyos fogalmi tévedés |
| **MITM-elemzés** | Pontosan levezeti, mit lát és mit módosít a támadó | Nagyrészt pontos | Felületes | Nincs pozíció-értés |
| **Adatvédelmi elemzés** | Valódi dilemmamérlegelés, alternatívák feltárása | Jó, de kissé sablonos | Formalitás | Hiányzik |
| **Önreflexió és laborkapcsolat** | Konkrét laboros megfigyelésekkel támasztja alá | Néhány konkrétum | Általános | Nincs kapcsolat |

### 6.2 Összpontszám

```
Protokollismeret:        ____ / 5
MITM-elemzés:            ____ / 5
Adatvédelmi elemzés:     ____ / 5
Önreflexió:              ____ / 5
                         --------
Összesen:                ____ / 20  →  jegy: ______  (18+=5, 14+=4, 11+=3, 8+=2)

Laborvezető megjegyzése: ________________________________________________
```

---

*Megjegyzés oktatónak: a lap szándékosan dilemma-alapú — az adatvédelmi kérdéseknél nincs egyetlen „helyes" válasz, a pontozás a mérlegelés minőségét értékeli. A 3.2 SSL-stripping/HSTS-rész, a 3.3 DNSSEC/DoH-elkülönítés és a 4.2 GDPR-elvpárosítás a leginkább differenciáló részek.*
