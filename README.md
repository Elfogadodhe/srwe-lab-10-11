# SRWE Modul 10–11 — Layer 2 támadás/védelem labor

Cisco NetAcad **Switching, Routing and Wireless Essentials (SRWE) v7.0** Modul 10 (LAN Security Concepts) és Modul 11 (Switch Security Configuration) tananyaghoz készült, teljes hallgatói laborcsomag.

A labor **12 Layer 2 támadást** és a hozzájuk tartozó Cisco-védelmet járja végig a `támadás → megfigyelés → védelem → újratámadás (elhiúsul)` minta szerint. A támadó kliens Python (scapy) szkripteket futtat, a Cisco-konfiguráció YAML-ben van definiálva és netmiko tölti fel az eszközökre.

## Repó-struktúra

| Útvonal | Tartalom |
|---|---|
| `docs/srwe-labor-konyv.md` | **Kezdd itt:** a teljes labor egyetlen könyvben — a Python/venv/VSCode környezet felállításától nulláról, az összes fájlon át, a 12 támadás lépésről lépésre, másolható parancsokkal. Pythonhoz nem kell előismeret. |
| `docs/hallgatoi-feladatlap.md` | Hallgatói munkalap (12 fázis, kitöltendő) |
| `docs/reflexios-lap.md` | Reflexiós és adatvédelmi lap (MITM / HTTP / HTTPS / DNS / DoH elemzés, GDPR) |
| `docs/index-es-deploy-checklist.md` | Deployment checklist + oktatói megoldókulcs |
| `docs/AI-instrukcio.md` | AI-instrukció (reprodukciós instrukció + bővítési roadmap) |
| `requirements.txt` | Python-függőségek (netmiko, pyyaml, scapy) — `pip install -r requirements.txt` |
| `inventory.yml` | Eszközleltár (IP, hitelesítés) a `push_config.py`-hoz |
| `configs/baseline.yml` | Kiinduló (sebezhető) eszközbeállítások |
| `configs/mitigations.yml` | Védelmi beállítások fázisonként (szekciókra bontva) |
| `push_config.py` | Beállításokat tölt az eszközökre a YAML-ekből (netmiko) |
| `attacker/` | A 12 támadó szkript (scapy) — a Linux ATTACKER gépen fut |
| `verify.py` | Ellenőrző szkript: 27 regex-ellenőrzés + JSON-kimenet. **Nem ad jegyet és nem pontoz** — csak megnézi, hogy minden védelem a helyén van-e (Pipa/Hiba). |

## A 12 fázis

1. MAC address table overflow (CAM flood) → `port-security`
2. MAC spoofing → `port-security` (sticky)
3. DHCP starvation → `dhcp-snooping` (+ rate limit)
4. DHCP spoofing (rogue DHCP) → `dhcp-snooping` (trust)
5. ARP poisoning (kétirányú MITM) → `dai`
6. STP manipulation (root takeover) → `stp-guard`
7. VLAN hopping (DTP) → `vlan-hop`
8. CDP recon + nyílt Telnet → `hardening`
9. 802.1Q double-tagging → `native-vlan-hardening`
10. IP spoofing → `ip-source-guard`
11. LLDP recon → `lldp-hardening`
12. ICMP redirect (gateway MITM) → `icmp-redirect`

A következő iterációk bővítési roadmapját (13–16. fázis: HSRP eltérítés, IPv6 RA spoofing, DHCPv6 starvation/spoofing, VTP injection) lásd: `docs/AI-instrukcio.md`, RÉSZ 0.

## Biztonsági megkötés

A labor **kizárólag izolált, oktatási célú hálózati szegmensen** futtatható. A támadó szkriptek valódi Layer 2/3 támadásokat szimulálnak — éles vagy intézményi hálózaton tilos futtatni őket.
