#!/usr/bin/env python3
"""YAML-ban definiált konfiguráció feltöltése Cisco eszközökre.

Használat:
    python push_config.py inventory.yml configs/baseline.yml
    python push_config.py inventory.yml configs/mitigations.yml port-security
    python push_config.py inventory.yml configs/mitigations.yml   # minden szekció

Megjegyzés: a pusher NEM szúr be automatikus 'exit'-et a konténerparancsok
után — a YAML-ban azok explicit módon szerepelnek.
"""
import sys
import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


# Egy eszköz-konfigban ezek a (opcionális) kulcsok fordulhatnak elő.
CONFIG_KEYS = {"global", "dhcp_pool", "interfaces", "post"}


def parse_interface_key(key: str):
    """'range Fa0/4 - 23' -> ('interface range', 'Fa0/4 - 23')"""
    if key.startswith("range "):
        return "interface range", key[len("range "):].strip()
    return "interface", key


def is_device_cfg(body) -> bool:
    """Igaz, ha a `body` egy eszköz-konfig (global/interfaces/dhcp_pool/post
    kulcsokkal), nem pedig egy szekció (ami eszközneveket tartalmaz).
    Így ugyanaz a szkript kezeli a lapos `baseline.yml`-t (eszköz → konfig)
    és a szekciós `mitigations.yml`-t (szekció → eszköz → konfig) is."""
    return isinstance(body, dict) and bool(set(body.keys()) & CONFIG_KEYS)


def push_device(inventory: dict, device_name: str, device_cfg: dict, save: bool = True):
    if device_name not in inventory.get("devices", {}):
        print(f"[HIBA] A(z) '{device_name}' eszköz nincs az inventory.yml "
              f"'devices' listájában — kihagyva.")
        return False
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

    # A két konfig-szerkezet automatikus felismerése:
    #   - lapos (baseline.yml):   eszköz → konfig            (top-level: S1/S2/R1)
    #   - szekciós (mitigations): szekció → eszköz → konfig  (top-level: port-security, ...)
    flat = all(is_device_cfg(body) for body in config.values())

    # Normalizálás egységes (szekció, eszköz, konfig) listává.
    tasks = []
    if flat:
        if section_filter:
            print(f"[MEGJEGYZÉS] A(z) '{cfg_path}' lapos (eszköz-szintű) fájl; "
                  f"a(z) '{section_filter}' szűrőt eszköznévként értelmezem.")
        for device_name, device_cfg in config.items():
            tasks.append((None, device_name, device_cfg))
    else:
        for section_name, section_cfg in config.items():
            for device_name, device_cfg in section_cfg.items():
                tasks.append((section_name, device_name, device_cfg))

    # Szűrés: szekciós fájlnál szekciónévre, lapos fájlnál eszköznévre.
    if section_filter:
        tasks = [t for t in tasks
                 if (t[0] == section_filter) or (t[0] is None and t[1] == section_filter)]
        if not tasks:
            print(f"[HIBA] A(z) '{section_filter}' szűrőre nincs találat a(z) "
                  f"'{cfg_path}' fájlban.")
            sys.exit(1)

    failures = []
    current_section = object()  # szekció-fejléc csak változáskor
    for section_name, device_name, device_cfg in tasks:
        if section_name is not None and section_name != current_section:
            print(f"\n########## SZEKCIÓ: {section_name} ##########")
            current_section = section_name
        if not push_device(inventory, device_name, device_cfg):
            label = f"{section_name}/{device_name}" if section_name else device_name
            failures.append(label)

    if failures:
        print(f"\nSIKERTELEN: {', '.join(failures)}")
        sys.exit(2)
    print("\nKész.")


if __name__ == "__main__":
    main()
