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
