"""
pa_cleanup.py - delete unused objects on a Palo Alto firewall or Panorama (uses pan-os-python).
Install:  pip install pan-os-python
Edit the settings, then run:  python3 pa_cleanup.py
The result is printed on the screen.
"""
import re, time
import xml.etree.ElementTree as ET
from collections import defaultdict
from panos.firewall import Firewall
from panos.panorama import Panorama

# ------------------------- SETTINGS -------------------------
HOST = "192.168.1.1"
USER = "admin"
PASSWORD = "change-me"
VSYS = "vsys1"            # firewall: which vsys to clean
DEVICE_GROUP = ""         # "" = firewall. Name of a device group = connect to Panorama and clean that group

DRY_RUN = True            # True = only show what would be deleted
DELETE_ALL = False        # True = delete ALL objects and ALL rules (not only the unused ones)
COMMIT = False            # True = commit after deleting
KEEP = set()              # names that must never be deleted, e.g. {"SRV-DC01"}
# ------------------------------------------------------------

TYPES = ["address", "address-group", "service", "service-group", "tag"]
if DEVICE_GROUP:
    BASE = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{DEVICE_GROUP}']"
else:
    BASE = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{VSYS}']"

WHO = {"<rule>": "a rule", "<other>": "other settings", "<keep>": "your KEEP list"}


def analyze(cfg):
    """Return (rules, layers, objects, users). layers[0] = unused now, layers[1] = unused once layer 0 is gone, ..."""
    if DEVICE_GROUP:
        scope = cfg.find(f".//device-group/entry[@name='{DEVICE_GROUP}']")
    else:
        scope = cfg.find(f".//vsys/entry[@name='{VSYS}']")
    objects = {e.get("name"): (t, e) for t in TYPES for e in scope.findall(f"{t}/entry")}  # name -> (type, element)
    owner_of = {e: name for name, (t, e) in objects.items()}
    parent = {child: p for p in cfg.iter() for child in p}

    def who(el):
        """What contains this element: an object name, '<rule>' or '<other>'."""
        in_rule = False
        while el is not None:
            if el in owner_of:
                return owner_of[el]
            in_rule = in_rule or el.tag.endswith("rulebase")
            el = parent.get(el)
        return "<rule>" if in_rule else "<other>"

    # users[x] = everything that points at x
    users = defaultdict(set)
    for el in cfg.iter():
        text = (el.text or "").strip()
        if text:
            for name in {text, *re.findall(r"'([^']+)'", text)}:     # 2nd part: dynamic group filters
                if name in objects and who(el) != name:
                    users[name].add(who(el))
    for name in KEEP:
        users[name].add("<keep>")

    rules = [(rb.tag, s.tag, r.get("name")) for rb in scope if rb.tag.endswith("rulebase")
             for s in rb for r in s.findall("rules/entry")]
    if DELETE_ALL:
        for u in users.values():
            u.discard("<rule>")            # the rules are going away, so they no longer count

    gone, layers = set(), []
    while True:
        layer = [n for n in objects if n not in gone and users[n] <= gone]   # everything pointing at it is gone
        if not layer:
            return (rules if DELETE_ALL else []), layers, objects, users
        layers.append(layer)
        gone.update(layer)


def main():
    print("=" * 60)
    print(f"Firewall: {HOST}   Scope: {'device group ' + DEVICE_GROUP if DEVICE_GROUP else VSYS}")
    print("Mode:    ", "DELETE ALL (rules and objects)" if DELETE_ALL else "delete unused objects only")
    print("Dry run: ", "YES - nothing will be changed" if DRY_RUN else "NO - changes will be made")
    print("=" * 60)

    device = Panorama(HOST, USER, PASSWORD) if DEVICE_GROUP else Firewall(HOST, USER, PASSWORD)
    device.xapi.get("/config")
    cfg = device.xapi.element_result.find("config")
    backup = f"backup-{time.strftime('%Y%m%d-%H%M%S')}.xml"
    open(backup, "wb").write(ET.tostring(cfg))
    print(f"Config downloaded. Backup saved to: {backup}\n")

    rules, layers, objects, users = analyze(cfg)
    deleting = {n for layer in layers for n in layer}

    print(f"KEEP - still in use ({len(objects) - len(deleting)} objects)")
    for name in objects:
        if name not in deleting:
            by = ", ".join(WHO.get(u, "object " + u) for u in sorted(users[name]))
            print(f"  {objects[name][0]:<14} {name:<28} used by: {by}")

    if rules:
        print(f"\nDELETE - {len(rules)} rules")
        for rb, sec, name in rules:
            print(f"  rule  {sec:<10} {name}")
    for i, layer in enumerate(layers, 1):
        note = "nothing uses them" if i == 1 else "they were only used by the layer before, which is deleted"
        print(f"\nDELETE - layer {i} ({note})")
        for name in layer:
            print(f"  {objects[name][0]:<14} {name}")

    print(f"\nSUMMARY: {len(objects)} objects found, {len(deleting)} to delete, {len(objects) - len(deleting)} kept")

    if DRY_RUN:
        print("\nDRY RUN finished. Nothing was changed. Set DRY_RUN = False to delete.")
        return
    if DELETE_ALL:
        print("\nWARNING: DELETE_ALL is on. Starting in 5 seconds, press Ctrl+C to stop.")
        time.sleep(5)

    print()
    for rb, sec, name in rules:
        device.xapi.delete(f"{BASE}/{rb}/{sec}/rules/entry[@name='{name}']")
        print(f"deleted rule   {name}")
    for layer in layers:
        for name in layer:
            kind = objects[name][0]
            device.xapi.delete(f"{BASE}/{kind}/entry[@name='{name}']")
            print(f"deleted {kind:<14} {name}")

    if COMMIT:
        print("\nCommitting, please wait...")
        device.commit(sync=True)
        print("Commit finished.")
    else:
        print("\nDone. The changes are in the candidate config. Commit them yourself.")


if __name__ == "__main__":
    main()
