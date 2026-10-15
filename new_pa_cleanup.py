"""Plan and optionally delete unused PAN-OS objects. Default: read-only dry run."""

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import xml.etree.ElementTree as ET

from pan.xapi import PanXapi, PanXapiError


TYPES = ("address", "address-group", "service", "service-group", "tag")
ADDRESS_TYPES = {"address", "address-group"}
SERVICE_TYPES = {"service", "service-group"}
ADDRESS_FIELDS = {
    "source", "destination", "source-address", "destination-address",
    "translated-address",
}


@dataclass(frozen=True, order=True)
class ObjectKey:
    kind: str
    name: str

    def __str__(self):
        return f"{self.kind} {self.name}"


@dataclass
class Plan:
    base: str
    objects: dict
    users: dict
    rules: list
    layers: list

    @property
    def deleting(self):
        return {key for layer in self.layers for key in layer}

    def object_path(self, key):
        return f"{self.base}/{key.kind}/entry[@name={xpath_literal(key.name)}]"

    @property
    def paths(self):
        return self.rules + [self.object_path(key) for layer in self.layers for key in layer]


def xpath_literal(value):
    """Do not interpolate unescaped names into an API XPath."""
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    raise ValueError("An XPath name cannot contain both single and double quotes")


def config_element(root):
    """Accept an exported config or the usual XML API response/result wrapper."""
    if root is None:
        raise ValueError("The device returned no configuration")
    if root.tag == "config":
        return root
    configs = root.findall(".//config")
    if len(configs) != 1:
        raise ValueError("Expected exactly one <config> element")
    return configs[0]


def analyze(cfg, *, vsys="vsys1", device_group=None, keep=(), delete_all=False):
    """Build a conservative dependency graph; never contact or modify a device.

    Unrecognised reference fields and references outside the selected scope
    retain matching objects. This may keep extra objects instead of guessing.
    """
    cfg = config_element(cfg)
    scope_type, scope_name = ("device-group", device_group) if device_group else ("vsys", vsys)
    matches = [
        (device, scope)
        for device in cfg.findall("./devices/entry")
        for scope in device.findall(f"./{scope_type}/entry")
        if scope.get("name") == scope_name
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one {scope_type} named {scope_name!r}; found {len(matches)}")
    device, scope = matches[0]
    device_name = device.get("name")
    if not device_name:
        raise ValueError("The device entry has no name")
    base = (f"/config/devices/entry[@name={xpath_literal(device_name)}]"
            f"/{scope_type}/entry[@name={xpath_literal(scope_name)}]")
    objects = {}
    for kind in TYPES:
        for entry in scope.findall(f"{kind}/entry"):
            name = entry.get("name")
            if not name:
                raise ValueError(f"An entry in {kind} has no name")
            xpath_literal(name)
            key = ObjectKey(kind, name)
            if key in objects:
                raise ValueError(f"Duplicate object: {key}")
            objects[key] = entry

    parent = {child: node for node in cfg.iter() for child in node}
    owner_of = {entry: key for key, entry in objects.items()}

    def xml_path(element):
        parts = []
        while element is not None:
            part = element.tag
            if element.tag == "entry" and element.get("name") is not None:
                part += f"[@name={xpath_literal(element.get('name'))}]"
            parts.append(part)
            element = parent.get(element)
        return "/" + "/".join(reversed(parts))

    # Each rule has its own identity, including its device and scope.
    rule_owner = {}
    for rb in cfg.iter():
        if rb.tag in {"rulebase", "pre-rulebase", "post-rulebase"}:
            for section in rb:
                for rule in section.findall("rules/entry"):
                    rule_owner[rule] = "rule " + xml_path(rule)
    rules = []
    if delete_all:
        for rb in scope:
            if rb.tag in {"rulebase", "pre-rulebase", "post-rulebase"}:
                for section in rb:
                    rules.extend(xml_path(rule) for rule in section.findall("rules/entry"))
    removing_rules = {"rule " + path for path in rules}

    def owner(element):
        while element is not None:
            if element in owner_of:
                return owner_of[element]
            if element in rule_owner:
                return rule_owner[element]
            element = parent.get(element)
        return "other settings or an object outside the selected scope"

    def reference_types(element):
        container = parent.get(element)
        field = container.tag if element.tag == "member" and container is not None else element.tag
        if field == "tag" or element.tag == "filter":
            return {"tag"}
        if field == "service":
            return SERVICE_TYPES
        if field in ADDRESS_FIELDS or field == "static":
            return ADDRESS_TYPES
        if field == "members" and container is not None:
            entry = parent.get(container)
            group = parent.get(entry)
            if group is not None and group.tag == "service-group":
                return SERVICE_TYPES
        return set(TYPES)  # Unknown fields are intentionally conservative.

    by_name = defaultdict(list)
    for key in objects:
        by_name[key.name].append(key)
    users = {key: set() for key in objects}
    for element in cfg.iter():
        text = (element.text or "").strip()
        if not text or element.tag == "description":
            continue
        names = {text}
        if element.tag == "filter":
            names.update(match[1] for match in re.findall(r"(['\"])(.*?)\1", text))
        who = owner(element)
        if who in removing_rules:
            continue
        kinds = reference_types(element)
        for name in names:
            for key in by_name.get(name, ()):
                if key.kind in kinds:
                    users[key].add(who)
    for name in keep:
        if name not in by_name:
            raise ValueError(f"KEEP object {name!r} does not exist in the selected scope")
        for key in by_name[name]:
            users[key].add("KEEP list")

    # Dynamic groups can use tagged addresses without naming them in XML.
    # Filters can contain NOT, so matching just the quoted tags is insufficient.
    # Without runtime membership data, keep all address candidates while any
    # such group remains. An unused dynamic group can still be deleted first.
    for group, entry in objects.items():
        if group.kind == "address-group" and entry.find("dynamic/filter") is not None:
            for key in objects:
                if key.kind in ADDRESS_TYPES and key != group:
                    users[key].add(group)

    gone, layers = set(), []
    while True:
        layer = sorted(key for key in objects if key not in gone and users[key] <= gone)
        if not layer:
            break
        layers.append(layer)
        gone.update(layer)
    return Plan(base, objects, users, sorted(rules), layers)


def print_plan(plan):
    for key in sorted(plan.objects.keys() - plan.deleting):
        reasons = ", ".join(sorted(str(user) for user in plan.users[key]))
        print(f"KEEP    {key}: {reasons}")
    for path in plan.rules:
        print(f"DELETE  rule {path}")
    for number, layer in enumerate(plan.layers, 1):
        for key in layer:
            print(f"DELETE  layer {number}: {key}")
    print(f"SUMMARY: {len(plan.objects)} objects; {len(plan.deleting)} eligible for deletion; "
          f"{len(plan.objects) - len(plan.deleting)} kept; {len(plan.rules)} rules to delete")


def write_private(path, content):
    """Create a new file; never overwrite a backup or an existing user file."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)


def fingerprint(cfg):
    return hashlib.sha256(ET.tostring(cfg)).hexdigest()


def read_device_config(api):
    api.get("/config")
    return config_element(api.element_result)


def connect(args):
    # pan-python is the XML API client used underneath pan-os-python. Pass a
    # verified TLS context explicitly; its default context does not verify TLS.
    context = ssl.create_default_context(cafile=args.ca_bundle)
    api_key = os.environ.get("PAN_API_KEY")
    password = None
    if not api_key:
        if not args.user:
            raise ValueError("Supply --user (or PAN_USER), or set PAN_API_KEY")
        password = os.environ.get("PAN_PASSWORD") or getpass.getpass("Firewall password: ")
        if not password:
            raise ValueError("The password cannot be empty")
    return PanXapi(hostname=args.host, api_username=args.user,
                   api_password=password, api_key=api_key,
                   timeout=args.timeout, ssl_context=context)


def apply_plan(api, plan, *, commit=False):
    completed = 0
    for path in plan.paths:
        try:
            api.delete(path)
        except (Exception, KeyboardInterrupt) as exc:
            raise RuntimeError(
                f"Stopped after {completed}/{len(plan.paths)} confirmed deletions. "
                f"The result of the request for {path} is uncertain. "
                "Earlier changes may remain in candidate configuration. "
                "No automatic commit was sent. Inspect the device before retrying."
            ) from exc
        completed += 1
        print(f"DELETED {path}")
    if commit and completed:
        try:
            api.commit(cmd="<commit></commit>", sync=True, timeout=api.timeout)
            result = api.element_result
            if result is None or result.findtext(".//job/result") != "OK":
                raise RuntimeError("Commit did not report a successful job")
        except (Exception, KeyboardInterrupt) as exc:
            raise RuntimeError(
                f"All {completed} deletions completed, but commit failed or its result is unknown. "
                "Inspect the commit job and candidate configuration on the device."
            ) from exc
        print("Commit completed successfully.")
    elif completed:
        print("Changes are in candidate configuration. No commit was sent.")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="Firewall or Panorama management hostname/IP")
    source.add_argument("--config", type=Path, help="Analyze exported XML offline; no device access")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--vsys", default="vsys1")
    scope.add_argument("--device-group", help="Select a Panorama device group instead of a VSYS")
    parser.add_argument("--user", default=os.environ.get("PAN_USER"))
    parser.add_argument("--keep", action="append", default=[], metavar="NAME")
    parser.add_argument("--delete-all", action="store_true",
                        help="Include selected-scope rules; protected objects can still be kept")
    parser.add_argument("--apply", action="store_true", help="Prompt to execute the displayed plan")
    parser.add_argument("--commit", action="store_true",
                        help="With --apply, commit ALL pending candidate changes after success")
    parser.add_argument("--plan-file", type=Path, help="Save a JSON plan to a new file")
    parser.add_argument("--backup-dir", type=Path, default=Path("backups"))
    parser.add_argument("--ca-bundle", help="Trusted CA PEM file for the device certificate")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    if args.config and (args.apply or args.commit):
        parser.error("Offline XML analysis cannot apply changes or commit")
    if args.commit and not args.apply:
        parser.error("--commit requires --apply")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        api = None
        if args.config:
            cfg = config_element(ET.parse(args.config).getroot())
        else:
            api = connect(args)
            cfg = read_device_config(api)
            args.backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
            backup = args.backup_dir / f"backup-{stamp}.xml"
            write_private(backup, ET.tostring(cfg, encoding="utf-8", xml_declaration=True))
            print(f"Candidate configuration backup: {backup}")
        digest = fingerprint(cfg)
        plan = analyze(cfg, vsys=args.vsys, device_group=args.device_group,
                       keep=args.keep, delete_all=args.delete_all)
        print(f"Target: {args.host or args.config}   Scope: {plan.base}")
        print_plan(plan)
        if args.plan_file:
            data = {
                "target": args.host or str(args.config), "scope": plan.base,
                "config_sha256": digest, "rules": plan.rules,
                "object_layers": [[{"type": key.kind, "name": key.name,
                                     "xpath": plan.object_path(key)} for key in layer]
                                  for layer in plan.layers],
                "kept": [{"type": key.kind, "name": key.name,
                          "used_by": sorted(str(user) for user in plan.users[key])}
                         for key in sorted(plan.objects.keys() - plan.deleting)],
            }
            write_private(args.plan_file, json.dumps(data, indent=2).encode("utf-8"))
        if not args.apply:
            print("DRY RUN finished. No changes or commit were sent.")
            return 0
        if not plan.paths:
            print("Nothing to delete. No changes or commit were sent.")
            return 0
        if args.commit:
            print("WARNING: Commit includes ALL pending candidate changes, not just this plan.")
        expected = f"{args.host}/{args.device_group or args.vsys}"
        if input(f"Type {expected!r} to execute this plan: ").strip() != expected:
            print("Cancelled. No changes or commit were sent.")
            return 0
        if fingerprint(read_device_config(api)) != digest:
            raise ValueError("Candidate configuration changed after planning. Rerun to create a new plan.")
        apply_plan(api, plan, commit=args.commit)
        return 0
    except PanXapiError:
        # API exceptions can contain request details: do not print credentials.
        print("ERROR: Device API request failed. Check authentication, connectivity and TLS trust.",
              file=sys.stderr)
        return 1
    except (OSError, ET.ParseError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Cancelled. No further requests were sent.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
