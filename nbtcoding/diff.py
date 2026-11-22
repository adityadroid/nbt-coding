"""Find which coding setting a feature controls, by comparing two reads of a module. READ-ONLY.

    python3 -m nbtcoding.diff <before.json> <after.json> [MODULE|0xADDR]

The reliable, safe way to locate an unknown feature: read a module's coding, toggle the feature in the car (iDrive menu,
key fob, whatever), read it again, and diff. Every coding function whose value changed is printed with its location
(datagroup:byte:mask), old value and new value. One of them is the feature — no guessing a byte offset.

Both files are probe files (python3 -m nbtcoding.probe) or coding backups (saved on every GUI read). The module is
picked by name (CAS/FRM/KOMBI/HU_NBT) or diagnostic address; omit it to diff every module the two reads share.
Compares decoded functions, so a one-bit change shows as exactly one changed setting, named if the overlay knows it.
"""
from __future__ import annotations

import json
import os
import sys

from . import caf as caf_mod
from . import decode as decode_mod
from . import names as names_mod

from .modules import MODULES as _ALL
ADDR_NAME = {"%02X" % m[0]: m[1] for m in _ALL}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if "modules" in d:                       # a probe file: {modules:[{addr, svk, datagroups}]}
        out = {}
        for m in d["modules"]:
            cafd = next((e["id"] for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
            out[m["addr"].upper()] = {"cafd": cafd, "datagroups": m.get("datagroups", {})}
        return out
    if "datagroups" in d:                     # a coding backup: one module
        addr = next((a for a, n in ADDR_NAME.items() if n == d.get("module")), d.get("module", "?"))
        return {addr.upper(): {"cafd": d.get("cafd_id"), "datagroups": d["datagroups"]}}
    raise ValueError("%s is neither a probe nor a coding backup" % path)


def _features(mod: dict) -> dict:
    cafd = mod.get("cafd")
    xml = decode_mod.find_cafd_xml(cafd) if cafd else None
    if not xml:
        return {}
    c = caf_mod.parse(xml)
    coding = {a.upper(): bytes.fromhex(h) for a, h in mod["datagroups"].items()}
    by_upper = {dg.addr.upper(): dg.addr for dg in c.datagroups}
    coding = {by_upper.get(a, a): b for a, b in coding.items()}
    overlay = names_mod.load(c.cafd_id)
    return {f.key: f for f in decode_mod.build_features(c, coding, overlay)}


def diff_module(before: dict, after: dict) -> list[dict]:
    fb, fa = _features(before), _features(after)
    out = []
    for key in sorted(set(fb) & set(fa)):
        a, b = fb[key], fa[key]
        if a.current is None or b.current is None or a.current == b.current:
            continue
        out.append({"key": key, "datagroup": b.datagroup, "start": b.start, "end": b.end, "mask": b.mask,
                    "name": b.name, "from": a.current_label, "to": b.current_label})
    return out


def main() -> int:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    before, after = _load(sys.argv[1]), _load(sys.argv[2])
    want = sys.argv[3] if len(sys.argv) > 3 else ""
    want_addr = None
    if want:
        want_addr = next((a for a, n in ADDR_NAME.items() if n == want.upper()), want.replace("0x", "").upper())
    shared = sorted(set(before) & set(after))
    total = 0
    for addr in shared:
        if want_addr and addr != want_addr:
            continue
        if before[addr].get("cafd") != after[addr].get("cafd"):
            print("%s: CAFD changed between the two reads (%s -> %s), skipped"
                  % (addr, before[addr].get("cafd"), after[addr].get("cafd")))
            continue
        changes = diff_module(before[addr], after[addr])
        name = ADDR_NAME.get(addr, addr)
        if not decode_mod.find_cafd_xml(before[addr].get("cafd") or ""):
            continue
        print("\n== %s (%s): %d setting(s) changed" % (name, addr, len(changes)))
        for c in changes:
            loc = "%s:b%d%s:%02X" % (c["datagroup"], c["start"],
                                     "-%d" % c["end"] if c["end"] != c["start"] else "", c["mask"])
            nm = c["name"] or "(unnamed — this is the feature's location)"
            print("   %-22s %-28s %s -> %s" % (loc, nm, c["from"], c["to"]))
        total += len(changes)
    if total == 0:
        print("\nNo decoded setting changed. (Nothing toggled, the reads are identical, or the CAFD is not in cafd/.)")
    else:
        print("\n%d changed setting(s). To name one: add its location key to names/<CAFD>.json." % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
