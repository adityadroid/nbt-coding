"""Import BMW's real function names onto our trimmed CAFDs from an Open CAFD Map checkout.

BMW strips every group, function and value name in a CAFD to ".". Open CAFD Map
(https://github.com/shamair28/OpenCAFDMap, MIT) keeps BMW's original names from untrimmed CAFD dumps in
definitions/untrimmed/<CAFD id>.tsv.gz, keyed by each datagroup's exact function layout. A layout is the ordered list of
(start, end, mask) of every function in the datagroup; its hash is md5("start:end:mask;...")[:16], with the mask written
as eight bits plus "b". If our CAFD's datagroup has the same hash, every function in it sits exactly where the named one
does, so the names apply without guessing. Datagroups whose layout differs are left unnamed.

    python3 -m nbtcoding.import_names <OpenCAFDMap dir> [CAFD_ID ...]

With no CAFD ids it names every decrypted CAFD it finds in cafd/. Writes nbtcoding/names/<CAFD>.json, keeping any name
already in that file (hand-confirmed names win). Read-only against the car.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

from . import caf as caf_mod
from . import decode as decode_mod
from . import names as names_mod

SOURCE = "Open CAFD Map untrimmed names (github.com/shamair28/OpenCAFDMap, MIT)"


def mask_bits(mask: int) -> str:
    return format(mask & 0xFF, "08b") + "b"


def norm_mask(text: str) -> str:
    s = (text or "").strip()
    if re.fullmatch(r"[01]+b", s, re.I):
        return s.lower()
    if re.fullmatch(r"[0-9A-Fa-f]{1,2}", s):
        return format(int(s, 16), "08b") + "b"
    return s.lower()


def layout_hash(funcs) -> str:
    """funcs: ordered [(start, end, mask_bits)] -> 16 hex chars (Open CAFD Map's layout hash)."""
    s = ";".join("%d:%d:%s" % (int(a), int(b), m) for a, b, m in funcs)
    return hashlib.md5(s.encode("ascii")).hexdigest()[:16]


def dg_hash(dg: caf_mod.Datagroup) -> str:
    return layout_hash([(f.start, f.end, mask_bits(f.mask)) for f in dg.funcs])


def load_untrimmed(path: str):
    """(groups, funcs, values) from one <CAFD>.tsv.gz. Keys: (addr, hash) -> ..."""
    groups, fallback, funcs, values = {}, {}, defaultdict(dict), defaultdict(dict)
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            kind, addr, h, st, en, mk, val, name = (line.rstrip("\n").split("\t") + [""] * 8)[:8]
            addr = addr.upper()
            if not name:
                continue
            if kind == "G":
                (fallback if h == "*" else groups).setdefault(addr if h == "*" else (addr, h), name)
            elif kind == "F":
                funcs[(addr, h)][(int(st), int(en), norm_mask(mk))] = name
            elif kind == "V":
                values[(addr, h)][(int(st), int(en), norm_mask(mk), val.upper())] = name
    return groups, fallback, funcs, values


def overlay_for(c: caf_mod.Caf, untrimmed_path: str) -> tuple[dict, int, int]:
    """Names for one parsed CAFD. Returns (overlay, datagroups matched, datagroups total)."""
    groups, fallback, funcs, values = load_untrimmed(untrimmed_path)
    out = {"groups": {}, "functions": {}}
    hit = 0
    for dg in c.datagroups:
        addr = dg.addr.upper()
        h = dg_hash(dg)
        g = groups.get((addr, h)) or fallback.get(addr)
        if g:
            out["groups"][dg.addr] = g
        fmap = funcs.get((addr, h))
        if not fmap:
            continue
        hit += 1
        vmap = values.get((addr, h), {})
        for f in dg.funcs:
            k = (f.start, f.end, mask_bits(f.mask))
            name = fmap.get(k)
            if not name:
                continue
            vals = {str(int(vk[3], 16)): vn for vk, vn in vmap.items() if vk[:3] == k and re.fullmatch(r"[0-9A-F]+", vk[3])}
            out["functions"][f.key()] = {"name": name, "values": vals}
    return out, hit, len(c.datagroups)


def merge(existing: dict, new: dict, module: str = "") -> dict:
    """Hand-confirmed names already in the overlay win over imported ones."""
    res = {"module": existing.get("module") or module, "source": SOURCE,
           "groups": dict(new.get("groups", {})), "functions": dict(new.get("functions", {}))}
    res["groups"].update(existing.get("groups", {}))
    for k, v in existing.get("functions", {}).items():
        cur = res["functions"].setdefault(k, {"name": "", "values": {}})
        if v.get("name"):
            cur["name"] = v["name"]
        if v.get("desc"):
            cur["desc"] = v["desc"]
        cur["values"] = {**cur.get("values", {}), **v.get("values", {})}
    return res


def cafd_ids_on_disk() -> list[str]:
    ids = set()
    for base in decode_mod.CAFD_SEARCH:
        if base and os.path.isdir(base):
            for n in os.listdir(base):
                m = re.match(r"cafd_([0-9a-fA-F]{8})", n)
                if m:
                    ids.add(m.group(1).upper())
    return sorted(ids)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    ocm, ids = argv[0], [i.upper() for i in argv[1:]] or cafd_ids_on_disk()
    udir = os.path.join(ocm, "definitions", "untrimmed")
    if not os.path.isdir(udir):
        print("no definitions/untrimmed in %s (clone github.com/shamair28/OpenCAFDMap)" % ocm)
        return 2
    os.makedirs(names_mod.NAMES_DIR, exist_ok=True)
    for cid in ids:
        src = os.path.join(udir, "%s.tsv.gz" % cid)
        xml = decode_mod.find_cafd_xml(cid)
        if not xml:
            print("  %s: no decrypted CAFD in cafd/, skipped" % cid)
            continue
        if not os.path.exists(src):
            print("  %s: Open CAFD Map has no names for this CAFD yet" % cid)
            continue
        c = caf_mod.parse(xml)
        new, hit, total = overlay_for(c, src)
        merged = merge(names_mod.load(cid), new)
        with open(os.path.join(names_mod.NAMES_DIR, "%s.json" % cid), "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=1, sort_keys=True)
        print("  %s v%s: %d/%d datagroups match exactly, %d functions named"
              % (cid, c.version, hit, total, len(merged["functions"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
