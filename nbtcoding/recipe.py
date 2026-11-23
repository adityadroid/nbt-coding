"""Apply a named coding recipe (nbtcoding/recipes.json): one change that may span several modules.

    python3 -m nbtcoding.recipe                       list recipes
    python3 -m nbtcoding.recipe <name>                dry run against the newest saved full read (no car)
    python3 -m nbtcoding.recipe <name> --car          review against the car: fresh read + backup per module, no write
    python3 -m nbtcoding.recipe <name> --car --write  write it (asks for the owner phrase), module by module

Each step is (module, BMW function name, value label). Names and labels are resolved against the module's own CAFD
and the name overlay, so a recipe follows a setting if a CAFD version moves it; a step whose name or label the CAFD
does not have stops the recipe before anything is written. All steps of one module go into one signed write (one
review, one signature). Modules are written in the order they first appear; if one fails, the rest are not written.
"""
from __future__ import annotations

import glob
import json
import os
import sys

from . import caf as caf_mod
from . import decode, edit, modules, names, sign, write

HERE = os.path.dirname(__file__)


def load() -> dict:
    with open(os.path.join(HERE, "recipes.json"), encoding="utf-8") as fh:
        return json.load(fh)["recipes"]


def resolve(c: caf_mod.Caf, steps: list) -> list[dict]:
    """[(name, label)] -> [{key, scalar, name, label}] for one module's CAFD. Raises on anything not found."""
    overlay = names.load(c.cafd_id).get("functions", {})
    by_name = {}
    for key, meta in overlay.items():
        by_name.setdefault(meta.get("name", ""), []).append((key, meta.get("values", {})))
    out = []
    for name, label in steps:
        hits = by_name.get(name, [])
        if len(hits) != 1:
            raise ValueError("%s: %d settings named %r in CAFD %s" % (c.cafd_id, len(hits), name, name))
        key, values = hits[0]
        scal = [int(s) for s, lab in values.items() if lab == label]
        if len(scal) != 1:
            raise ValueError("%s: no value %r (has %s)" % (name, label, sorted(set(values.values()))))
        out.append({"key": key, "scalar": scal[0], "name": name, "label": label})
    return out


def grouped(recipe: dict) -> list[tuple[str, list]]:
    order, groups = [], {}
    for mod, name, label in recipe["steps"]:
        if mod not in groups:
            order.append(mod); groups[mod] = []
        groups[mod].append((name, label))
    return [(m, groups[m]) for m in order]


def dry_run(recipe: dict) -> int:
    files = sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-full-all-*.json")))
    if not files:
        print("no saved full read (tools_fullread_all.py)"); return 2
    probe = json.load(open(files[-1], encoding="utf-8"))
    print("dry run against", os.path.basename(files[-1]))
    for mod, steps in grouped(recipe):
        ok, why = edit.writable(mod)
        m = next((x for x in probe["modules"] if x["addr"].upper() == "%02X" % modules.addr_of(mod)), None)
        if not m:
            print("  %s: not in the saved read" % mod); return 1
        cafd = next(e for e in m["svk"] if e.get("class") == "CAFD")
        c = caf_mod.parse(decode.find_cafd_xml(cafd["id"], cafd["version"]))
        before = {a.upper(): bytes.fromhex(h) for a, h in m["datagroups"].items()}
        changes = resolve(c, steps)
        after, done = edit.build_after(c, before, changes)
        p = edit.plan(mod, c, before, after)
        print("  %s (%s): %s" % (mod, "writable" if ok else "NOT writable: " + why, ", ".join(p["changed"]) or "already set"))
        for ch, d in zip(changes, done):
            print("     %-34s %s -> %s" % (ch["name"], d["from"], ch["label"]))
    return 0


def on_car(recipe: dict, do_write: bool) -> int:
    from . import server
    unlock = ""
    if do_write:
        mods = {m for m, _ in grouped(recipe)}
        # car 2026-11-23: the CAS reset at the end of a CAS write switches the ignition off and stops a running engine
        power = ("ENGINE OFF, ignition on (charger if you can). The CAS restart at the end switches the ignition off"
                 if "CAS" in mods else "Engine running or charger on")
        print("Writing %s. %s. Type %s to go on:" % (recipe["title"], power, write.UNLOCK))
        unlock = input("> ").strip()
        if unlock != write.UNLOCK:
            print("not confirmed, nothing written"); return 1
    for mod, steps in grouped(recipe):
        conn = server.connect()
        try:
            c, _before, _vin = server.read_module(conn, mod)
        finally:
            conn.close()
        changes = [{"key": x["key"], "scalar": x["scalar"]} for x in resolve(c, steps)]
        p = server._plan({"module": mod, "changes": changes})
        if p.get("error"):
            print("  %s: %s" % (mod, p["error"])); return 1
        print("  %s: backup %s" % (mod, p["backup"]))
        for ch in p["changes"]:
            print("     %-34s %s -> %s" % (ch["name"], ch["from"], ch["to"]))
        if p.get("nothing_to_do"):
            continue
        if not do_write:
            continue
        r = server._write({"token": p["token"], "unlock": unlock})
        if r.get("error") or not r.get("verified"):
            print("  %s: %s — stopping; restore %s to undo" % (mod, r.get("error") or r.get("warning"), p["backup"]))
            return 1
        print("  %s: written and verified" % mod)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    recipes = load()
    if not argv:
        for k, r in recipes.items():
            print("  %-26s %-10s %s" % (k, r["risk"].split()[0], r["title"]))
        return 0
    r = recipes.get(argv[0])
    if not r:
        print("no recipe %r" % argv[0]); return 2
    print(r["title"], "| risk:", r["risk"])
    if "--car" not in argv:
        rc = dry_run(r)
    else:
        rc = on_car(r, "--write" in argv)
    print("test:", r["test"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
