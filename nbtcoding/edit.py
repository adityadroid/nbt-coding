"""Turn changes picked in the GUI into a signed write plan, and run it. The GUI's only path to writing.

A change is {"key": <caf.Func.key()>, "scalar": <value>}; a restore is a saved backup's datagroups. Either way the
result is a write.plan() over a coding read from the car moments before: only the content datagroups that differ plus
the re-signed signature datagroup are written, signature last, and the plan self-verifies before it is offered.

Who may be written (writable()):
  - HU_NBT never: the Android Auto mod lives there.
  - Only modules whose signer reproduced the car's own signature (sign.PROVEN). CAS is, since 2026-11-22 (keyed MD5);
    it is the immobiliser module, so the GUI asks for extra care.
Executing (execute()) additionally needs the exact owner unlock phrase and the car still holding the coding the plan was
built from. Pure Python standard library.
"""
from __future__ import annotations

import os

from . import caf as caf_mod
from . import modules, sign, write

NEVER = {"HU_NBT": "the head unit carries the Android Auto mod; coding it is off-limits in this tool"}
# Owner override, one run at a time (Adi, 2026-11-23: lock-horn menu + key cooling menu live in the head unit's coding).
# Coding writes the CAFD only, not the file system the Android Auto mod lives in; its signer is proven like the rest.
if os.environ.get("NBTCODING_ALLOW_HU") == "1":
    NEVER = {}


def writable(module: str) -> tuple[bool, str]:
    if module in NEVER:
        return False, NEVER[module]
    if module not in sign.PROVEN:
        return False, "the signer for %s has not reproduced this car's own signature yet" % module
    if not signer_key(module):
        return False, "no signing key for %s in keys/" % module
    if module in modules.BY_NAME and not sign.load_key(modules.BY_NAME[module][3], "l3"):
        return False, "no SecurityAccess key for %s in keys/" % module
    return True, "signer proven against this car"


def signer_key(module: str):
    if module == "CAS":
        return sign.load_cas_key(sign.CAS_BTLD)
    if module in sign.BTLD:
        return sign.load_key(modules.BY_NAME[module][3], "ncd")
    return None


def _shift(mask: int) -> int:
    s = 0
    while mask and not (mask >> s) & 1:
        s += 1
    return s


def allowed_scalars(f: caf_mod.Func) -> set[int]:
    """Values BMW defines for a single-byte field (right-aligned). Empty for multi-byte fields."""
    if f.end != f.start:
        return set()
    width = f.mask >> _shift(f.mask)          # CAF values are stored right-aligned (see decode._scalar)
    return {v[0] & width for v in f.values if v}


def build_after(c: caf_mod.Caf, before: dict, changes: list[dict]) -> tuple[dict, list[dict]]:
    """Apply GUI changes to a copy of `before`. Refuses unknown keys, multi-byte fields, values BMW does not define,
    and anything in the signature datagroup."""
    by_key = {f.key(): f for f in c.all_funcs()}
    after = dict(before)
    done = []
    for ch in changes:
        f = by_key.get(ch.get("key", ""))
        if not f:
            raise ValueError("unknown setting %r" % ch.get("key"))
        if f.dg_addr.upper() == c.sign_addr.upper():
            raise ValueError("%s is inside the signature block" % f.key())
        allowed = allowed_scalars(f)
        if not allowed:
            raise ValueError("%s spans several bytes; editing those is not supported" % f.key())
        scalar = int(ch.get("scalar"))
        if scalar not in allowed:
            raise ValueError("%s: value %d is not one BMW defines (%s)" % (f.key(), scalar, sorted(allowed)))
        cur = f.scalar(after[f.dg_addr.upper()]) if f.dg_addr.upper() in after else None
        after = write.apply_change(after, f, scalar)
        done.append({"key": f.key(), "from": cur, "to": scalar})
    return after, done


def plan(module: str, c: caf_mod.Caf, before: dict, after: dict) -> dict:
    ok, why = writable(module)
    p = write.plan(before, after, c, signer_key(module), module)
    p["writable"], p["why"] = ok, why
    return p


def execute(conn, tgt: int, module: str, c: caf_mod.Caf, before: dict, after: dict, unlock: str,
            current: dict) -> dict:
    """Write it. `current` is a read taken just now; it must equal `before` in every datagroup the plan covers."""
    ok, why = writable(module)
    if not ok:
        raise PermissionError("refused: %s" % why)
    drift = [a for a in after if a in before and current.get(a) != before.get(a)]
    if drift:
        raise RuntimeError("the car's coding changed since the review (%s); review again" % ", ".join(sorted(drift)))
    l3 = sign.load_key(modules.BY_NAME[module][3], "l3")
    return write.commit(conn, tgt, module, before, after, c, signer_key(module), l3,
                        dry_run=False, unlock=unlock, have_backup=True)
