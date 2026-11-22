"""Write coding back to a module — the signed choreography. GATED: a real-car write needs explicit unlock.

The write that a module accepts (for the original-NBT-era F-series, offline-signed):

    10 03 ; 10 41              extended session, then coding session
    27 01 <testerId> -> seed  SecurityAccess L3 request
    27 02 <signed key>        answer the 8-byte seed: MD5([testerId][BTLD][seed]) raw-RSA with the L3 private key
    2E <dg> <bytes> ...       write each CHANGED coding datagroup
    2E <signDg> <signature>   write the re-signed signature datagroup LAST (nbtcoding.sign)
    (read each back, compare)
    31 01 0F01                CheckCodingSignature — status bytes must be all zero
    2E 37FE <cps>             coding protection status
    11 01                     ECU reset; the module reboots and re-verifies

This module builds that plan (sign.verify must pass locally first) and can execute it against anything exposing
``request(uds_bytes, tgt=...)`` — a real car's Hsfz or the test simulator. Executing against a real car is refused
unless `unlock` is the exact confirmation string AND a fresh backup exists AND the module's signer is proven. Dry-run
(the default) touches nothing and returns the steps. Pure Python standard library.
"""
from __future__ import annotations

import hashlib

from . import sign

SESSION_EXTENDED, SESSION_CODING = 0x03, 0x41
SA_SEED_LEVEL, SA_KEY_LEVEL = 0x01, 0x02
RID_CHECK_CODING = 0x0F01
DID_CPS = 0x37FE
UNLOCK = "I-OWN-THIS-CAR-AND-HAVE-A-BACKUP"


def sign_seed(seed: bytes, l3: sign.Key, btld: int, tester_id: int = 0) -> bytes:
    """SecurityAccess L3 key for a seed: MD5([testerId][BTLD][seed]) raw-RSA (little-endian), word-count + wordswap."""
    if len(seed) != 8:
        raise ValueError("seed must be 8 bytes, got %d" % len(seed))
    if l3.private_exponent is None:
        raise ValueError("L3 key has no private exponent")
    block = tester_id.to_bytes(4, "big") + btld.to_bytes(4, "big") + seed
    m = int.from_bytes(hashlib.md5(block).digest(), "little")
    s = pow(m, l3.private_exponent, l3.modulus)
    if pow(s, l3.public_exponent, l3.modulus) != m:
        raise ValueError("seed signature self-check failed — wrong L3 key?")
    return (l3.size // 4).to_bytes(4, "big") + sign._wordswap(s.to_bytes(l3.size, "little"))


def apply_change(coding: dict, func, new_scalar: int) -> dict:
    """Return a copy of coding with one function set to new_scalar (right-aligned into its mask). coding: {DG: bytes}."""
    out = {a: bytearray(b) for a, b in coding.items()}
    dg = func.dg_addr.upper()
    if dg not in out:
        raise KeyError("datagroup %s not read; cannot change it" % dg)
    shift = sign._wordswap  # unused; keep import tidy
    s = 0
    while not (func.mask >> s) & 1:
        s += 1
    val = (new_scalar << s) & func.mask
    for off in range(func.start, func.end + 1):
        if off < len(out[dg]):
            out[dg][off] = (out[dg][off] & ~func.mask & 0xFF) | val
    return {a: bytes(b) for a, b in out.items()}


def resign(coding: dict, caf, ncd_key: sign.Key) -> dict:
    """Return a copy of coding with the signature datagroup recomputed for the current content."""
    content, sign_dg = sign.scheme_from_caf(caf)
    page = sign.sign(coding, content, ncd_key)
    out = dict(coding)
    out["%04X" % sign_dg] = page
    return out


def plan(before: dict, after: dict, caf, ncd_key: sign.Key) -> dict:
    """What a write would send. Verifies the new signature locally; lists changed datagroups, signature last."""
    content, sign_dg = sign.scheme_from_caf(caf)
    after = resign(after, caf, ncd_key)
    if not sign.verify(after, content, sign_dg, ncd_key):
        raise ValueError("the re-signed coding does not self-verify; refusing to plan a write")
    changed = [a for a in ("%04X" % d for d in content) if before.get(a) != after.get(a) and a in after]
    changed_sig = before.get("%04X" % sign_dg) != after.get("%04X" % sign_dg)
    order = changed + (["%04X" % sign_dg] if changed_sig else [])
    steps = ["10 %02X" % SESSION_EXTENDED, "10 %02X" % SESSION_CODING,
             "27 %02X <testerId>  (seed)" % SA_SEED_LEVEL, "27 %02X <signed key>" % SA_KEY_LEVEL]
    steps += ["2E %s %s  (%d bytes)%s" % (a[:2], a[2:], len(after[a]), "   <- signature LAST" if a == "%04X" % sign_dg else "")
              for a in order]
    steps += ["31 01 %04X  CheckCodingSignature" % RID_CHECK_CODING, "2E 37FE <cps>", "11 01  reset"]
    return {"changed": order, "after": after, "sign_dg": sign_dg, "steps": steps}


def _req(conn, uds: bytes, tgt: int) -> bytes:
    r = conn.request(uds, tgt=tgt)
    if r and r[0] == 0x7F:
        raise RuntimeError("negative response to %s: %s" % (uds[:1].hex(), r.hex()))
    return r


def commit(conn, tgt: int, module: str, before: dict, after: dict, caf, ncd_key: sign.Key, l3_key: sign.Key,
           *, dry_run: bool = True, unlock: str = "", have_backup: bool = False, tester_id: int = 0) -> dict:
    """Execute (or rehearse) the write. Real write refused unless dry_run is False AND unlock==UNLOCK AND have_backup
    AND the module's signer is proven. Reads everything back and checks the coding signature before the reset."""
    p = plan(before, after, caf, ncd_key)
    if dry_run:
        return {"dry_run": True, "steps": p["steps"], "changed": p["changed"]}
    if unlock != UNLOCK:
        raise PermissionError("real write refused: pass unlock=%r once you have a backup and mean it" % UNLOCK)
    if module not in sign.PROVEN:
        raise PermissionError("refused: the signer for %s is not proven against this car yet" % module)
    if not have_backup:
        raise PermissionError("refused: no backup confirmed for %s" % module)
    btld = int(sign.BTLD[module], 16)
    _req(conn, bytes([0x10, SESSION_EXTENDED]), tgt)
    _req(conn, bytes([0x10, SESSION_CODING]), tgt)
    seed = _req(conn, bytes([0x27, SA_SEED_LEVEL]) + tester_id.to_bytes(4, "big"), tgt)[2:]
    _req(conn, bytes([0x27, SA_KEY_LEVEL]) + sign_seed(seed, l3_key, btld, tester_id), tgt)
    for a in p["changed"]:
        did = int(a, 16)
        _req(conn, bytes([0x2E, did >> 8, did & 0xFF]) + p["after"][a], tgt)
    bad = []
    for a in p["changed"]:
        did = int(a, 16)
        rb = _req(conn, bytes([0x22, did >> 8, did & 0xFF]), tgt)[3:]
        if rb != p["after"][a]:
            bad.append(a)
    if bad:
        raise RuntimeError("read-back mismatch at %s; no CheckCodingSignature, no reset. Revert = write your backup." % bad)
    resp = _req(conn, bytes([0x31, 0x01, RID_CHECK_CODING >> 8, RID_CHECK_CODING & 0xFF]), tgt)
    status = resp[4:]
    if status and any(status):
        raise RuntimeError("CheckCodingSignature not OK (%s); no reset. Read back and decide." % resp.hex())
    _req(conn, bytes([0x11, 0x01]), tgt)
    return {"dry_run": False, "wrote": p["changed"], "check_coding": resp.hex()}


def _main() -> int:
    """python3 -m nbtcoding.write  — show the write choreography for a toggle flip (DRY RUN; never writes)."""
    import glob
    import json
    import sys
    from . import caf as cafmod, decode
    if len(sys.argv) < 3:
        print("usage: python3 -m nbtcoding.write <probe.json> <MODULE> [location_key]  (dry run only)")
        return 2
    probe = json.load(open(sys.argv[1], encoding="utf-8"))
    addr = {"HU_NBT": "63", "FRM": "72", "KOMBI": "60", "CAS": "40"}.get(sys.argv[2].upper(), sys.argv[2])
    m = next((x for x in probe["modules"] if x["addr"] == addr), None)
    if not m:
        print("module %s not in the probe" % sys.argv[2])
        return 1
    cafd = next((e["id"] for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
    c = cafmod.parse(decode.find_cafd_xml(cafd))
    coding = {a.upper(): bytes.fromhex(h) for a, h in m["datagroups"].items()}
    ncd = sign.load_key(sign.BTLD.get(sys.argv[2].upper(), ""), "ncd") if sys.argv[2].upper() in sign.BTLD else None
    if not ncd:
        print("no NCD key for %s — cannot plan a signed write" % sys.argv[2])
        return 1
    bykey = {f.key(): f for f in c.all_funcs()}
    want = sys.argv[3] if len(sys.argv) > 3 else None
    if want:
        func = bykey.get(want)
        if not func:
            print("no function %s in this CAFD" % want)
            return 1
    else:   # no location given: flip the first codeable on/off toggle, just to show the write shape
        fdict = {x.key: x for x in decode.build_features(c, coding, {})}
        func = next(f for f in c.all_funcs() if f.key() in fdict and fdict[f.key()].kind == "toggle"
                    and fdict[f.key()].current is not None)
    after = apply_change(coding, func, 1)
    try:
        p = plan(coding, after, c, ncd)
    except ValueError as e:
        print("cannot plan: %s" % e)
        return 1
    print("DRY RUN — changing %s. Would send:" % func.key())
    for s in p["steps"]:
        print("  " + s)
    print("\nNothing was written. A real write needs a live car, a backup, and the unlock in write.commit().")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
