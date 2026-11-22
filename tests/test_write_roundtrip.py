"""Prove the write path end to end, offline: read NBT coding, flip one setting, re-sign, and write it to a simulated
ECU that verifies the SecurityAccess key and the coding signature exactly as the car would. No car is touched."""
import glob
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from nbtcoding import caf as cafmod, decode, sign, write          # noqa: E402
from tests.fake_ecu import FakeEcu                                # noqa: E402


def _nbt_coding():
    probe = json.load(open(sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-*.json")))[-1], encoding="utf-8"))
    m = next(x for x in probe["modules"] if x["addr"] == "63")
    return {a.upper(): bytes.fromhex(h) for a, h in m["datagroups"].items()}


def run():
    coding = _nbt_coding()
    c = cafmod.parse(decode.find_cafd_xml("00000DED"))
    l3, ncd = sign.load_key("00001275", "l3"), sign.load_key("00001275", "ncd")
    content, sign_dg = sign.scheme_from_caf(c)
    assert sign.verify(coding, content, sign_dg, ncd), "baseline NBT signature must verify"

    feats = {f.key: f for f in decode.build_features(c, coding, {})}
    func = next(f for f in cafmod.parse(decode.find_cafd_xml("00000DED")).all_funcs()
               if f.key() in feats and feats[f.key()].kind == "toggle" and feats[f.key()].current is not None
               and int(f.dg_addr, 16) < sign_dg)
    cur = feats[func.key()].current_scalar
    after = write.apply_change(coding, func, 1 - cur)             # flip the toggle
    assert after != coding, "the change must alter the bytes"

    ecu = FakeEcu(coding, l3, ncd, c, btld=int("00001275", 16))
    # dry run touches nothing
    dr = write.commit(ecu, 0x63, "HU_NBT", coding, after, c, ncd, l3, dry_run=True)
    assert dr["dry_run"] and dr["changed"], dr
    assert "%04X" % sign_dg in dr["changed"], "signature datagroup must be written last"

    # real write against the simulator (owner unlock + backup)
    res = write.commit(ecu, 0x63, "HU_NBT", coding, after, c, ncd, l3,
                       dry_run=False, unlock=write.UNLOCK, have_backup=True)
    assert res["wrote"], res
    assert ecu.reset_done, "the ECU must have been reset after a good write"
    # the simulator accepted the signature and now holds the change
    assert sign.verify({a: bytes(b) for a, b in ecu.coding.items()}, content, sign_dg, ncd), "ECU signature must verify after write"
    assert bytes(ecu.coding[func.dg_addr.upper()]) == after[func.dg_addr.upper()], "the flipped datagroup must be stored"

    # gates: a real write is refused without the unlock, without a backup, and for an unproven module
    for kw in (dict(unlock="", have_backup=True), dict(unlock=write.UNLOCK, have_backup=False)):
        try:
            write.commit(ecu, 0x63, "HU_NBT", coding, after, c, ncd, l3, dry_run=False, **kw)
            raise AssertionError("write should have been refused: %s" % kw)
        except PermissionError:
            pass
    print("OK: dry-run, gated real write to the simulator, signature accepted, reset, and refusals all pass")




if __name__ == "__main__":
    run()
