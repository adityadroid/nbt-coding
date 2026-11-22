"""The GUI's write path end to end, offline: review a change through the server, write it to a simulated FRM that checks
the SecurityAccess key and the coding signature like the car, read it back, then restore the backup. Also the refusals.
Needs this car's FRM read (backups/probe-*.json), its decrypted CAFD (cafd/) and keys (keys/); skips without them."""
import glob
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from nbtcoding import caf as cafmod, decode, server, sign, write   # noqa: E402
from tests.fake_ecu import FakeEcu                                 # noqa: E402

FRM_CAFD, WL_AL = "0000106D", "3050:30:30:0C"   # WL_FUNKTION_AL: low beam in the welcome light


class Conn:
    """Adapts FakeEcu to the Hsfz interface the server uses (timeout kw, close)."""
    def __init__(self, ecu):
        self.ecu = ecu

    def request(self, uds, tgt=None, timeout=None, settle=None):
        return self.ecu.request(uds, tgt=tgt)

    def close(self):
        pass


def _frm_coding():
    for path in sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-*.json")), reverse=True):
        d = json.load(open(path, encoding="utf-8"))
        m = next((x for x in d.get("modules", []) if x.get("addr") == "72" and len(x.get("datagroups", {})) > 16), None)
        if m:
            return {a.upper(): bytes.fromhex(h) for a, h in m["datagroups"].items()}
    return None


def run():
    coding = _frm_coding()
    xml = decode.find_cafd_xml(FRM_CAFD)
    l3, ncd = sign.load_key(sign.BTLD["FRM"], "l3"), sign.load_key(sign.BTLD["FRM"], "ncd")
    if not (coding and xml and l3 and ncd):
        print("SKIP: needs this car's full FRM read, its CAFD and keys")
        return
    c = cafmod.parse(xml)
    ecu = FakeEcu(coding, l3, ncd, c, btld=int(sign.BTLD["FRM"], 16))
    tmp = tempfile.mkdtemp(prefix="nbt-gui-test-")
    saved = (server.connect, server.read_ids, decode.BACKUP_DIR)
    os.environ["NBT_RESET_WAIT"] = "0"
    server.connect = lambda: Conn(ecu)
    server.read_ids = lambda conn, tgt: ("", FRM_CAFD)
    decode.BACKUP_DIR = tmp
    try:
        start = bytes(ecu.coding["3050"])
        # review: one change, described in BMW's words, nothing written yet
        p = server._plan({"module": "FRM", "changes": [{"key": WL_AL, "scalar": 1}]})
        assert p.get("token") and p["writable"], p
        assert [(x["name"], x["from"], x["to"]) for x in p["changes"]] == [("WL_FUNKTION_AL", "nicht_aktiv", "soft_on")], p["changes"]
        assert p["datagroups"][-1] == c.sign_addr.upper(), "signature datagroup must be written last"
        assert bytes(ecu.coding["3050"]) == start, "a review must not write"
        review_backup = p["backup"]

        # wrong phrase: refused, review still usable
        assert "error" in server._write({"token": p["token"], "unlock": "yes"})
        # real write: accepted by the simulated module's signature check, reset, read back
        r = server._write({"token": p["token"], "unlock": write.UNLOCK})
        assert r.get("ok") and r.get("verified"), r
        assert ecu.reset_done and ecu.coding["3050"][30] == 0x06, ecu.coding["3050"][30]
        assert "error" in server._write({"token": p["token"], "unlock": write.UNLOCK}), "a review token is single-use"

        # restore the backup taken at review: back to the original bytes, signature still valid
        ecu.reset_done = False
        p2 = server._plan({"module": "FRM", "restore": review_backup})
        assert p2.get("token"), p2
        r2 = server._write({"token": p2["token"], "unlock": write.UNLOCK})
        assert r2.get("verified") and bytes(ecu.coding["3050"]) == start, r2
        content, sdg = sign.scheme_from_caf(c)
        assert sign.verify({a: bytes(b) for a, b in ecu.coding.items()}, content, sdg, ncd)

        # refusals
        assert "error" in server._plan({"module": "HU_NBT", "changes": []}), "the head unit is never written"
        assert "error" in server._plan({"module": "FRM", "changes": [{"key": WL_AL, "scalar": 9}]}), "undefined value"
        assert "error" in server._plan({"module": "FRM", "changes": [{"key": "3050:99:99:01", "scalar": 1}]}), "unknown key"
        # drift: the car changed between review and write
        p3 = server._plan({"module": "FRM", "changes": [{"key": WL_AL, "scalar": 2}]})
        ecu.coding["3050"][29] ^= 0x01
        r3 = server._write({"token": p3["token"], "unlock": write.UNLOCK})
        assert "error" in r3 and "changed since" in r3["error"], r3
    finally:
        server.connect, server.read_ids, decode.BACKUP_DIR = saved
        shutil.rmtree(tmp, ignore_errors=True)
    print("OK: GUI review, gated write, read-back, restore, and refusals all pass against the simulated FRM")


if __name__ == "__main__":
    run()
