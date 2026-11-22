"""Every coded module's signer reproduces the car's own signature from the newest full read (backups/probe-full-all-*),
and re-signing unchanged coding gives back the exact page the module holds (so a write would carry the format it
expects: word-swapped RSA, little-endian RSA on the DME, keyed MD5 on CAS). Skips without the car read or keys."""
import glob
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from nbtcoding import caf, decode, edit, modules, sign, write   # noqa: E402


def run():
    files = sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-full-all-*.json")))
    if not files:
        print("SKIP: no full read of every module (tools_fullread_all.py)")
        return
    probe = json.load(open(files[-1], encoding="utf-8"))
    checked = 0
    for m in probe["modules"]:
        if m["addr"].upper() not in modules.BY_ADDR or not m["datagroups"]:
            continue
        name = modules.name_of(m["addr"])
        key = edit.signer_key(name)
        if key is None:
            print("SKIP %s: no key in keys/" % name)
            continue
        cafd = next(e for e in m["svk"] if e.get("class") == "CAFD")
        c = caf.parse(decode.find_cafd_xml(cafd["id"], cafd["version"]))
        coding = {a.upper(): bytes.fromhex(h) for a, h in m["datagroups"].items()}
        content, sdg = sign.scheme_from_caf(c)
        _, verify = write._signer(name)
        assert verify(coding, content, sdg, key), "%s: signer does not reproduce the car's signature" % name
        again = write.resign(coding, c, key, name)
        assert again["%04X" % sdg] == coding["%04X" % sdg], "%s: re-signing unchanged coding changed the page" % name
        checked += 1
    print("OK: %d modules: car signature reproduced and re-signing is byte-exact" % checked)


if __name__ == "__main__":
    run()
