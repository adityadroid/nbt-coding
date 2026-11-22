"""Extra read-only captures for the offline builds (22 only), tester F4:
  1. identity/FA ranges on CAS (F100-F1FF, 3F00-3FFF) and the gateway (F100-F1FF, 3F00-3FFF) -> CAS MAC work, coding
  2. after tools_diag_dump.py has saved, re-read every DID it found 3 times, 20 s apart -> which values move
Writes backups/extra-<time>.json (git-ignored)."""
import glob, json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz

GW, SRC = "169.254.101.24", 0xF4
DUMP_LOG = sys.argv[1]
OUT = os.path.join(os.path.dirname(__file__), "backups", "extra-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
out = {"ident": {}, "samples": []}
h = None


def connect():
    global h
    try:
        if h: h.close()
    except Exception:
        pass
    h = Hsfz(GW, src=SRC, verbose=False); h.open()


def rq(tgt, did):
    for _ in range(3):
        try:
            return h.request(bytes([0x22, did >> 8, did & 0xFF]), tgt=tgt, timeout=1.5, settle=0.0)
        except Exception:
            time.sleep(1); connect()
    return b""


connect()
for tgt, name in ((0x40, "CAS"), (0x10, "ZGW")):
    for a, b in ((0xF100, 0xF1FF), (0x3F00, 0x3FFF)):
        found = {}
        for did in range(a, b + 1):
            r = rq(tgt, did)
            if r and r[0] == 0x62:
                found["%04X" % did] = r[3:].hex()
        out["ident"]["%02X %s %04X-%04X" % (tgt, name, a, b)] = found
        json.dump(out, open(OUT, "w"), indent=1)
        print("%s %04X-%04X: %d" % (name, a, b, len(found)), flush=True)

while "saved" not in open(DUMP_LOG).read():      # wait for the DID scan to finish
    time.sleep(5)
diag = json.load(open(sorted(glob.glob(os.path.join(os.path.dirname(__file__), "backups", "diag-*.json")))[-1]))
dids = [(int(k.split()[0], 16), int(d, 16)) for k, v in diag["dids"].items() for d in v if not d.startswith("_")]
print("re-reading %d DIDs x3" % len(dids), flush=True)
for n in range(3):
    t = time.time()
    s = {"t": time.strftime("%H:%M:%S"), "values": {}}
    for tgt, did in dids:
        r = rq(tgt, did)
        s["values"]["%02X:%04X" % (tgt, did)] = r[3:].hex() if r and r[0] == 0x62 else ""
    out["samples"].append(s)
    json.dump(out, open(OUT, "w"), indent=1)
    print("sample %d done in %.0fs" % (n + 1, time.time() - t), flush=True)
    if n < 2:
        time.sleep(max(0, 20 - (time.time() - t)))
h.close()
print("saved", OUT)
