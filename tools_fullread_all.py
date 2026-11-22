"""Full coding read of every module the newest probe found: every datagroup its CAFD declares. Read-only (22 only).
Waits for a free tester address: F4 (taken while the head unit's Car health page polls) or F5 (taken while
tools_diag_dump.py runs). Writes one backup per module (decode.save_backup) plus backups/probe-full-all-<time>.json."""
import glob, json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz
from nbtcoding import caf as cafmod, decode

GW = "169.254.101.24"
DUMP_LOG = sys.argv[1] if len(sys.argv) > 1 else ""


def free(src):
    try:
        h = Hsfz(GW, src=src, verbose=False); h.open()
        t0 = time.time()
        while time.time() - t0 < 6:
            h.request(bytes.fromhex("22F190"), tgt=0x60, timeout=3); time.sleep(0.3)
        return h
    except Exception:
        return None


h, src, t0 = None, None, time.time()
while not h and time.time() - t0 < 1800:
    for s in (0xF4, 0xF5):
        if s == 0xF5 and DUMP_LOG and "saved" not in open(DUMP_LOG).read():
            continue
        h = free(s)
        if h:
            src = s; break
    if not h:
        time.sleep(10)
if not h:
    sys.exit("no free tester address within 30 min")
print("reading with tester %02X" % src, flush=True)

probe = json.load(open(sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-2*.json")))[-1]))
out = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "modules": []}


def rq(tgt, did):
    global h
    for _ in range(3):
        try:
            return h.request(bytes([0x22, did >> 8, did & 0xFF]), tgt=tgt, timeout=4, settle=0.0)
        except Exception:
            try: h.close()
            except Exception: pass
            time.sleep(1)
            h = Hsfz(GW, src=src, verbose=False); h.open()
    return b""


for m in probe["modules"]:
    tgt = int(m["addr"], 16)
    cafds = [e for e in m.get("svk", []) if e.get("class") == "CAFD"]
    data = {}
    for e in cafds:
        xml = decode.find_cafd_xml(e["id"], e["version"])
        if not xml:
            print("  %s: no CAFD file for %s" % (m["addr"], e["id"])); continue
        c = cafmod.parse(xml)
        for d in c.datagroups:
            r = rq(tgt, int(d.addr, 16))
            if r and r[0] == 0x62:
                data[d.addr.upper()] = r[3:].hex()
        decode.save_backup("M%s" % m["addr"], c.cafd_id, {a: bytes.fromhex(v) for a, v in data.items()})
    out["modules"].append({"addr": m["addr"], "svk": m.get("svk", []), "datagroups": data})
    print("  %s: %d datagroups" % (m["addr"], len(data)), flush=True)
h.close()
path = os.path.join(decode.BACKUP_DIR, "probe-full-all-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
json.dump(out, open(path, "w"), indent=1)
print("saved", path)
