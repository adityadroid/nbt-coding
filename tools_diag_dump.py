"""Read-only diagnostic dump for building the Car health tool offline: every supported OBD-II PID of the DME, OBD
service 09 identifiers, fault memory with snapshot/extended data of every relevant fault on every module, and a scan
of BMW measurement DIDs on the DME and KOMBI. Services 01, 09, 19, 22 only. Tester 0xF5 (the head unit's nbt_health
uses 0xF4). Writes backups/diag-<time>.json (git-ignored: it holds the VIN)."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz

GW, SRC = "169.254.101.24", 0xF5
OUT = os.path.join(os.path.dirname(__file__), "backups", "diag-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
MODS = {0x01: "ACSM", 0x12: "DME", 0x18: "EGS", 0x29: "DSC", 0x30: "EPS", 0x40: "CAS", 0x56: "FZD", 0x60: "KOMBI",
        0x63: "HU_NBT", 0x64: "PDC", 0x72: "FRM", 0x78: "IHKA", 0x10: "ZGW", 0x0D: "SZL?", 0x1C: "ICM?", 0x5F: "?5F",
        0x4D: "?4D", 0x4E: "?4E", 0x21: "?21", 0x35: "?35", 0x36: "?36", 0x37: "?37", 0x3B: "?3B", 0x46: "?46"}
out = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "obd": {}, "obd09": {}, "faults": {}, "dids": {}}
h = Hsfz(GW, src=SRC, verbose=False)
h.open()


def rq(tgt, hexs, timeout=2.0):
    global h
    for attempt in range(2):
        try:
            return h.request(bytes.fromhex(hexs.replace(" ", "")), tgt=tgt, timeout=timeout, settle=0.0)
        except Exception:
            try:
                h.close()
            except Exception:
                pass
            time.sleep(0.5)
            h = Hsfz(GW, src=SRC, verbose=False)
            h.open()
    return b""


def save():
    json.dump(out, open(OUT, "w"), indent=1)


# 1. OBD-II service 01: supported banks, then every supported PID
sup = []
for base in range(0, 0xE0, 0x20):
    r = rq(0x12, "01%02X" % base)
    if len(r) < 6 or r[0] != 0x41:
        break
    mask = int.from_bytes(r[2:6], "big")
    out["obd"]["supported_%02X" % base] = r[2:6].hex()
    sup += [base + i + 1 for i in range(32) if mask & (1 << (31 - i))]
    if not mask & 1:
        break
for p in sup:
    if p % 0x20 == 0:
        continue
    r = rq(0x12, "01%02X" % p)
    out["obd"]["%02X" % p] = r.hex()
print("OBD PIDs supported:", " ".join("%02X" % p for p in sup), flush=True)
# service 09 (calibration ids, CVN; 02 = VIN is skipped)
for p in (0x00, 0x04, 0x06, 0x0A):
    out["obd09"]["%02X" % p] = rq(0x12, "09%02X" % p).hex()
save()

# 2. fault memory on every module, with snapshots + extended data for faults that failed or are confirmed
for tgt, name in MODS.items():
    r = rq(tgt, "1902FF", timeout=4.0)
    if len(r) < 3 or r[0] != 0x59:
        continue
    recs = [(r[i:i + 3].hex(), r[i + 3]) for i in range(3, len(r) - 3, 4)]
    entry = {"raw": r.hex(), "count": len(recs), "details": {}}
    for dtc, st in recs:
        if st & 0x0B:      # failing now, this drive, or confirmed
            entry["details"][dtc] = {"status": "%02X" % st,
                                     "snapshot": rq(tgt, "1904%sFF" % dtc, 4.0).hex(),
                                     "extended": rq(tgt, "1906%sFF" % dtc, 4.0).hex()}
    out["faults"]["%02X %s" % (tgt, name)] = entry
    print("faults %-8s %3d entries, %d detailed" % (name, len(recs), len(entry["details"])), flush=True)
save()

# 3. BMW measurement DID scan (time-boxed per range)
RANGES = [(0x12, 0x4000, 0x4FFF), (0x12, 0x5000, 0x5FFF), (0x12, 0xD000, 0xDFFF), (0x60, 0xD000, 0xDFFF),
          (0x60, 0x4000, 0x4FFF), (0x12, 0x2000, 0x2FFF), (0x12, 0x6000, 0x6FFF), (0x60, 0x2000, 0x2FFF)]
for tgt, a, b in RANGES:
    key = "%02X %s %04X-%04X" % (tgt, MODS[tgt], a, b)
    found, t0 = {}, time.time()
    for did in range(a, b + 1):
        r = rq(tgt, "22%04X" % did, timeout=1.0)
        if r and r[0] == 0x62:
            found["%04X" % did] = r[3:].hex()
        if time.time() - t0 > 150:
            found["_stopped_at"] = "%04X" % did
            break
    out["dids"][key] = found
    save()
    print("DIDs %s: %d answered in %.0fs" % (key, len([k for k in found if not k.startswith('_')]), time.time() - t0), flush=True)
h.close()
print("saved", OUT)
