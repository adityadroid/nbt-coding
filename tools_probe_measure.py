"""Find out how this car's DME gives its live measurement values (oil temperature, oil level, oil pressure, rail and
boost actual/target, DPF pressure, exhaust temperatures ...), which refused a plain 22 read on 2026-11-22.

For each DID from the SGBD list (research findings, untested_measurement_dids) it tries, in order:
  1. 22 <DID> in the default session
  2. 10 03 (extended session), then 22 <DID>
  3. a dynamically defined DID: 2C 03 F300 (clear), 2C 01 F300 <DID> 01 <len>, 22 F300, 2C 03 F300 (clear again)
     -- a temporary definition in the DME's RAM, gone at the next session change or restart; nothing is coded
and ends with 10 01 (default session). No writes to coding, no resets. Tester F4 (nbt_health uses F5).
Writes backups/measure-<time>.json and prints the decoded value next to each DID that answered.

    python3 tools_probe_measure.py [findings.json]
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz

GW, SRC, DME = "169.254.101.24", 0xF4, 0x12
FINDINGS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "health_findings.json")
OUT = os.path.join(os.path.dirname(__file__), "backups", "measure-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
items = json.load(open(FINDINGS))["untested_measurement_dids"]
h = Hsfz(GW, src=SRC, verbose=False)
h.open()


def rq(b, t=3.0):
    try:
        return h.request(bytes(b), tgt=DME, timeout=t, settle=0.0)
    except Exception as e:
        return ("ERR " + str(e)).encode()


def decode(it, data):
    d = it["decode"]
    off, ln = d.get("byte_offset", 0), d.get("length", 2)
    if len(data) < off + ln:
        return None
    raw = int.from_bytes(data[off:off + ln], "big", signed=bool(d.get("signed")))
    return round(raw * d.get("factor", 1) + d.get("offset", 0), 3)


out = []
for it in items:
    did = int(it["did"], 16)
    ln = it["decode"].get("length", 2) + it["decode"].get("byte_offset", 0)
    rec = {"did": it["did"], "name": it["name"]}
    r = rq([0x22, did >> 8, did & 0xFF])
    rec["default"] = r.hex() if isinstance(r, bytes) else str(r)
    if not (r[:1] == b"\x62"):
        rq([0x10, 0x03])
        r = rq([0x22, did >> 8, did & 0xFF])
        rec["extended"] = r.hex()
        if not (r[:1] == b"\x62"):
            rq([0x2C, 0x03, 0xF3, 0x00])
            d1 = rq([0x2C, 0x01, 0xF3, 0x00, did >> 8, did & 0xFF, 0x01, ln])
            r = rq([0x22, 0xF3, 0x00])
            rq([0x2C, 0x03, 0xF3, 0x00])
            rec["dynamic_define"] = d1.hex()
            rec["dynamic"] = r.hex()
        rq([0x10, 0x01])
    ok = r[:1] == b"\x62"
    rec["value"] = decode(it, r[3:]) if ok else None
    rec["route"] = ("default" if "extended" not in rec else "extended" if "dynamic" not in rec else "dynamic") if ok else "none"
    out.append(rec)
    print("%-4s %-28s %-9s %s %s" % (it["did"], it["name"][:28], rec["route"], rec["value"], it["decode"].get("unit", "")),
          flush=True)
    json.dump(out, open(OUT, "w"), indent=1)
h.close()
print("saved", OUT)
