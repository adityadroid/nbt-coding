"""Sweep a DID range on one ECU with plain 22 reads (read-only) and save every DID that answers.

    python3 tools_scan_dids.py [ecu_hex] [start_hex] [end_hex] [session]   # session: default|extended
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz

ECU = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x12
A = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4000
B = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x5FFF
SESSION = sys.argv[4] if len(sys.argv) > 4 else "default"
OUT = os.path.join(os.path.dirname(__file__), "backups",
                   "scan-%02X-%04X-%04X-%s-%s.json" % (ECU, A, B, SESSION, time.strftime("%Y%m%d-%H%M%S")))
h = Hsfz("169.254.101.24", src=0xF4, verbose=False)
h.open()
if SESSION == "extended":
    h.request(bytes([0x10, 0x03]), tgt=ECU, timeout=3, settle=0)
found, t0 = {}, time.time()
for did in range(A, B + 1):
    try:
        r = h.request(bytes([0x22, did >> 8, did & 0xFF]), tgt=ECU, timeout=2, settle=0)
    except Exception as e:
        h.close(); time.sleep(1); h = Hsfz("169.254.101.24", src=0xF4, verbose=False); h.open()
        if SESSION == "extended":
            h.request(bytes([0x10, 0x03]), tgt=ECU, timeout=3, settle=0)
        continue
    if r[:1] == b"\x62":
        found["%04X" % did] = r[3:].hex()
        print("%04X %s" % (did, r[3:].hex()[:60]), flush=True)
    if did % 256 == 255:
        json.dump(found, open(OUT, "w"), indent=0)
        print("# %04X done, %d found, %.0fs" % (did, len(found), time.time() - t0), flush=True)
if SESSION == "extended":
    h.request(bytes([0x10, 0x01]), tgt=ECU, timeout=3, settle=0)
h.close()
json.dump(found, open(OUT, "w"), indent=0)
print("saved", OUT)
