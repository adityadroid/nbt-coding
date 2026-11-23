"""Clear the fault memory of every module that answers (UDS 14 FF FF FF), after saving every module's faults
(19 02 FF) to backups/faults-before-clear-<time>.json, then read them again. Ignition on, engine off.
Never touches coding. Tester F4.

    python3 tools_clear_faults.py
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from nbtcoding.hsfz import Hsfz
from nbtcoding import modules

GW, SRC = "169.254.101.24", 0xF4
STAMP = time.strftime("%Y%m%d-%H%M%S")
OUT = os.path.join(os.path.dirname(__file__), "backups", "faults-before-clear-%s.json" % STAMP)
addrs = sorted({int(k, 16) for k in modules.BY_ADDR} | {0x10, 0x17, 0x1C, 0x5F, 0x63})
h = Hsfz(GW, src=SRC, verbose=False)
h.open()


def rq(tgt, b, t=4.0):
    try:
        return h.request(bytes(b), tgt=tgt, timeout=t, settle=0.0)
    except Exception as e:
        return ("ERR " + str(e)).encode()


def faults(a):
    r = rq(a, [0x19, 0x02, 0xFF])
    if r[:1] != b"\x59":
        return None
    return [(r[i:i + 3].hex().upper(), r[i + 3]) for i in range(3, len(r) - 3, 4) if r[i + 3] & 0x0B]


name = modules.name_of
before = {}
for a in addrs:
    f = faults(a)
    if f is not None:
        before[name(a)] = f
json.dump(before, open(OUT, "w"), indent=1)
print("saved", OUT, "-", sum(len(v) for v in before.values()), "faults in", len(before), "modules")
for a in addrs:
    if name(a) not in before:
        continue
    r = rq(a, [0x14, 0xFF, 0xFF, 0xFF], 8.0)
    print("  %-8s clear: %s" % (name(a), "ok" if r[:1] == b"\x54" else r.hex()))
time.sleep(3)
left = 0
for a in addrs:
    if name(a) not in before:
        continue
    f = faults(a) or []
    left += len(f)
    if f:
        print("  %-8s still: %s" % (name(a), " ".join("%s(%02X)" % x for x in f)))
print("faults left:", left)
h.close()
