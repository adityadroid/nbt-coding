"""Car probe: find every module on the ENET link and read what coding work needs. READ-ONLY.

    python3 -m nbtcoding.probe                 # discover the gateway, probe the known F-series modules
    python3 -m nbtcoding.probe --scan          # also try every other address 0x01..0x7F (slower)
    python3 -m nbtcoding.probe --host IP       # skip discovery

For each module address it reads:
  - the SVK (22 F1 01): software parts, incl. the CAFD id(s) = which coding file the module needs
  - the coding datagroups 22 3000..300F (raw bytes, whatever exists)
and writes everything to backups/probe-<time>.json (git-ignored: it holds the VIN and your coding).

Only UDS ReadDataByIdentifier (22) is sent. If a module refuses the reads in its default session, the probe asks for the
extended diagnostic session (10 03), reads, and goes back to the default session (10 01); a session change writes
nothing. No security access, no writes, no resets.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

from .decode import BACKUP_DIR, find_cafd_xml
from .ecu import SVK_CLASS
from .hsfz import Hsfz, HsfzError

HSFZ_PORT = 6801
IDENT_PORT = 6811
NBT_HOST = os.environ.get("NBT_HOST", "169.254.199.99")

# Common F-series diagnostic addresses (names are a guide; the SVK says what really answered).
KNOWN = {
    0x01: "ACSM (airbags)", 0x10: "ZGW (gateway)", 0x12: "DME (engine)", 0x18: "EGS (gearbox)",
    0x29: "DSC (stability)", 0x30: "EPS (steering)", 0x40: "CAS (keys, locks, start/stop)",
    0x56: "FZD (roof)", 0x5D: "KAFAS (camera)", 0x60: "KOMBI (cluster)", 0x63: "HU_NBT (head unit)",
    0x64: "PDC (parking)", 0x67: "ZBE (controller)", 0x68: "RSE (rear entertainment)", 0x6D: "TRSVC (top/rear view)",
    0x72: "FRM (lights)", 0x78: "IHKA (climate)", 0x7A: "SZM (centre console)",
}
CODING_DIDS = list(range(0x3000, 0x3010))
SESSION_NRCS = (0x7F, 0x22, 0x33, 0x7E)   # not in this session / conditions / security: worth trying 10 03


def enet_source() -> str | None:
    """Local 169.254.x.x address the ENET cable uses (None if the route points elsewhere, e.g. a VPN)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("169.254.1.1", 9))
        ip = s.getsockname()[0]
        s.close()
        return ip if ip.startswith("169.254.") else None
    except OSError:
        return None


def discover(src: str | None, timeout: float = 4.0) -> tuple[str, str] | None:
    """HSFZ identification broadcast -> (gateway IP, VIN) or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if src:
        try:
            s.bind((src, 0))
        except OSError:
            pass
    s.settimeout(timeout)
    try:
        s.sendto(struct.pack(">IH", 0, 0x0011), ("169.254.255.255", IDENT_PORT))
        data, addr = s.recvfrom(512)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()
    ident = data[6:].decode("latin1", "replace")
    vin = ident.split("BMWVIN", 1)[1][:17] if "BMWVIN" in ident else ""
    return addr[0], vin


def parse_svk(val: bytes) -> list[dict]:
    """SVK value (after 62 F1 01) -> [{class, id, version}] (same layout as tools/nbt-unlock/svkread.py, car-tested)."""
    if len(val) < 4:
        return []
    count = int.from_bytes(val[2:4], "big")
    first = len(val) - count * 8
    if count == 0 or first < 4:
        return []
    out = []
    for k in range(count):
        at = first + k * 8
        cls = val[at]
        out.append({"class": SVK_CLASS.get(cls, "C%02X" % cls), "id": "%08X" % int.from_bytes(val[at + 1:at + 5], "big"),
                    "version": "%03d.%03d.%03d" % (val[at + 5], val[at + 6], val[at + 7])})
    return out


def _matches(req: bytes, r: bytes) -> bool:
    """Is r the answer to req? (a module that answers after our timeout must not be read as the next answer)"""
    if r[:1] == b"\x7f":
        return len(r) >= 2 and r[1] == req[0]
    if not r or r[0] != req[0] + 0x40:
        return False
    return req[0] != 0x22 or r[1:3] == req[1:3]   # ReadDataByIdentifier echoes the DID


def ask(hu: Hsfz, tgt: int, req: bytes, timeout: float) -> bytes | None:
    try:
        r = hu.request(req, tgt=tgt, timeout=timeout, settle=0.05)
    except HsfzError:
        return None
    return r if _matches(req, r) else None   # a stale answer counts as no answer


def read_dids(hu: Hsfz, tgt: int, timeout: float) -> tuple[dict, dict]:
    data, nrc = {}, {}
    for did in CODING_DIDS:
        r = ask(hu, tgt, bytes([0x22, did >> 8, did & 0xFF]), timeout)
        key = "%04X" % did
        if r and r[0] == 0x62 and len(r) >= 3:
            data[key] = r[3:].hex()
        elif r and r[0] == 0x7F and len(r) >= 3:
            nrc[key] = r[2]
        else:
            nrc[key] = -1   # no answer
    return data, nrc


def probe_module(hu: Hsfz, tgt: int, timeout: float) -> dict | None:
    r = ask(hu, tgt, bytes.fromhex("22F101"), timeout)
    if r is None:
        return None
    m: dict = {"addr": "%02X" % tgt, "name": KNOWN.get(tgt, "")}
    if r[0] != 0x62:
        m["svk_error"] = r.hex()
        return m
    val = bytes(r[3:])
    m["svk_raw"] = val.hex()
    m["svk"] = parse_svk(val)
    m["cafd"] = [e["id"] for e in m["svk"] if e["class"] == "CAFD"]
    data, nrc = read_dids(hu, tgt, timeout)
    if not data and any(v in SESSION_NRCS for v in nrc.values()):
        s = ask(hu, tgt, bytes.fromhex("1003"), timeout)
        if s and s[0] == 0x50:
            m["session"] = "extended (10 03)"
            data, nrc = read_dids(hu, tgt, timeout)
            ask(hu, tgt, bytes.fromhex("1001"), timeout)
    m["datagroups"] = data
    m["refused"] = {k: v for k, v in nrc.items() if v != 0x31}   # 31 = that datagroup does not exist: normal
    return m


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="gateway / module address (default: discover, then %s)" % NBT_HOST)
    ap.add_argument("--port", type=int, default=HSFZ_PORT)
    ap.add_argument("--scan", action="store_true", help="also try every other address 0x01..0x7F")
    ap.add_argument("--timeout", type=float, default=2.5, help="seconds per request (default 2.5)")
    a = ap.parse_args()

    src = enet_source()
    vin = ""
    host = a.host
    if not host:
        found = discover(src)
        if found:
            host, vin = found
            print("gateway found at %s" % host)
        else:
            host = NBT_HOST
            print("no gateway answered the broadcast: trying %s (the head unit; other modules may not answer)" % host)
    targets = sorted(KNOWN) + ([t for t in range(0x01, 0x80) if t not in KNOWN] if a.scan else [])

    hu = Hsfz(host, port=a.port, verbose=False)
    try:
        hu.open(timeout=5)
    except OSError as e:
        print("cannot connect to %s:%d: %s\nIs the ENET cable in and the ignition on? (wait ~20 s after plugging in)"
              % (host, a.port, e))
        return 2
    modules = []
    try:
        for t in targets:
            label = KNOWN.get(t, "")
            print("  %02X %-30s" % (t, label), end="", flush=True)
            m = probe_module(hu, t, a.timeout)
            if m is None:
                print("no answer")
                continue
            modules.append(m)
            if "svk_error" in m:
                print("answered, SVK refused (%s)" % m["svk_error"])
                continue
            print("CAFD %s, %d datagroups%s" % (",".join(m["cafd"]) or "-", len(m["datagroups"]),
                                               ", " + m["session"] if m.get("session") else ""))
            if not vin and t == 0x10:
                r = ask(hu, t, bytes.fromhex("22F190"), a.timeout)
                if r and r[0] == 0x62:
                    vin = r[3:].decode("latin1").strip("\x00 ")
    finally:
        hu.close()

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, "probe-%s.json" % stamp)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"saved": stamp, "host": host, "vin": vin, "modules": modules}, fh, indent=2)

    print("\n%d modules answered. Saved: %s" % (len(modules), path))
    need = sorted({c for m in modules for c in m.get("cafd", [])})
    if need:
        have = [c for c in need if find_cafd_xml(c)]
        print("CAFD files needed: %s" % ", ".join(need))
        print("  already decoded: %s" % (", ".join(have) or "none"))
    return 0 if modules else 1


if __name__ == "__main__":
    sys.exit(main())
