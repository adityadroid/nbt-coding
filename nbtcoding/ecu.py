"""Read a module's coding from the car over ENET, and decode it against its CAF.

Safe by default: this module only READS. Writing coding needs a valid signature (the
SYSTEM datagroup at ncdSignAddress), which is a separate, later step; `write_datagroup`
here refuses unless explicitly unlocked, so nothing can change the car by accident.

How BMW F-series coding is read:
  - Each USER datagroup in the CAF has an address like 3000..3005. That address is a UDS
    Data Identifier. Reading it is ReadDataByIdentifier: 22 <hi> <lo>  ->  62 <hi> <lo> ...bytes.
  - The returned bytes are that datagroup's coding. We decode each function (field) out of it
    with the CAF (byte offset + bit mask).

ECU diagnostic addresses are the HSFZ target byte. The common F-series ones are below; the
authoritative CAFD for a module comes from its own SVK (22 F1 01), not guessed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .hsfz import Hsfz, HsfzError

# Friendly module name -> (HSFZ diagnostic address, note). Addresses are standard F-series.
from .modules import MODULES as _ALL
MODULES = {name: (addr, desc) for addr, name, desc, _btld, _scheme in _ALL}   # every coded module of this car

SVK_CLASS = {1: "HWEL", 2: "HWAP", 3: "HWFR", 4: "GWTB", 5: "CAFD",
             6: "BTLD", 7: "FLSL", 8: "SWFL", 9: "SWFF", 10: "SWPF", 11: "ONPS"}


@dataclass
class DatagroupRead:
    addr: str
    ok: bool
    data: bytes
    nrc: str = ""


def read_vin(hu: Hsfz, tgt: int) -> str:
    r = hu.request(bytes.fromhex("22F190"), tgt=tgt, timeout=5)
    if r and r[0] == 0x62:
        return r[3:].decode("latin1").strip("\x00 ")
    return ""


def read_cafd_id(hu: Hsfz, tgt: int) -> str | None:
    """Read the module's SVK (22 F1 01) and return its CAFD id (e.g. '00000DED')."""
    r = hu.request(bytes.fromhex("22F101"), tgt=tgt, timeout=6)
    if not r or r[0] != 0x62:
        return None
    val = r[3:]
    count = int.from_bytes(val[2:4], "big")
    first = len(val) - count * 8
    for k in range(count):
        at = first + k * 8
        cls = SVK_CLASS.get(val[at], "")
        if cls == "CAFD":
            return "%08X" % int.from_bytes(val[at + 1:at + 5], "big")
    return None


def read_datagroup(hu: Hsfz, tgt: int, addr: str) -> DatagroupRead:
    """UDS ReadDataByIdentifier for one datagroup address (e.g. '3000'). Read-only."""
    did = int(addr, 16)
    req = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
    try:
        r = hu.request(req, tgt=tgt, timeout=6)
    except HsfzError as e:
        return DatagroupRead(addr, False, b"", "no reply (%s)" % e)
    if not r:
        return DatagroupRead(addr, False, b"", "no reply")
    if r[0] == 0x7F:
        nrc = r[2] if len(r) >= 3 else 0
        return DatagroupRead(addr, False, b"", "NRC %02X" % nrc)
    if r[0] == 0x62:
        return DatagroupRead(addr, True, bytes(r[3:]))   # strip 62 <hi> <lo>
    return DatagroupRead(addr, False, b"", "unexpected %02X" % r[0])


def read_coding(host: str, tgt: int, addrs: list[str]) -> dict[str, DatagroupRead]:
    """Read the given datagroup addresses from one module. Read-only."""
    hu = Hsfz(host, verbose=False)
    hu.open()
    out: dict[str, DatagroupRead] = {}
    try:
        for a in addrs:
            out[a] = read_datagroup(hu, tgt, a)
    finally:
        hu.close()
    return out


# ------------------------------------------------------------------ writing (locked off)
class WriteLocked(Exception):
    pass


def write_datagroup(*_args, unlock: str = "", **_kw):
    """Placeholder for writing coding. Deliberately refuses: writing needs a re-signed
    SYSTEM signature datagroup, which is not built yet. Keeps the car safe during read work."""
    if unlock != "I-UNDERSTAND-AND-HAVE-A-BACKUP-AND-SIGNER":
        raise WriteLocked(
            "writing coding is not enabled yet: the coding signer is not built, and a write "
            "without a valid signature can brick the module. Read and back up first."
        )
    raise WriteLocked("signer not implemented")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Read a module's coding over ENET (read-only).")
    ap.add_argument("module", choices=sorted(MODULES))
    ap.add_argument("--host", default=os.environ.get("NBT_HOST", "169.254.199.99"))
    ap.add_argument("--datagroups", default="3000,3001,3002,3003,3004,3005")
    a = ap.parse_args()
    tgt, note = MODULES[a.module]
    print("%s @ %02X  - %s" % (a.module, tgt, note))
    res = read_coding(a.host, tgt, a.datagroups.split(","))
    for addr, dr in res.items():
        print("  %s: %s" % (addr, dr.data.hex(" ") if dr.ok else dr.nrc))
