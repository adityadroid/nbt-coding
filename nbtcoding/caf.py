"""Parse a BMW CAF/CAFD coding-description file (the XML that E-Sys calls a "CAFD") into a
simple model we can use to read and (later) write a module's coding over ENET.

A CAF describes one module's coding. Structure (from the real NBT file cafd_00000ded.xml):

    <caf ncdSignAddress="3007">
      <datagroup address="3000" datagroupClass="USER" units="98"> ... </datagroup>
      ...
      <datagroup address="3007" datagroupClass="SYSTEM">   # holds the coding signature
      <function>                      # one codeable field
        <storageInfo><start>0</start><end>0</end><mask>00000001b</mask></storageInfo>
        <defVal><unitVal position="0">00</unitVal></defVal>
        <condParam><paramName>.</paramName>
          <bool mainSeries="F010">true()</bool> ...
          <values><unitVal position="0">01</unitVal></values>
        </condParam>
        ...
      </function>

Important: BMW ships these with the readable names stripped to ".". A function is therefore
identified by its location (datagroup address + byte range + bit mask). Friendly names come
from a separate overlay (see names/). This parser never needs the names to work.

USER datagroups hold the coding you may change; SYSTEM datagroups (incl. the signature at
ncdSignAddress) are written by the signer, never by hand.

Read-only: this module only parses a local file. It never touches the car.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


def _mask_to_int(s: str) -> int:
    """'00000001b' -> 1, 'FF' / '0xFF' -> 255. Returns 0xFF for a full/absent mask."""
    s = (s or "").strip()
    if not s:
        return 0xFF
    if s.endswith("b"):
        bits = s[:-1]
        return int(bits, 2) if bits else 0xFF
    return int(s, 16)


def _lowest_set_bit(mask: int) -> int:
    """Shift needed to right-align a masked field. mask 0b00011000 -> 3."""
    if mask == 0:
        return 0
    shift = 0
    while not (mask >> shift) & 1:
        shift += 1
    return shift


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@dataclass
class Func:
    """One codeable field inside a datagroup."""

    dg_addr: str                     # e.g. "3000" (hex string, as in the file)
    index: int                       # position of this function within its datagroup
    start: int                       # first byte offset within the datagroup
    end: int                         # last byte offset (inclusive)
    mask: int                        # bit mask within each byte
    default: list[int] = field(default_factory=list)   # default value, one int per byte
    values: list[list[int]] = field(default_factory=list)  # all distinct known values (option menu)
    series_value: list[int] | None = None              # value this series' condParam expects, if any

    @property
    def nbytes(self) -> int:
        return self.end - self.start + 1

    @property
    def shift(self) -> int:
        return _lowest_set_bit(self.mask)

    def key(self) -> str:
        """Stable location key, used to join with the friendly-name overlay."""
        return "%s:%d:%d:%02X" % (self.dg_addr, self.start, self.end, self.mask)

    def decode(self, dg_bytes: bytes) -> list[int]:
        """Pull this field's raw bytes out of a datagroup's coding bytes, masked."""
        out = []
        for off in range(self.start, self.end + 1):
            b = dg_bytes[off] if off < len(dg_bytes) else 0
            out.append(b & self.mask)
        return out

    def scalar(self, dg_bytes: bytes) -> int:
        """Single right-aligned integer for a one-byte field (the common case)."""
        raw = self.decode(dg_bytes)
        return (raw[0] >> self.shift) if raw else 0


@dataclass
class Datagroup:
    addr: str
    kind: str                        # USER or SYSTEM
    funcs: list[Func] = field(default_factory=list)


@dataclass
class Caf:
    cafd_id: str                     # e.g. "00000DED"
    version: str                     # "003.015.224"
    sign_addr: str                   # datagroup that holds the signature (e.g. "3007")
    datagroups: list[Datagroup] = field(default_factory=list)

    def user_datagroups(self) -> list[Datagroup]:
        return [d for d in self.datagroups if d.kind == "USER"]

    def all_funcs(self) -> list[Func]:
        return [f for d in self.datagroups for f in d.funcs]


def _unitvals(parent) -> list[int]:
    """Collect <unitVal position="i">HH</unitVal> children, ordered by position."""
    vals = []
    for uv in parent:
        if _localname(uv.tag) != "unitVal":
            continue
        pos = int(uv.get("position", "0"))
        try:
            v = int((uv.text or "0").strip(), 16)
        except ValueError:
            v = 0
        vals.append((pos, v))
    vals.sort()
    return [v for _, v in vals]


def _series_true(cond, series: str) -> bool:
    """Does this condParam apply to the given mainSeries (e.g. 'F010')?

    A condParam lists <bool mainSeries="F010">true()/false()</bool> per series.
    """
    for b in cond:
        if _localname(b.tag) != "bool":
            continue
        if b.get("mainSeries") == series:
            return "true" in (b.text or "")
    return False


def parse(path: str, series: str = "F010") -> Caf:
    """Parse a decoded CAF XML. `series` filters the per-vehicle candidate values
    (an F10 is mainSeries F010)."""
    tree = ET.parse(path)
    root = tree.getroot()

    cafd_id = version = ""
    sign_addr = ""
    for el in root.iter():
        ln = _localname(el.tag)
        if ln == "sweHeader":
            sign_addr = el.get("ncdSignAddress", "")
        elif ln == "cafIdent":
            parts = {_localname(c.tag): (c.text or "").strip() for c in el}
            cafd_id = parts.get("id", "")
            version = "%s.%s.%s" % (
                parts.get("mainVersion", "000"),
                parts.get("subVersion", "000"),
                parts.get("patchVersion", "000"),
            )
            break

    caf = Caf(cafd_id=cafd_id, version=version, sign_addr=sign_addr)

    for dg_el in root.iter():
        if _localname(dg_el.tag) != "datagroup":
            continue
        dg = Datagroup(addr=dg_el.get("address", ""), kind=dg_el.get("datagroupClass", ""))
        fi = 0
        for fn in dg_el:
            if _localname(fn.tag) != "function":
                continue
            start = end = 0
            mask = 0xFF
            default: list[int] = []
            values: list[list[int]] = []
            series_value: list[int] | None = None
            for child in fn:
                cln = _localname(child.tag)
                if cln == "storageInfo":
                    for s in child:
                        sln = _localname(s.tag)
                        if sln == "start":
                            start = int((s.text or "0").strip())
                        elif sln == "end":
                            end = int((s.text or "0").strip())
                        elif sln == "mask":
                            mask = _mask_to_int(s.text or "")
                elif cln == "defVal":
                    default = _unitvals(child)
                elif cln == "condParam":
                    vals = []
                    for v in child:
                        if _localname(v.tag) == "values":
                            vals = _unitvals(v)
                    if vals:
                        if vals not in values:          # the full option menu
                            values.append(vals)
                        if series_value is None and _series_true(child, series):
                            series_value = vals         # what this series expects
            dg.funcs.append(
                Func(dg_addr=dg.addr, index=fi, start=start, end=end, mask=mask,
                     default=default, values=values, series_value=series_value)
            )
            fi += 1
        caf.datagroups.append(dg)

    return caf


if __name__ == "__main__":
    import sys

    c = parse(sys.argv[1] if len(sys.argv) > 1 else ".local/psdz/cafd_00000ded.xml")
    print("CAFD %s v%s  sign@%s" % (c.cafd_id, c.version, c.sign_addr))
    for dg in c.datagroups:
        print("  datagroup %s [%s]  %d functions" % (dg.addr, dg.kind, len(dg.funcs)))
    toggles = [f for f in c.all_funcs() if len(f.values) > 1]
    print("functions with >1 candidate value for this series:", len(toggles))
