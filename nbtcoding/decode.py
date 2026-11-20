"""Join a parsed CAF, the coding bytes read from the car, and the friendly-name overlay into
a flat list of features for the GUI. Read-only.

This is also where a raw field is turned into something a human can read: every function is
classified (on/off toggle, a choice of values, or a plain number), its current and default
values are turned into labels (On/Off, or the overlay's words, or hex as a last resort), and a
one-line plain-English summary is generated. BMW strips the real names, so even an unnamed
field still gets a useful, honest description of what *kind* of setting it is and its state.

Also finds the decoded CAFD XML for a given CAFD id under PSdZData, and saves a full backup of
the raw coding bytes (so any change can be reverted).
"""
from __future__ import annotations

import glob
import json
import os
import time
from dataclasses import asdict, dataclass

from . import caf as caf_mod
from . import names as names_mod

HERE = os.path.dirname(__file__)
REPO = os.path.abspath(os.path.join(HERE, ".."))   # repo root (parent of the package)
# where decoded CAFD XMLs live: drop them in cafd/ (or point NBT_CAFD_DIR at your PSdZData)
CAFD_SEARCH = [
    os.environ.get("NBT_CAFD_DIR", ""),
    os.path.join(REPO, "cafd"),
    os.path.join(REPO, ".local", "psdz"),
    os.path.join(REPO, ".local", "psdz", "cafd"),
]
BACKUP_DIR = os.path.join(REPO, "backups")


@dataclass
class Feature:
    key: str
    datagroup: str
    start: int
    end: int
    mask: int
    name: str                        # friendly name from overlay, else ""
    desc: str                        # friendly description from overlay, else ""
    kind: str                        # "toggle" | "choice" | "value"
    default: list[int]
    options: list[list[int]]
    value_labels: dict
    current: list[int] | None        # raw masked bytes read from the car (None if not read)
    current_scalar: int | None
    is_default: bool | None
    codeable: bool                   # more than one known option
    # friendly, ready-to-show fields ----------------------------------------
    current_label: str               # "On" / "Off" / overlay word / "0x01" / "—"
    default_label: str
    option_labels: list[dict]        # [{"scalar": int, "label": str}]
    on: bool | None                  # for a toggle: is it on? (else None)
    summary: str                     # one-line plain-English explanation


def find_cafd_xml(cafd_id: str) -> str | None:
    cafd_id = cafd_id.lower()
    for base in CAFD_SEARCH:
        if not base:
            continue
        for pat in ("cafd_%s.xml" % cafd_id, "cafd_%s*.xml" % cafd_id, "*%s*.xml" % cafd_id):
            hits = glob.glob(os.path.join(base, pat))
            if hits:
                return hits[0]
    return None


def _popcount(x: int) -> int:
    return bin(x & 0xFF).count("1")


def _shift(mask: int) -> int:
    if not mask:
        return 0
    s = 0
    while not (mask >> s) & 1:
        s += 1
    return s


def _scalar(vals: list[int], mask: int, shift: int) -> int | None:
    """Right-aligned integer for a single-byte field value (masked). None if multi-byte/empty."""
    if not vals:
        return None
    if len(vals) > 1:
        return None
    return (vals[0] & mask) >> shift


def _label(scalar: int | None, raw: list[int] | None, kind: str, overlay_vals: dict) -> str:
    """Turn a value into something readable."""
    if scalar is None:
        if raw:
            return " ".join("%02X" % b for b in raw)
        return "—"
    key = str(scalar)
    if key in overlay_vals:                 # a word we have confirmed for this value
        return overlay_vals[key]
    if kind == "toggle":
        return "On" if scalar else "Off"
    return "0x%02X" % scalar                # honest fallback: the raw number


def build_features(c: caf_mod.Caf, coding: dict | None, overlay: dict) -> list[Feature]:
    """coding: {datagroup_addr: bytes} read from the car, or None for an offline view."""
    fns = overlay.get("functions", {})
    out: list[Feature] = []
    for f in c.all_funcs():
        key = f.key()
        meta = fns.get(key, {})
        overlay_vals = meta.get("values", {})
        nbytes = f.end - f.start + 1
        shift = _shift(f.mask)

        # current value read from the car (masked bytes), decided before labelling
        cur = cur_scalar = is_def = on = None
        if coding is not None and f.dg_addr in coding:
            dg_bytes = coding[f.dg_addr]
            cur = f.decode(dg_bytes)
            cur_scalar = f.scalar(dg_bytes)
            is_def = bool(f.default) and cur == [d & f.mask for d in f.default]

        # provisional kind; the option menu is built once, then kind may be corrected
        if nbytes == 1 and _popcount(f.mask) == 1:
            kind = "toggle"                 # one bit: structurally an on/off switch
        elif len(f.values) > 1:
            kind = "choice"                 # a menu of values (corrected below if it collapses)
        else:
            kind = "value"                  # a single number / fixed field

        # build the distinct option menu (handles multi-byte fields too)
        option_labels = []
        seen = set()
        for v in f.values:
            vm = [b & f.mask for b in v]
            sc = _scalar(v, f.mask, shift)
            lab = _label(sc, vm, kind, overlay_vals)
            if lab in seen:
                continue
            seen.add(lab)
            option_labels.append({"scalar": sc, "label": lab, "cur": cur is not None and vm == cur})
        if kind == "choice" and len(option_labels) <= 1:
            kind = "value"                  # only one real value: not a choice
            for o in option_labels:         # relabel under the corrected kind
                o["label"] = _label(o["scalar"], None, kind, overlay_vals)

        if kind == "toggle":
            on = bool(cur_scalar) if cur_scalar is not None else None

        def_scalar = _scalar(f.default, f.mask, shift)
        current_label = _label(cur_scalar, cur, kind, overlay_vals)
        default_label = _label(def_scalar, [d & f.mask for d in f.default] if f.default else None,
                               kind, overlay_vals)

        summary = _summary(kind, name=meta.get("name", ""), desc=meta.get("desc", ""),
                           current_label=current_label, default_label=default_label,
                           is_default=is_def, n_options=len(option_labels), read=coding is not None)

        out.append(Feature(
            key=key, datagroup=f.dg_addr, start=f.start, end=f.end, mask=f.mask,
            name=meta.get("name", ""), desc=meta.get("desc", ""), kind=kind,
            default=f.default, options=f.values, value_labels=overlay_vals,
            current=cur, current_scalar=cur_scalar, is_default=is_def,
            codeable=len(f.values) > 1,
            current_label=current_label, default_label=default_label,
            option_labels=option_labels, on=on, summary=summary,
        ))
    return out


def _summary(kind, name, desc, current_label, default_label, is_default, n_options, read) -> str:
    """One honest line that says what this setting is and where it stands."""
    if desc:                                # we know exactly what it does
        lead = desc
    elif kind == "toggle":
        lead = "An on/off switch."
    elif kind == "choice":
        lead = "A choice of %d values." % n_options
    else:
        lead = "A single value field."
    if not name and not desc:
        lead += " BMW ships this field unnamed; what it controls is not confirmed yet."
    if read:
        state = "Now: %s" % current_label
        if default_label not in ("", "—"):
            state += ", factory default: %s" % default_label
        if is_default is False:
            state += " (changed from default)"
        return "%s %s." % (lead, state)
    if default_label not in ("", "—"):
        return "%s Factory default: %s." % (lead, default_label)
    return lead


def save_backup(module: str, cafd_id: str, coding: dict, vin: str = "") -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, "%s-%s-%s.json" % (module, cafd_id, stamp))
    blob = {
        "module": module, "cafd_id": cafd_id, "vin": vin, "saved": stamp,
        "datagroups": {a: b.hex() for a, b in coding.items()},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(blob, fh, indent=2)
    return path


def features_to_json(feats: list[Feature]) -> list[dict]:
    return [asdict(f) for f in feats]
