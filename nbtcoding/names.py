"""Friendly-name overlay for coding functions.

BMW ships CAFs with the function names stripped to ".", so a function is known only by its
location (datagroup:start:end:mask, see caf.Func.key()). This overlay maps those location
keys to readable names and value labels, per CAFD id. It is ours to grow: every entry we
confirm on this car (or from community coding sheets) goes here.

Overlay file: names/<CAFD_ID>.json, e.g. names/00000DED.json:
    {
      "module": "HU_NBT",
      "functions": {
        "3000:0:0:01": {"name": "EXAMPLE_FEATURE", "values": {"0": "nicht_aktiv", "1": "aktiv"}}
      }
    }

Nothing here changes the car; it only makes the viewer readable.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(__file__)
NAMES_DIR = os.path.join(HERE, "names")


def load(cafd_id: str) -> dict:
    """Return {"module": str, "functions": {key: {name, values}}} for a CAFD id (or empty)."""
    path = os.path.join(NAMES_DIR, "%s.json" % cafd_id.upper())
    if not os.path.exists(path):
        return {"module": "", "functions": {}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)
