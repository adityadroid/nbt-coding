"""Local web GUI for viewing (and later editing) BMW coding. Dependency-free: Python stdlib
http.server only. Nothing is installed.

    ./.venv/bin/python tools/bmw-coding/server.py
    # then open the URL it prints (http://127.0.0.1:8733)

Endpoints (all JSON except /):
    GET /                      the GUI page
    GET /api/modules           known modules and their diagnostic addresses
    GET /api/offline?cafd=ID   parse a decoded CAFD XML and list features (no car needed)
    GET /api/read?module=NAME  read that module's coding from the car, decode, save a backup

Binds to localhost only. Read-only against the car: it never writes coding.
"""
from __future__ import annotations

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import caf as caf_mod
from . import decode as decode_mod
from . import ecu as ecu_mod
from . import names as names_mod

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = int(os.environ.get("NBT_CODING_PORT", os.environ.get("BMW_CODING_PORT", "8733")))
CAR_HOST = os.environ.get("NBT_HOST", "169.254.199.99")


def _offline(cafd_id: str) -> dict:
    xml = decode_mod.find_cafd_xml(cafd_id)
    if not xml:
        return {"error": "no decoded CAFD XML found for %s under .local/psdz" % cafd_id}
    try:
        c = caf_mod.parse(xml)
    except caf_mod.CafEncrypted:
        return {"error": "CAFD %s is still encrypted (raw PSdZData): decrypt it with E-Sys first" % cafd_id}
    overlay = names_mod.load(c.cafd_id)
    feats = decode_mod.build_features(c, None, overlay)
    return {
        "cafd_id": c.cafd_id, "version": c.version, "sign_addr": c.sign_addr,
        "module": overlay.get("module", ""), "source": os.path.basename(xml),
        "datagroups": [{"addr": d.addr, "kind": d.kind, "count": len(d.funcs)}
                       for d in c.datagroups],
        "features": decode_mod.features_to_json(feats),
    }


def _probes() -> dict:
    """Saved car probes (newest first) and, per module, what can be shown from them without the car."""
    import glob, json
    files = sorted(glob.glob(os.path.join(decode_mod.BACKUP_DIR, "probe-*.json")), reverse=True)
    out = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            continue
        mods = []
        for m in d.get("modules", []):
            cafd = next((e for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
            mods.append({"addr": m.get("addr"), "name": m.get("name", ""),
                         "cafd": cafd["id"] if cafd else "", "cafd_version": cafd["version"] if cafd else "",
                         "datagroups": len(m.get("datagroups", {})),
                         "decodable": bool(cafd and decode_mod.find_cafd_xml(cafd["id"], cafd["version"]))})
        out.append({"file": os.path.basename(path), "saved": d.get("saved", ""), "modules": mods})
    return {"probes": out}


def _probe(fname: str, addr: str) -> dict:
    """One module from a saved probe: its coding decoded with its CAFD (offline, no car)."""
    import json
    if "/" in fname or not fname.startswith("probe-") or not fname.endswith(".json"):
        return {"error": "bad probe file name"}
    try:
        with open(os.path.join(decode_mod.BACKUP_DIR, fname), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError) as e:
        return {"error": "cannot read %s: %s" % (fname, e)}
    m = next((x for x in d.get("modules", []) if x.get("addr", "").upper() == addr.upper()), None)
    if not m:
        return {"error": "module %s not in %s" % (addr, fname)}
    cafd = next((e for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
    raw = {k.upper(): v for k, v in m.get("datagroups", {}).items()}
    if not cafd:
        return {"error": "module %s reported no CAFD (nothing codeable)" % addr}
    xml = decode_mod.find_cafd_xml(cafd["id"], cafd["version"])
    if not xml:
        return {"error": "no coding file for CAFD %s %s yet: put cafd_%s.caf.%s into cafd/ (from PSdZData)"
                         % (cafd["id"], cafd["version"], cafd["id"].lower(), cafd["version"].replace(".", "_")),
                "raw_datagroups": raw}
    try:
        c = caf_mod.parse(xml)
    except caf_mod.CafEncrypted:
        return {"error": "the coding file for CAFD %s is still encrypted (raw PSdZData). E-Sys must decrypt it first, "
                         "the way cafd_00000ded here was decrypted; a Lite bundle ships it encrypted too." % cafd["id"],
                "raw_datagroups": raw}
    coding = {a: bytes.fromhex(h) for a, h in raw.items()}
    # the CAF names datagroups like "3000"; the probe stored "%04X": match case-insensitively
    by_upper = {dg.addr.upper(): dg.addr for dg in c.datagroups}
    coding = {by_upper.get(a, a): b for a, b in coding.items()}
    overlay = names_mod.load(c.cafd_id)
    feats = decode_mod.build_features(c, coding, overlay)
    res = {"module": "%s %s" % (m.get("addr"), m.get("name", "")), "cafd_id": c.cafd_id, "version": c.version,
           "car_version": cafd["version"], "source": fname,
           "read_datagroups": sorted(coding), "features": decode_mod.features_to_json(feats)}
    if c.version != cafd["version"]:
        res["warning"] = ("coding file is version %s but the car has %s: settings may sit at other places; "
                          "get cafd_%s.caf.%s before trusting (or writing) anything"
                          % (c.version, cafd["version"], cafd["id"].lower(), cafd["version"].replace(".", "_")))
    return res


def _read(module: str) -> dict:
    if module not in ecu_mod.MODULES:
        return {"error": "unknown module %s" % module}
    tgt, note = ecu_mod.MODULES[module]
    try:
        hu = ecu_mod.Hsfz(CAR_HOST, verbose=False)
        hu.open()
    except Exception as e:  # noqa: BLE001
        return {"error": "cannot reach the car at %s: %s" % (CAR_HOST, e)}
    try:
        vin = ecu_mod.read_vin(hu, tgt)
        cafd_id = ecu_mod.read_cafd_id(hu, tgt)
        if not cafd_id:
            return {"error": "could not read the module's CAFD id (SVK). Wrong address?"}
        xml = decode_mod.find_cafd_xml(cafd_id)
        if not xml:
            return {"error": "read CAFD %s from the car, but no decoded XML for it under "
                             ".local/psdz. Decode that CAFD first." % cafd_id}
        c = caf_mod.parse(xml)
        coding = {}
        for d in c.user_datagroups():
            dr = ecu_mod.read_datagroup(hu, tgt, d.addr)
            if dr.ok:
                coding[d.addr] = dr.data
        # also read the signature datagroup, for the backup only
        sig = ecu_mod.read_datagroup(hu, tgt, c.sign_addr)
        if sig.ok:
            coding[c.sign_addr] = sig.data
    finally:
        hu.close()
    backup = decode_mod.save_backup(module, c.cafd_id, coding, vin)
    overlay = names_mod.load(c.cafd_id)
    feats = decode_mod.build_features(c, coding, overlay)
    return {
        "module": module, "vin_present": bool(vin), "cafd_id": c.cafd_id,
        "version": c.version, "sign_addr": c.sign_addr,
        "backup": os.path.relpath(backup, decode_mod.REPO),
        "read_datagroups": sorted(coding),
        "features": decode_mod.features_to_json(feats),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # quiet
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/modules":
            self._json({"host": CAR_HOST,
                        "modules": [{"name": n, "addr": "%02X" % a, "note": note}
                                    for n, (a, note) in sorted(ecu_mod.MODULES.items())]})
        elif parsed.path == "/api/offline":
            cafd = (q.get("cafd") or [""])[0]
            self._json(_offline(cafd) if cafd else {"error": "cafd required"})
        elif parsed.path == "/api/probes":
            self._json(_probes())
        elif parsed.path == "/api/probe":
            self._json(_probe((q.get("file") or [""])[0], (q.get("module") or [""])[0]))
        elif parsed.path == "/api/read":
            module = (q.get("module") or [""])[0]
            self._json(_read(module) if module else {"error": "module required"})
        else:
            self._json({"error": "not found"}, 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("BMW coding GUI:  http://%s:%d" % (HOST, PORT))
    print("Car host: %s (set NBT_HOST to change). Read-only; writing is disabled." % CAR_HOST)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
