"""Local web GUI for reading and writing BMW coding. Dependency-free: Python stdlib http.server only.

    python3 -m nbtcoding        # then open http://127.0.0.1:8733

Endpoints (JSON except /):
    GET  /                       the GUI page
    GET  /api/modules            modules, addresses, and whether each can be written
    GET  /api/offline?cafd=ID    a decoded CAFD's settings (no car)
    GET  /api/probes             saved car probes
    GET  /api/probe?file=&module=  one module from a saved probe (no car)
    GET  /api/read?module=NAME   read a module from the car (every CAFD datagroup), save a backup, decode
    GET  /api/backups?module=    saved backups for a module
    POST /api/plan               {module, changes:[{key, scalar}]} or {module, restore:<backup file>}
                                 -> fresh read + backup, then the exact write it would do (writes nothing)
    POST /api/write              {token, unlock} -> do the reviewed write, then read back

Binds to localhost only. A write needs a review token from /api/plan (valid 10 minutes), the owner unlock phrase, a
module whose signer is proven against this car, and the car still holding the coding the review was built from.
"""
from __future__ import annotations

import glob
import json
import os
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import caf as caf_mod
from . import decode as decode_mod
from . import ecu as ecu_mod
from . import edit as edit_mod
from . import names as names_mod
from . import sign as sign_mod
from . import write as write_mod

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = int(os.environ.get("NBT_CODING_PORT") or os.environ.get("PORT") or "8733")
WRITE_MODULES = ("FRM", "KOMBI", "CAS")
PLAN_TTL = 600
PENDING: dict[str, dict] = {}
CAR_LOCK = threading.Lock()          # one car conversation at a time
_HOST_CACHE = {"host": None}


# ---------------------------------------------------------------- car access (tests replace connect/read_ids)
def car_host() -> str:
    """The car's HSFZ gateway: NBT_HOST if set, else found by broadcast on the ENET cable, else the head unit."""
    if os.environ.get("NBT_HOST"):
        return os.environ["NBT_HOST"]
    if _HOST_CACHE["host"]:
        return _HOST_CACHE["host"]
    from . import probe
    found = probe.discover(probe.enet_source(), timeout=3.0)
    _HOST_CACHE["host"] = found[0] if found else probe.NBT_HOST
    return _HOST_CACHE["host"]


def connect():
    hu = ecu_mod.Hsfz(car_host(), verbose=False)
    hu.open()
    return hu


def read_ids(conn, tgt: int) -> tuple[str, str]:
    """(VIN, CAFD id) of a module."""
    return ecu_mod.read_vin(conn, tgt), ecu_mod.read_cafd_id(conn, tgt)


def read_module(conn, module: str) -> tuple[caf_mod.Caf, dict, str]:
    """(parsed CAFD, {datagroup: bytes} for every datagroup the CAFD declares, VIN)."""
    tgt = ecu_mod.MODULES[module][0]
    vin, cafd_id = read_ids(conn, tgt)
    if not cafd_id:
        raise RuntimeError("could not read %s's CAFD id (SVK). Is the module there?" % module)
    xml = decode_mod.find_cafd_xml(cafd_id)
    if not xml:
        raise RuntimeError("CAFD %s has no decrypted coding file in cafd/" % cafd_id)
    c = caf_mod.parse(xml)
    coding = {}
    for d in c.datagroups:
        dr = ecu_mod.read_datagroup(conn, tgt, d.addr)
        if dr.ok:
            coding[d.addr.upper()] = dr.data
    missing = [d.addr for d in c.datagroups if d.addr.upper() not in coding]
    if missing:
        raise RuntimeError("%s did not return datagroup(s) %s; refusing a partial read" % (module, ", ".join(missing)))
    return c, coding, vin


# ---------------------------------------------------------------- views
def _view(c: caf_mod.Caf, coding: dict | None, module: str = "") -> dict:
    overlay = names_mod.load(c.cafd_id)
    by_upper = {dg.addr.upper(): dg.addr for dg in c.datagroups}
    coding_caf = {by_upper.get(a.upper(), a): b for a, b in coding.items()} if coding is not None else None
    feats = decode_mod.build_features(c, coding_caf, overlay)
    ok, why = edit_mod.writable(module) if module else (False, "")
    return {"cafd_id": c.cafd_id, "version": c.version, "sign_addr": c.sign_addr,
            "groups": overlay.get("groups", {}), "names_source": overlay.get("source", ""),
            "named": sum(1 for f in feats if f.name), "writable": ok, "write_note": why,
            "features": decode_mod.features_to_json(feats)}


def _offline(cafd_id: str) -> dict:
    xml = decode_mod.find_cafd_xml(cafd_id)
    if not xml:
        return {"error": "no decoded CAFD XML for %s in cafd/" % cafd_id}
    try:
        c = caf_mod.parse(xml)
    except caf_mod.CafEncrypted:
        return {"error": "CAFD %s is still encrypted (raw PSdZData); decrypt it first" % cafd_id}
    res = _view(c, None)
    res.update(source=os.path.basename(xml), module=names_mod.load(c.cafd_id).get("module", ""))
    return res


def _probes() -> dict:
    out = []
    for path in sorted(glob.glob(os.path.join(decode_mod.BACKUP_DIR, "probe-*.json")), reverse=True):
        try:
            with open(path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            continue
        mods = []
        for m in d.get("modules", []):
            cafd = next((e for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
            mods.append({"addr": m.get("addr"), "name": m.get("name", ""),
                         "cafd": cafd["id"] if cafd else "", "cafd_version": cafd.get("version", "") if cafd else "",
                         "datagroups": len(m.get("datagroups", {})),
                         "decodable": bool(cafd and decode_mod.find_cafd_xml(cafd["id"], cafd.get("version", "")))})
        out.append({"file": os.path.basename(path), "saved": d.get("saved", d.get("time", "")), "modules": mods})
    return {"probes": out}


def _probe(fname: str, addr: str) -> dict:
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
    if not cafd:
        return {"error": "module %s reported no CAFD (nothing codeable)" % addr}
    xml = decode_mod.find_cafd_xml(cafd["id"], cafd.get("version", ""))
    if not xml:
        return {"error": "no coding file for CAFD %s %s in cafd/" % (cafd["id"], cafd.get("version", ""))}
    c = caf_mod.parse(xml)
    coding = {k.upper(): bytes.fromhex(v) for k, v in m.get("datagroups", {}).items()}
    res = _view(c, coding)
    res.update(module="%s %s" % (m.get("addr"), m.get("name", "")), source=fname, read_datagroups=sorted(coding),
               writable=False, write_note="saved probe: read the module from the car to change it")
    if cafd.get("version") and c.version != cafd["version"]:
        res["warning"] = "coding file is v%s but the car reported v%s" % (c.version, cafd["version"])
    return res


def _read(module: str) -> dict:
    if module not in ecu_mod.MODULES:
        return {"error": "unknown module %s" % module}
    with CAR_LOCK:
        try:
            conn = connect()
        except Exception as e:  # noqa: BLE001
            return {"error": "cannot reach the car: %s" % e}
        try:
            c, coding, vin = read_module(conn, module)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
        finally:
            conn.close()
    backup = decode_mod.save_backup(module, c.cafd_id, coding, vin)
    res = _view(c, coding, module)
    res.update(module=module, vin_present=bool(vin), backup=os.path.basename(backup), read_datagroups=sorted(coding))
    return res


def _backups(module: str) -> dict:
    files = sorted(glob.glob(os.path.join(decode_mod.BACKUP_DIR, "%s-*.json" % module)), reverse=True)
    return {"backups": [os.path.basename(p) for p in files]}


def _load_backup(module: str, fname: str) -> dict:
    if "/" in fname or not fname.startswith(module + "-") or not fname.endswith(".json"):
        raise ValueError("bad backup file name")
    with open(os.path.join(decode_mod.BACKUP_DIR, fname), encoding="utf-8") as fh:
        d = json.load(fh)
    return {a.upper(): bytes.fromhex(h) for a, h in d["datagroups"].items()}


# ---------------------------------------------------------------- review + write
def _describe(c: caf_mod.Caf, before: dict, after: dict) -> list[dict]:
    """Every named/unnamed setting whose value differs, in words."""
    overlay = names_mod.load(c.cafd_id)
    by_upper = {dg.addr.upper(): dg.addr for dg in c.datagroups}
    fb = {f.key: f for f in decode_mod.build_features(c, {by_upper.get(a, a): v for a, v in before.items()}, overlay)}
    fa = {f.key: f for f in decode_mod.build_features(c, {by_upper.get(a, a): v for a, v in after.items()}, overlay)}
    out = []
    for k, a in fa.items():
        b = fb.get(k)
        if b and b.current != a.current and a.datagroup.upper() != c.sign_addr.upper():
            out.append({"key": k, "name": a.name or "(unnamed)", "group": overlay.get("groups", {}).get(a.datagroup, ""),
                        "from": b.current_label, "to": a.current_label})
    return out


def _plan(body: dict) -> dict:
    module = body.get("module", "")
    if module not in WRITE_MODULES:
        return {"error": "%s cannot be written from this tool" % module}
    ok, why = edit_mod.writable(module)
    with CAR_LOCK:
        try:
            conn = connect()
        except Exception as e:  # noqa: BLE001
            return {"error": "cannot reach the car: %s" % e}
        try:
            c, before, vin = read_module(conn, module)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
        finally:
            conn.close()
    backup = decode_mod.save_backup(module, c.cafd_id, before, vin)
    try:
        if body.get("restore"):
            saved = _load_backup(module, body["restore"])
            content, _sig = sign_mod.scheme_from_caf(c)
            after = dict(before)
            for d in content:
                a = "%04X" % d
                if a in saved:
                    after[a] = saved[a]
        else:
            after, _done = edit_mod.build_after(c, before, body.get("changes", []))
        p = edit_mod.plan(module, c, before, after)
    except (ValueError, KeyError) as e:
        return {"error": str(e), "backup": os.path.basename(backup)}
    changes = _describe(c, before, p["after"])
    token = secrets.token_hex(12)
    PENDING[token] = {"module": module, "caf": c, "before": before, "after": p["after"], "time": time.time()}
    return {"token": token if ok and p["changed"] else "", "module": module, "writable": ok, "write_note": why,
            "changes": changes, "datagroups": p["changed"], "steps": p["steps"], "backup": os.path.basename(backup),
            "unlock_phrase": write_mod.UNLOCK, "nothing_to_do": not p["changed"]}


def _write(body: dict) -> dict:
    for t in [t for t, v in PENDING.items() if time.time() - v["time"] > PLAN_TTL]:
        PENDING.pop(t, None)
    pend = PENDING.pop(body.get("token", ""), None)
    if not pend:
        return {"error": "review expired or unknown; press Review again"}
    if body.get("unlock") != write_mod.UNLOCK:
        PENDING[body.get("token", "")] = pend
        return {"error": "the unlock phrase does not match"}
    module, c = pend["module"], pend["caf"]
    tgt = ecu_mod.MODULES[module][0]
    with CAR_LOCK:
        try:
            conn = connect()
        except Exception as e:  # noqa: BLE001
            return {"error": "cannot reach the car: %s" % e}
        try:
            _c, current, _vin = read_module(conn, module)
            res = edit_mod.execute(conn, tgt, module, c, pend["before"], pend["after"], body["unlock"], current)
        except Exception as e:  # noqa: BLE001
            return {"error": "%s. Nothing was reset. To undo, restore the backup taken at review." % e}
        finally:
            conn.close()
        time.sleep(float(os.environ.get("NBT_RESET_WAIT", "4")))   # the module reboots after 11 01
        readback = None
        for _ in range(5):
            try:
                conn = connect()
                try:
                    _c, readback, vin = read_module(conn, module)
                finally:
                    conn.close()
                break
            except Exception:  # noqa: BLE001
                time.sleep(2)
    out = {"ok": True, "module": module, "wrote": res.get("wrote"), "check_coding": res.get("check_coding")}
    if readback is None:
        out["warning"] = "written and reset, but the module did not answer a read-back yet; read it again"
        return out
    decode_mod.save_backup(module, c.cafd_id, readback, vin)
    bad = [a for a in res.get("wrote", []) if readback.get(a) != pend["after"].get(a)]
    out["verified"] = not bad
    if bad:
        out["warning"] = "after reset the module holds different bytes in %s" % ", ".join(bad)
    res2 = _view(c, readback, module)
    out["features"] = res2["features"]
    return out


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
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
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        if parsed.path == "/":
            with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/modules":
            mods = []
            for n, (a, note) in sorted(ecu_mod.MODULES.items()):
                if not a:
                    continue
                ok, why = edit_mod.writable(n) if n in WRITE_MODULES else (False, edit_mod.NEVER.get(n, "read only"))
                mods.append({"name": n, "addr": "%02X" % a, "note": note, "writable": ok, "write_note": why})
            self._json({"host": os.environ.get("NBT_HOST", "found on the ENET cable"), "modules": mods})
        elif parsed.path == "/api/offline":
            self._json(_offline(q["cafd"]) if q.get("cafd") else {"error": "cafd required"})
        elif parsed.path == "/api/probes":
            self._json(_probes())
        elif parsed.path == "/api/probe":
            self._json(_probe(q.get("file", ""), q.get("module", "")))
        elif parsed.path == "/api/read":
            self._json(_read(q["module"]) if q.get("module") else {"error": "module required"})
        elif parsed.path == "/api/backups":
            self._json(_backups(q.get("module", "")))
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if self.headers.get("Origin") not in (None, "http://%s:%d" % (HOST, PORT), "http://localhost:%d" % PORT):
            return self._json({"error": "cross-origin request refused"}, 403)
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0") or 0)) or b"{}")
        except ValueError:
            return self._json({"error": "bad JSON"}, 400)
        if parsed.path == "/api/plan":
            self._json(_plan(body))
        elif parsed.path == "/api/write":
            self._json(_write(body))
        else:
            self._json({"error": "not found"}, 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("BMW coding GUI:  http://%s:%d" % (HOST, PORT))
    print("Writes need a review, the owner unlock phrase, and a module whose signer is proven against this car.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
