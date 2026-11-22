"""Offline coding signer for original-NBT-era F-series modules (BMWSigVerify).

The signature a module stores at its ncdSignAddress is a raw RSA signature over the MD5 of its coding, with NO padding:

    content = concatenation of the coding datagroups' bytes, in address order (up to, not including, the sign datagroup)
    m       = int.from_bytes(md5(content), "little")          # a 128-bit number
    s       = m ** d (mod N)                                   # d = private exponent of the module's NCD key
    stored  = wordswap(s)                                      # bytes of s, little-endian, reversed within each 32-bit word
    page    = (keysize//4) as big-endian uint32  +  stored     # what sits in the sign datagroup

Verification (what the ECU does) uses the public exponent e (always 3 here): raise the stored signature to e, and it must
equal the little-endian MD5 of the content (and be no wider than the digest). No BMW server is involved — 2014 coding is
signed offline — so the signing key is the per-BTLD NCD key, recovered from your own PSdZData (see docs below).

This module is pure Python standard library. It never touches the car. Keys live in keys/ (git-ignored); recover them with
evocode's `recover-key --kind ncd --btld <BTLD>` (needs sec_ncdkeys.xml from a PSdZData Lite bundle and your car's VIN).
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

HERE = os.path.dirname(__file__)
REPO = os.path.abspath(os.path.join(HERE, ".."))
KEYS_DIR = os.environ.get("NBT_KEYS_DIR", os.path.join(REPO, "keys"))


@dataclass
class Key:
    modulus: int
    public_exponent: int
    private_exponent: int | None
    btld: str

    @property
    def size(self) -> int:
        return (self.modulus.bit_length() + 7) // 8


def _wordswap(b: bytes) -> bytes:
    if len(b) % 4:
        raise ValueError("length must be a multiple of 4")
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def content_digest(coding: dict, content_dgs) -> bytes:
    """MD5 of the content datagroups, concatenated in address order. coding: {addr_str(upper): bytes}."""
    blob = b"".join(coding[a] for a in ("%04X" % d for d in content_dgs) if a in coding)
    return hashlib.md5(blob).digest()


def load_key(btld: str) -> Key | None:
    """The NCD key for a BTLD, from keys/ncd_<btld>.json (as evocode writes it). None if not present."""
    for name in ("ncd_%s.json" % btld.lower(), "ncd_%s.json" % btld.upper()):
        path = os.path.join(KEYS_DIR, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            priv = d.get("private_exponent_hex")
            return Key(modulus=int(d["modulus_hex"], 16), public_exponent=int(d.get("public_exponent", 3)),
                       private_exponent=int(priv, 16) if priv else None, btld=d.get("btld", btld))
    return None


def verify(coding: dict, content_dgs, sign_dg: int, key: Key) -> bool:
    """Reproduce the ECU's check: does the stored signature match the content's MD5 under this key? Writes nothing."""
    page = coding.get("%04X" % sign_dg, b"")
    if len(page) < 4 + key.size:
        return False
    sig = page[4:4 + key.size]
    recovered = pow(int.from_bytes(_wordswap(sig), "little"), key.public_exponent, key.modulus)
    return recovered.bit_length() <= 128 and recovered.to_bytes(16, "little") == content_digest(coding, content_dgs)


def sign(coding: dict, content_dgs, key: Key) -> bytes:
    """The signature-datagroup payload for the current content. Needs the private exponent. Writes nothing to the car."""
    if key.private_exponent is None:
        raise ValueError("no private exponent in the key: recover it from your own PSdZData")
    m = int.from_bytes(content_digest(coding, content_dgs), "little")
    s = pow(m, key.private_exponent, key.modulus)
    return (key.size // 4).to_bytes(4, "big") + _wordswap(s.to_bytes(key.size, "little"))


# Per-module signing scheme. content_dgs and sign_dg come from the module's CAFD (ncdSignAddress); "proven" means
# verify() reproduced the car's own signature on a real probe. Only NBT is proven so far; the others wait for their
# decrypted CAFD to fix content_dgs/sign_dg (their keys are already recovered).
@dataclass
class Scheme:
    btld: str
    content_dgs: tuple
    sign_dg: int
    proven: bool = False


# Per-module BTLD (selects the NCD key) and whether the signer is proven against this car's own signature.
# The sign address and content datagroups now come from the decrypted CAFD (scheme_from_caf), not hardcoded.
# NBT/FRM/KOMBI sign with a 1024-bit RSA NCD key (this module's scheme). CAS (BTLD 0000074B) is NOT here: its
# sec_ncdkeys entry is 32 bytes, not an RSA key, so CAS coding uses a different signature (a symmetric scheme, to be
# worked out) — and CAS is the immobiliser module, so it stays last and most careful regardless.
BTLD = {"HU_NBT": "00001275", "FRM": "0000106B", "KOMBI": "000016E4"}
PROVEN = {"HU_NBT"}   # verify() reproduced the car's own signature; others need a full read to confirm


def scheme_from_caf(caf) -> tuple:
    """(content_dgs, sign_dg) from a parsed CAFD: every datagroup below ncdSignAddress, in order, signed together."""
    sign_dg = int(caf.sign_addr, 16)
    content = tuple(sorted(int(d.addr, 16) for d in caf.datagroups if int(d.addr, 16) < sign_dg))
    return content, sign_dg


def _main() -> int:
    """python3 -m nbtcoding.sign [probe.json] — verify each module's signature against its key + decrypted CAFD."""
    import glob
    import sys
    from . import caf as cafmod, decode
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    files = [arg] if arg else sorted(glob.glob(os.path.join(decode.BACKUP_DIR, "probe-*.json")), reverse=True)
    if not files:
        print("no probe given and none in backups/ (run: python3 -m nbtcoding.probe)")
        return 2
    with open(files[0], encoding="utf-8") as f:
        probe = json.load(f)
    print("signatures in", os.path.basename(files[0]))
    by_addr = {"63": "HU_NBT", "72": "FRM", "60": "KOMBI", "40": "CAS"}
    for m in probe.get("modules", []):
        name = by_addr.get(m.get("addr", ""))
        if not name:
            continue
        cafd = next((e["id"] for e in m.get("svk", []) if e.get("class") == "CAFD"), None)
        xml = decode.find_cafd_xml(cafd) if cafd else None
        key = load_key(BTLD.get(name, ""))
        coding = {a.upper(): bytes.fromhex(h) for a, h in m.get("datagroups", {}).items()}
        if key is None:
            print("  %-7s key for BTLD %s not in keys/ (recover it)" % (name, BTLD.get(name)))
            continue
        if not xml:
            print("  %-7s key present; CAFD %s not decrypted yet" % (name, cafd))
            continue
        content, sign_dg = scheme_from_caf(cafmod.parse(xml))
        missing = [("%04X" % d) for d in content if ("%04X" % d) not in coding]
        if missing:
            print("  %-7s key + CAFD ready; read these datagroups to verify: %s" % (name, " ".join(missing)))
        else:
            ok = verify(coding, content, sign_dg, key)
            print("  %-7s signature %s (sign@%04X, %d datagroups)"
                  % (name, "VERIFIED against the car" if ok else "did NOT verify", sign_dg, len(content)))
    return 0



if __name__ == "__main__":
    raise SystemExit(_main())
